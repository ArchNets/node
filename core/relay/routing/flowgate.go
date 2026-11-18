package routing

import (
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"
)

var (
	// ErrFlowGateStrict is returned when strict mode is enabled and reverse budget is exceeded.
	ErrFlowGateStrict = errors.New("flow gate: strict reverse budget exceeded")
	// ErrFlowGateStalled is returned when a stream has been throttled without allowed progress.
	ErrFlowGateStalled = errors.New("flow gate: reverse stream throttled without upload progress")
)

const (
	DefaultReverseRatio     = 0.04  // 4% reverse/allowed ratio
	MinReverseRatio         = 0.005 // 0.5%
	MaxReverseRatio         = 0.50  // 50%
	DefaultReverseBurstKB   = 64    // 64 KB burst budget
	MinReverseBurstKB       = 4     // 4 KB
	MaxReverseBurstKB       = 1024  // 1 MB
	DefaultThrottleStallSec = 20    // 20s stall timeout
	MinThrottleStallSec     = 5     // 5s
	MaxThrottleStallSec     = 120   // 120s
)

func clampRatio(r float64) float64 {
	if r <= 0 {
		return DefaultReverseRatio
	}
	if r < MinReverseRatio {
		return MinReverseRatio
	}
	if r > MaxReverseRatio {
		return MaxReverseRatio
	}
	return r
}

func clampBurstKB(b int) int {
	if b <= 0 {
		return DefaultReverseBurstKB
	}
	if b < MinReverseBurstKB {
		return MinReverseBurstKB
	}
	if b > MaxReverseBurstKB {
		return MaxReverseBurstKB
	}
	return b
}

func clampStallSec(s int) int {
	if s <= 0 {
		return DefaultThrottleStallSec
	}
	if s < MinThrottleStallSec {
		return MinThrottleStallSec
	}
	if s > MaxThrottleStallSec {
		return MaxThrottleStallSec
	}
	return s
}

// FlowGate coordinates per-connection L4 asymmetric direction flow control.
// In upload_only mode, reverse bytes (downlink) are bounded by burst + allowed_bytes*ratio.
// In download_only mode, reverse bytes (uplink) are bounded similarly.
type FlowGate struct {
	flowMode         string
	ratio            float64
	burstBytes       int64
	strict           bool
	stallTimeout     time.Duration
	allowedBytes     atomic.Int64
	reverseBytes     atomic.Int64
	lastAllowedNano  atomic.Int64
	notifyCh         chan struct{}
	closeOnce        sync.Once
	closeCh          chan struct{}
	throttleLoggedAt atomic.Int64
}

// NewFlowGate creates a new L4 flow gate initialized from forwarder rule parameters with clamping.
func NewFlowGate(rule ForwarderRule) *FlowGate {
	ratio := clampRatio(rule.ReverseRatio)
	burstKB := clampBurstKB(rule.ReverseBurstKB)
	stallSec := clampStallSec(rule.ThrottleStallSec)

	return newFlowGateRaw(rule.FlowMode, ratio, burstKB, stallSec, rule.Strict)
}

// NewFlowGateUnclamped creates an unconstrained flow gate for testing purposes.
func NewFlowGateUnclamped(flowMode string, ratio float64, burstKB int, stallSec int, strict bool) *FlowGate {
	return newFlowGateRaw(flowMode, ratio, burstKB, stallSec, strict)
}

func newFlowGateRaw(flowMode string, ratio float64, burstKB int, stallSec int, strict bool) *FlowGate {
	g := &FlowGate{
		flowMode:     flowMode,
		ratio:        ratio,
		burstBytes:   int64(burstKB) * 1024,
		strict:       strict,
		stallTimeout: time.Duration(stallSec) * time.Second,
		notifyCh:     make(chan struct{}, 1),
		closeCh:      make(chan struct{}),
	}
	g.lastAllowedNano.Store(time.Now().UnixNano())
	return g
}

// AddAllowed increments the allowed-direction byte count and notifies any waiting throttled reader.
func (g *FlowGate) AddAllowed(n int) {
	if n <= 0 {
		return
	}
	g.allowedBytes.Add(int64(n))
	g.lastAllowedNano.Store(time.Now().UnixNano())

	select {
	case g.notifyCh <- struct{}{}:
	default:
	}
}

// AllowedBudget returns current max permissible reverse-direction bytes.
func (g *FlowGate) AllowedBudget() int64 {
	allowed := g.allowedBytes.Load()
	return g.burstBytes + int64(float64(allowed)*g.ratio)
}

// AvailableReverse returns remaining reverse-direction byte allowance.
func (g *FlowGate) AvailableReverse() int64 {
	avail := g.AllowedBudget() - g.reverseBytes.Load()
	if avail < 0 {
		return 0
	}
	return avail
}

// logThrottleRateLimited logs a debug message when a stream is throttled, rate-limited to once every 5 seconds.
func (g *FlowGate) logThrottleRateLimited() {
	now := time.Now().Unix()
	last := g.throttleLoggedAt.Load()
	if now-last >= 5 {
		if g.throttleLoggedAt.CompareAndSwap(last, now) {
			log.WithFields(log.Fields{
				"flowMode":     g.flowMode,
				"allowedBytes": g.allowedBytes.Load(),
				"reverseBytes": g.reverseBytes.Load(),
				"budget":       g.AllowedBudget(),
			}).Debug("[FlowGate] Reverse stream reached budget limit; throttling with TCP backpressure")
		}
	}
}

// WaitForBudget waits until available reverse budget > 0, stall timeout expires, or gate is closed.
func (g *FlowGate) WaitForBudget() (int64, error) {
	var waitTimer *time.Timer
	defer func() {
		if waitTimer != nil {
			waitTimer.Stop()
		}
	}()

	for {
		avail := g.AvailableReverse()
		if avail > 0 {
			return avail, nil
		}

		if g.strict {
			return 0, ErrFlowGateStrict
		}

		g.logThrottleRateLimited()

		// Verify stall timeout
		lastAllowed := time.Unix(0, g.lastAllowedNano.Load())
		elapsed := time.Since(lastAllowed)
		if elapsed >= g.stallTimeout {
			return 0, ErrFlowGateStalled
		}

		remaining := g.stallTimeout - elapsed
		if waitTimer == nil {
			waitTimer = time.NewTimer(remaining)
		} else {
			if !waitTimer.Stop() {
				select {
				case <-waitTimer.C:
				default:
				}
			}
			waitTimer.Reset(remaining)
		}

		select {
		case <-g.closeCh:
			return 0, net.ErrClosed
		case <-g.notifyCh:
			// Check budget on wakeup
		case <-waitTimer.C:
			return 0, ErrFlowGateStalled
		}
	}
}

// CheckUDPReverse checks if an incoming reverse UDP datagram fits within the allowed budget.
// Returns (allowed, closeSession).
func (g *FlowGate) CheckUDPReverse(payloadLen int) (bool, bool) {
	if payloadLen <= 0 {
		return true, false
	}
	budget := g.AllowedBudget()
	cur := g.reverseBytes.Load()
	if cur+int64(payloadLen) <= budget {
		g.reverseBytes.Add(int64(payloadLen))
		return true, false
	}

	if g.strict {
		return false, true
	}

	// Non-strict: check stall timeout
	lastAllowed := time.Unix(0, g.lastAllowedNano.Load())
	if time.Since(lastAllowed) >= g.stallTimeout {
		return false, true
	}

	g.logThrottleRateLimited()
	return false, false // Drop packet, keep session alive
}

// Close signals closure and unblocks any waiting reader.
func (g *FlowGate) Close() {
	g.closeOnce.Do(func() {
		close(g.closeCh)
	})
}

// GatedReader wraps an io.Reader, bounding total bytes read by the flow gate's budget.
type GatedReader struct {
	src  io.Reader
	gate *FlowGate
}

// WrapReader wraps r with budget-constrained gating.
func (g *FlowGate) WrapReader(r io.Reader) io.Reader {
	return &GatedReader{
		src:  r,
		gate: g,
	}
}

func (gr *GatedReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	avail, err := gr.gate.WaitForBudget()
	if err != nil {
		return 0, err
	}

	toRead := len(p)
	if int64(toRead) > avail {
		toRead = int(avail)
	}

	n, rErr := gr.src.Read(p[:toRead])
	if n > 0 {
		gr.gate.reverseBytes.Add(int64(n))
	}
	return n, rErr
}

package core

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/outbound"
)

type dummyAddr struct{}

func (dummyAddr) Network() string { return "tcp" }
func (dummyAddr) String() string  { return "127.0.0.1:12345" }

type linkReader struct {
	reader   buf.Reader
	leftover buf.MultiBuffer
}

func (r *linkReader) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	if r.leftover.IsEmpty() {
		mb, err := r.reader.ReadMultiBuffer()
		if err != nil {
			return 0, err
		}
		r.leftover = mb
	}
	var n int
	r.leftover, n = buf.SplitFirstBytes(r.leftover, b)
	return n, nil
}

type linkWriter struct {
	writer buf.Writer
}

func (w *linkWriter) Write(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	mb := buf.MergeBytes(nil, b)
	err := w.writer.WriteMultiBuffer(mb)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

// What changed: Added deadline timers, lock, and ctxCancel to xrayConn.
// Why: Ensures read/write operations unblock on timeout or context cancellation instead of wedging indefinitely.
type xrayConn struct {
	r          *linkReader
	w          *linkWriter
	closer     func() error
	closeOnce  sync.Once
	readTimer  *time.Timer
	writeTimer *time.Timer
	timerLock  sync.Mutex
	ctxCancel  context.CancelFunc
}

func (c *xrayConn) Read(b []byte) (int, error) {
	return c.r.Read(b)
}

func (c *xrayConn) Write(b []byte) (int, error) {
	return c.w.Write(b)
}

func (c *xrayConn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		c.timerLock.Lock()
		if c.readTimer != nil {
			c.readTimer.Stop()
			c.readTimer = nil
		}
		if c.writeTimer != nil {
			c.writeTimer.Stop()
			c.writeTimer = nil
		}
		c.timerLock.Unlock()

		if c.ctxCancel != nil {
			c.ctxCancel()
		}
		if c.closer != nil {
			err = c.closer()
		}
	})
	return err
}

func (c *xrayConn) LocalAddr() net.Addr  { return dummyAddr{} }
func (c *xrayConn) RemoteAddr() net.Addr { return dummyAddr{} }

func (c *xrayConn) SetDeadline(t time.Time) error {
	_ = c.SetReadDeadline(t)
	return c.SetWriteDeadline(t)
}

func (c *xrayConn) SetReadDeadline(t time.Time) error {
	c.timerLock.Lock()
	if c.readTimer != nil {
		c.readTimer.Stop()
		c.readTimer = nil
	}
	var closeNow bool
	if !t.IsZero() {
		if dur := time.Until(t); dur <= 0 {
			closeNow = true
		} else {
			c.readTimer = time.AfterFunc(dur, func() {
				_ = c.Close()
			})
		}
	}
	c.timerLock.Unlock()
	if closeNow {
		_ = c.Close()
	}
	return nil
}

func (c *xrayConn) SetWriteDeadline(t time.Time) error {
	c.timerLock.Lock()
	if c.writeTimer != nil {
		c.writeTimer.Stop()
		c.writeTimer = nil
	}
	var closeNow bool
	if !t.IsZero() {
		if dur := time.Until(t); dur <= 0 {
			closeNow = true
		} else {
			c.writeTimer = time.AfterFunc(dur, func() {
				_ = c.Close()
			})
		}
	}
	c.timerLock.Unlock()
	if closeNow {
		_ = c.Close()
	}
	return nil
}

var fallbackEndpoints = []string{
	"162.159.192.1:2408",
	"162.159.192.1:500",
	"162.159.192.1:1701",
	"162.159.192.1:4500",
	"188.114.97.1:2408",
	"188.114.97.1:500",
	"188.114.97.1:1701",
	"188.114.97.1:4500",
}

// What changed: Rotates through fallbackEndpoints skipping re-resolution on recovery attempts.
// Why: Dynamic re-resolution usually returns the same blocked IP, while fallback endpoints provide reliable alternative IPs.
func (c *XrayCore) getNextEndpoint(tag string, originalEndpoint string) string {
	idx := c.wgEndpointIndex[tag]
	endpoint := fallbackEndpoints[idx%len(fallbackEndpoints)]
	c.wgEndpointIndex[tag] = (idx + 1) % len(fallbackEndpoints)
	return endpoint
}

// DialOutbound dials a connection forced through a specific outbound tag.
func (v *XrayCore) DialOutbound(ctx context.Context, tag string, dest xnet.Destination) (net.Conn, error) {
	if v == nil || v.dispatcher == nil {
		return nil, fmt.Errorf("dispatcher is not initialized")
	}

	// Force outbound tag
	ctx = session.SetForcedOutboundTagToContext(ctx, tag)

	outbounds := session.OutboundsFromContext(ctx)
	if len(outbounds) == 0 {
		outbounds = []*session.Outbound{{}}
		ctx = session.ContextWithOutbounds(ctx, outbounds)
	}
	ob := outbounds[len(outbounds)-1]
	ob.OriginalTarget = dest
	ob.Target = dest

	link, err := v.dispatcher.Dispatch(ctx, dest)
	if err != nil {
		return nil, err
	}

	connCtx, cancel := context.WithCancel(ctx)

	conn := &xrayConn{
		r:         &linkReader{reader: link.Reader},
		w:         &linkWriter{writer: link.Writer},
		ctxCancel: cancel,
		closer: func() error {
			common.Close(link.Writer)
			common.Interrupt(link.Reader)
			return nil
		},
	}

	go func() {
		<-connCtx.Done()
		_ = conn.Close()
	}()

	return conn, nil
}

func (v *XrayCore) RemoveOutbound(tag string) error {
	if v == nil || v.ohm == nil {
		return fmt.Errorf("outbound manager is not initialized")
	}
	ctx, cancel := context.WithTimeout(v.watchdogCtx, 10*time.Second)
	defer cancel()
	return v.ohm.RemoveHandler(ctx, tag)
}

func (v *XrayCore) AddOutbound(config *core.OutboundHandlerConfig) error {
	if v == nil || v.Server == nil || v.ohm == nil {
		return fmt.Errorf("server/outbound manager is not initialized")
	}
	rawHandler, err := core.CreateObject(v.Server, config)
	if err != nil {
		return err
	}
	handler, ok := rawHandler.(outbound.Handler)
	if !ok {
		return fmt.Errorf("not an OutboundHandler")
	}
	ctx, cancel := context.WithTimeout(v.watchdogCtx, 10*time.Second)
	defer cancel()
	if err := v.ohm.AddHandler(ctx, handler); err != nil {
		return err
	}
	return nil
}

func (c *XrayCore) testWireguardConnection(ctx context.Context, tag string) error {
	dialer := func(ctx context.Context, network, addr string) (net.Conn, error) {
		dest, err := xnet.ParseDestination(network + ":" + addr)
		if err != nil {
			return nil, err
		}
		return c.DialOutbound(ctx, tag, dest)
	}

	transport := &http.Transport{
		DialContext:         dialer,
		DisableKeepAlives:   true,
		TLSHandshakeTimeout: 5 * time.Second,
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   8 * time.Second,
	}

	req, err := http.NewRequestWithContext(ctx, "GET", "http://cp.cloudflare.com/generate_204", nil)
	if err != nil {
		return err
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 204 && resp.StatusCode != 200 {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
	return nil
}

// What changed: Made WireguardWatchdog non-blocking by taking a snapshot under wgMutex and spawning probe routines.
// Why: Prevents probes from holding the task lock and stalling periodic execution.
func (c *XrayCore) WireguardWatchdog() error {
	c.wgMutex.Lock()
	if c.wgOutbounds == nil || len(c.wgOutbounds) == 0 {
		c.wgMutex.Unlock()
		return nil
	}
	outboundsCopy := make(map[string]*WireguardOutbound, len(c.wgOutbounds))
	for tag, ob := range c.wgOutbounds {
		outboundsCopy[tag] = ob
	}
	c.wgMutex.Unlock()

	for tag, config := range outboundsCopy {
		tag := tag
		config := config
		c.wgWatchdogGroup.Add(1)
		go func() {
			defer c.wgWatchdogGroup.Done()
			c.probeAndRecoverOutbound(tag, config)
		}()
	}

	return nil
}

// What changed: Implemented probeAndRecoverOutbound with 2-failure threshold, verification probe, and core reload escalation.
// Why: Ensures rapid detection, verification after rebuild, and fallback to full core reload on persistent failures.
func (c *XrayCore) probeAndRecoverOutbound(tag string, config *WireguardOutbound) {
	select {
	case <-c.watchdogCtx.Done():
		return
	default:
	}

	c.wgMutex.Lock()
	if c.wgRecovering == nil {
		c.wgRecovering = make(map[string]bool)
	}
	if c.wgRecovering[tag] {
		c.wgMutex.Unlock()
		return
	}
	c.wgRecovering[tag] = true

	if c.wgHandlerMissing == nil {
		c.wgHandlerMissing = make(map[string]bool)
	}
	if c.wgFailures == nil {
		c.wgFailures = make(map[string]int)
	}
	if c.wgEscalationCount == nil {
		c.wgEscalationCount = make(map[string]int)
	}
	if c.wgEndpointIndex == nil {
		c.wgEndpointIndex = make(map[string]int)
	}
	isMissing := c.wgHandlerMissing[tag]
	c.wgMutex.Unlock()

	defer func() {
		c.wgMutex.Lock()
		c.wgRecovering[tag] = false
		c.wgMutex.Unlock()
	}()

	var probeErr error
	if isMissing {
		probeErr = fmt.Errorf("handler is missing from previous cycle")
	} else {
		ctx, cancel := context.WithTimeout(c.watchdogCtx, 10*time.Second)
		probeErr = c.testWireguardConnection(ctx, tag)
		cancel()
	}

	if probeErr == nil {
		c.wgMutex.Lock()
		if c.wgFailures[tag] > 0 {
			log.WithFields(log.Fields{
				"tag":          tag,
				"old_failures": c.wgFailures[tag],
			}).Info("WireGuard connection recovered")
			c.wgFailures[tag] = 0
		}
		c.wgEscalationCount[tag] = 0
		c.wgMutex.Unlock()
		return
	}

	c.wgMutex.Lock()
	if isMissing {
		log.WithField("tag", tag).Warn("WireGuard handler is missing, attempting recovery...")
	} else {
		c.wgFailures[tag]++
		log.WithFields(log.Fields{
			"tag":      tag,
			"err":      probeErr,
			"failures": c.wgFailures[tag],
		}).Warn("WireGuard connection test failed")
	}
	failures := c.wgFailures[tag]
	c.wgMutex.Unlock()

	if !isMissing && failures < 2 {
		return
	}

	c.wgMutex.Lock()
	c.wgFailures[tag] = 0
	origEndpoint := config.Outbound.WireguardPeerEndpoint
	newEndpoint := c.getNextEndpoint(tag, origEndpoint)
	c.wgMutex.Unlock()

	log.WithFields(log.Fields{
		"tag":          tag,
		"new_endpoint": newEndpoint,
	}).Info("Rebuilding WireGuard config with rotated endpoint")

	newConfig, err := BuildWireguardOutbound(config.Outbound, newEndpoint)
	if err != nil {
		log.WithFields(log.Fields{
			"tag": tag,
			"err": err,
		}).Error("Failed to rebuild wireguard outbound config")
		return
	}

	if !isMissing {
		if err := c.RemoveOutbound(tag); err != nil {
			log.WithFields(log.Fields{
				"tag": tag,
				"err": err,
			}).Error("Failed to remove wireguard outbound handler")
		}
	}

	var addErr error
	for attempt := 1; attempt <= 3; attempt++ {
		if c.watchdogCtx.Err() != nil {
			return
		}
		addErr = c.AddOutbound(newConfig)
		if addErr == nil {
			break
		}
		log.WithFields(log.Fields{
			"tag":     tag,
			"attempt": attempt,
			"err":     addErr,
		}).Error("Failed to add wireguard outbound handler, retrying in 2s...")

		select {
		case <-time.After(2 * time.Second):
		case <-c.watchdogCtx.Done():
			return
		}
	}

	if c.watchdogCtx.Err() != nil {
		return
	}

	if addErr != nil {
		log.WithFields(log.Fields{
			"tag": tag,
			"err": addErr,
		}).Error("Failed to add wireguard outbound handler after retries")

		c.wgMutex.Lock()
		c.wgHandlerMissing[tag] = true
		c.wgEscalationCount[tag]++
		escalations := c.wgEscalationCount[tag]
		c.wgMutex.Unlock()

		if escalations >= 3 {
			c.escalateToReload(tag, escalations)
		}
		return
	}

	c.wgMutex.Lock()
	config.Config = newConfig
	c.wgHandlerMissing[tag] = false
	c.wgMutex.Unlock()
	log.WithField("tag", tag).Info("Successfully recreated wireguard outbound handler")

	// Post-rebuild verification probe
	verifyCtx, verifyCancel := context.WithTimeout(c.watchdogCtx, 10*time.Second)
	verifyErr := c.testWireguardConnection(verifyCtx, tag)
	verifyCancel()

	if c.watchdogCtx.Err() != nil {
		return
	}

	if verifyErr != nil {
		log.WithFields(log.Fields{
			"tag": tag,
			"err": verifyErr,
		}).Warn("Immediate verification probe after WireGuard rebuild failed")

		c.wgMutex.Lock()
		c.wgEscalationCount[tag]++
		escalations := c.wgEscalationCount[tag]
		c.wgMutex.Unlock()

		if escalations >= 3 {
			c.escalateToReload(tag, escalations)
		}
	} else {
		log.WithField("tag", tag).Info("Immediate verification probe after WireGuard rebuild succeeded")
		c.wgMutex.Lock()
		c.wgEscalationCount[tag] = 0
		c.wgMutex.Unlock()
	}
}

func (c *XrayCore) escalateToReload(tag string, escalationCount int) {
	log.WithFields(log.Fields{
		"tag":         tag,
		"escalations": escalationCount,
	}).Error("WireGuard watchdog: escalated to full core reload after repeated rebuild failures")

	c.wgMutex.Lock()
	c.wgEscalationCount[tag] = 0
	c.wgMutex.Unlock()

	if c.ReloadCh != nil {
		select {
		case c.ReloadCh <- struct{}{}:
		default:
			log.WithField("tag", tag).Warn("WireGuard watchdog: core reload already pending")
		}
	}
}

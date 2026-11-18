package routing

import (
	"bytes"
	"errors"
	"io"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// pipeConn implements net.Conn using an in-memory io.Pipe pair for fast loopback benchmarking.
type pipeConn struct {
	r *io.PipeReader
	w *io.PipeWriter
}

func newPipePair() (*pipeConn, *pipeConn) {
	r1, w1 := io.Pipe()
	r2, w2 := io.Pipe()
	return &pipeConn{r: r1, w: w2}, &pipeConn{r: r2, w: w1}
}

func (p *pipeConn) Read(b []byte) (int, error)         { return p.r.Read(b) }
func (p *pipeConn) Write(b []byte) (int, error)        { return p.w.Write(b) }
func (p *pipeConn) Close() error                       { _ = p.r.Close(); return p.w.Close() }
func (p *pipeConn) LocalAddr() net.Addr                { return &net.IPAddr{IP: net.IPv4(127, 0, 0, 1)} }
func (p *pipeConn) RemoteAddr() net.Addr               { return &net.IPAddr{IP: net.IPv4(127, 0, 0, 1)} }
func (p *pipeConn) SetDeadline(t time.Time) error      { return nil }
func (p *pipeConn) SetReadDeadline(t time.Time) error  { return nil }
func (p *pipeConn) SetWriteDeadline(t time.Time) error { return nil }

func TestFlowGateBudgetMath(t *testing.T) {
	rule := ForwarderRule{
		FlowMode:       "upload_only",
		ReverseRatio:   0.05, // 5%
		ReverseBurstKB: 10,   // 10 KB
	}
	g := NewFlowGate(rule)
	defer g.Close()

	if b := g.AllowedBudget(); b != 10*1024 {
		t.Fatalf("expected initial budget %d, got %d", 10*1024, b)
	}

	// Add 100 KB of allowed upload
	g.AddAllowed(100 * 1024)

	// Budget should now be: 10KB + 5% of 100KB = 10KB + 5KB = 15KB
	expected := int64(15 * 1024)
	if b := g.AllowedBudget(); b != expected {
		t.Fatalf("expected budget %d, got %d", expected, b)
	}
}

func TestFlowGateStrictRejection(t *testing.T) {
	rule := ForwarderRule{
		FlowMode:       "upload_only",
		ReverseRatio:   0.01,
		ReverseBurstKB: 4, // 4 KB burst
		Strict:         true,
	}
	g := NewFlowGate(rule)
	defer g.Close()

	buf := make([]byte, 8192)
	src := bytes.NewReader(buf)
	gr := g.WrapReader(src)

	// First 4 KB read should succeed
	p := make([]byte, 4096)
	n, err := gr.Read(p)
	if err != nil || n != 4096 {
		t.Fatalf("first 4KB read failed: n=%d, err=%v", n, err)
	}

	// Next read should be rejected immediately with ErrFlowGateStrict
	_, err = gr.Read(p)
	if !errors.Is(err, ErrFlowGateStrict) {
		t.Fatalf("expected ErrFlowGateStrict, got %v", err)
	}
}

func TestFlowGateEventDrivenWakeup(t *testing.T) {
	rule := ForwarderRule{
		FlowMode:         "upload_only",
		ReverseRatio:     0.10, // 10%
		ReverseBurstKB:   4,    // 4 KB burst
		ThrottleStallSec: 5,
		Strict:           false,
	}
	g := NewFlowGate(rule)
	defer g.Close()

	r, w := io.Pipe()
	defer r.Close()
	defer w.Close()

	gr := g.WrapReader(r)

	// Feed 16 KB into pipe writer in background
	go func() {
		chunk := make([]byte, 4096)
		for i := 0; i < 4; i++ {
			_, _ = w.Write(chunk)
		}
	}()

	// Read initial 4 KB (consumes all 4 KB burst)
	p := make([]byte, 4096)
	n, err := gr.Read(p)
	if err != nil || n != 4096 {
		t.Fatalf("initial read failed: n=%d err=%v", n, err)
	}

	// Next read will block because budget is empty.
	// We verify that AddAllowed wakes it up event-driven!
	readDone := make(chan int)
	go func() {
		nr, rErr := gr.Read(p)
		if rErr != nil {
			t.Errorf("woken read error: %v", rErr)
		}
		readDone <- nr
	}()

	// Ensure reader is waiting
	select {
	case <-readDone:
		t.Fatalf("reader should have blocked waiting for budget")
	case <-time.After(50 * time.Millisecond):
	}

	// Now upload 40 KB -> creates 10% of 40KB = 4KB reverse budget!
	g.AddAllowed(40 * 1024)

	// Reader should unblock immediately
	select {
	case nr := <-readDone:
		if nr != 4096 {
			t.Fatalf("expected 4096 bytes read after wakeup, got %d", nr)
		}
	case <-time.After(1 * time.Second):
		t.Fatalf("reader timed out; did not wake up event-driven")
	}
}

func TestFlowGateStallTimeoutReap(t *testing.T) {
	g := NewFlowGateUnclamped("upload_only", 0.01, 4, 1, false) // 1s stall timeout for test
	defer g.Close()

	r, w := io.Pipe()
	defer r.Close()
	defer w.Close()

	gr := g.WrapReader(r)
	go func() {
		chunk := make([]byte, 4096)
		for {
			if _, err := w.Write(chunk); err != nil {
				return
			}
		}
	}()

	// Exhaust initial 4KB burst
	p := make([]byte, 4096)
	_, _ = gr.Read(p)

	// Next read should stall and be reaped after 1s
	start := time.Now()
	_, err := gr.Read(p)
	dur := time.Since(start)

	if !errors.Is(err, ErrFlowGateStalled) {
		t.Fatalf("expected ErrFlowGateStalled, got %v", err)
	}
	if dur < 900*time.Millisecond || dur > 2500*time.Millisecond {
		t.Fatalf("expected stall reap around 1s, took %v", dur)
	}
}

func TestFlowGateUDP(t *testing.T) {
	g := NewFlowGateUnclamped("upload_only", 0.10, 2, 1, false) // 2KB burst for test
	defer g.Close()

	// Initial 1KB datagram should pass (within 2KB burst)
	ok, closeS := g.CheckUDPReverse(1024)
	if !ok || closeS {
		t.Fatalf("expected 1KB datagram allowed")
	}

	// Another 1KB should pass (reaches 2KB)
	ok, closeS = g.CheckUDPReverse(1024)
	if !ok || closeS {
		t.Fatalf("expected second 1KB datagram allowed")
	}

	// 3rd datagram exceeds 2KB burst -> dropped (ok=false, closeS=false)
	ok, closeS = g.CheckUDPReverse(512)
	if ok || closeS {
		t.Fatalf("expected datagram dropped without closing immediately")
	}

	// Upload 20 KB -> gives 2 KB new budget
	g.AddAllowed(20 * 1024)
	ok, closeS = g.CheckUDPReverse(1024)
	if !ok || closeS {
		t.Fatalf("expected datagram allowed after upload progress")
	}
}

// Benchmark10kConcurrentGatedConnections benchmarks 10,000 active concurrent connections
// over real loopback OS TCP sockets (5,000 uploading, 5,000 attempting unauthorized downloads)
// measuring CPU usage, goroutine cleanup, and memory allocation.
func Benchmark10kConcurrentGatedConnections(b *testing.B) {
	// Raise soft file descriptor limit to handle 10,000 real socket pairs (20,000 FDs)
	raiseFDLimit()

	runtime.GC()
	initialGoroutines := runtime.NumGoroutine()
	var mStart runtime.MemStats
	runtime.ReadMemStats(&mStart)

	const numConns = 10000
	const stallSec = 5

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatalf("listen error: %v", err)
	}
	defer ln.Close()

	serverConns := make([]net.Conn, numConns)
	clientConns := make([]net.Conn, numConns)
	gates := make([]*FlowGate, numConns)

	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		for i := 0; i < numConns; i++ {
			c, aErr := ln.Accept()
			if aErr != nil {
				return
			}
			serverConns[i] = c
		}
	}()
	addr := ln.Addr().String()
	for i := 0; i < numConns; i++ {
		c, dErr := net.Dial("tcp", addr)
		if dErr != nil {
			b.Fatalf("dial %d failed: %v (raise ulimit -n)", i, dErr)
		}
		clientConns[i] = c
		gates[i] = NewFlowGate(ForwarderRule{
			FlowMode:         "upload_only",
			ReverseRatio:     0.04,
			ReverseBurstKB:   64,
			ThrottleStallSec: stallSec,
		})
	}
	<-acceptDone

	b.ResetTimer()

	var wg sync.WaitGroup
	var uploaded, leakedDown, stalled atomic.Int64

	// Half the connections: real 256 KB uploads (allowed direction), feeding the gate.
	for i := 0; i < numConns/2; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			go func() {
				chunk := make([]byte, 16*1024)
				for k := 0; k < 16; k++ {
					if _, wErr := clientConns[idx].Write(chunk); wErr != nil {
						return
					}
				}
				_ = clientConns[idx].(*net.TCPConn).CloseWrite()
			}()
			buf := make([]byte, 32*1024)
			for {
				n, rErr := serverConns[idx].Read(buf)
				if n > 0 {
					gates[idx].AddAllowed(n)
					uploaded.Add(int64(n))
				}
				if rErr != nil {
					return
				}
			}
		}(i)
	}

	// Other half: server pushes 1 MB "download" through a gated reader; must stall at the burst and be reaped.
	for i := numConns / 2; i < numConns; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			go func() {
				chunk := make([]byte, 64*1024)
				for k := 0; k < 16; k++ {
					if _, wErr := serverConns[idx].Write(chunk); wErr != nil {
						return
					}
				}
			}()
			gr := gates[idx].WrapReader(clientConns[idx])
			buf := make([]byte, 32*1024)
			for {
				n, rErr := gr.Read(buf)
				if n > 0 {
					leakedDown.Add(int64(n))
				}
				if rErr != nil {
					if errors.Is(rErr, ErrFlowGateStalled) {
						stalled.Add(1)
					}
					return
				}
			}
		}(i)
	}

	// Measure process CPU while 5,000 readers sit throttled (event-driven wait => near-zero CPU).
	time.Sleep(1 * time.Second)
	var ruA, ruB unix.Rusage
	_ = unix.Getrusage(unix.RUSAGE_SELF, &ruA)
	idleWindow := 2 * time.Second
	time.Sleep(idleWindow)
	_ = unix.Getrusage(unix.RUSAGE_SELF, &ruB)
	cpuUsed := time.Duration(ruB.Utime.Nano()+ruB.Stime.Nano()-ruA.Utime.Nano()-ruA.Stime.Nano()) * time.Nanosecond
	peakGoroutines := runtime.NumGoroutine()

	wg.Wait()
	b.StopTimer()

	for i := 0; i < numConns; i++ {
		gates[i].Close()
		_ = clientConns[i].Close()
		_ = serverConns[i].Close()
	}

	time.Sleep(300 * time.Millisecond)
	runtime.GC()
	finalGoroutines := runtime.NumGoroutine()
	var mFinal runtime.MemStats
	runtime.ReadMemStats(&mFinal)

	allocMB := float64(mFinal.TotalAlloc-mStart.TotalAlloc) / (1024 * 1024)
	perConnDown := leakedDown.Load() / int64(numConns/2)
	b.Logf("10k real sockets: uploaded=%d MB | stalled+reaped=%d/%d | avg reverse bytes/conn=%d (burst=65536)",
		uploaded.Load()/(1024*1024), stalled.Load(), numConns/2, perConnDown)
	b.Logf("idle CPU over %v with %d throttled readers: %v (%.2f%% of one core) | goroutines before=%d peak=%d after=%d | alloc=%.2f MB (%.2f KB/conn)",
		idleWindow, numConns/2, cpuUsed, 100*cpuUsed.Seconds()/idleWindow.Seconds(),
		initialGoroutines, peakGoroutines, finalGoroutines, allocMB, (allocMB*1024)/float64(numConns))

	if stalled.Load() != int64(numConns/2) {
		b.Fatalf("expected all %d throttled download attempts reaped, got %d", numConns/2, stalled.Load())
	}
	if perConnDown > 64*1024 {
		b.Fatalf("reverse leak: avg %d bytes/conn exceeds burst budget", perConnDown)
	}
	if finalGoroutines > initialGoroutines+5 {
		b.Fatalf("goroutine leak: before=%d after=%d", initialGoroutines, finalGoroutines)
	}
}

func raiseFDLimit() {
	var rLimit unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &rLimit); err == nil {
		if rLimit.Cur < 65536 {
			rLimit.Cur = 65536
			if rLimit.Cur > rLimit.Max {
				rLimit.Cur = rLimit.Max
			}
			_ = unix.Setrlimit(unix.RLIMIT_NOFILE, &rLimit)
		}
	}
}

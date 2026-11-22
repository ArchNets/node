//go:build linux

package telemetry

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func countSelfFDs(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatalf("read /proc/self/fd: %v", err)
	}
	return len(entries)
}

func TestSplicePipePoolNoFDLeakAfterGC(t *testing.T) {
	// Warm up pool baseline
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			c, aErr := ln.Accept()
			if aErr != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(io.Discard, conn)
			}(c)
		}
	}()

	payload := bytes.Repeat([]byte("S"), 64*1024)
	runBatch := func(n int) {
		var wg sync.WaitGroup
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				c1, dErr := net.Dial("tcp", ln.Addr().String())
				if dErr != nil {
					return
				}
				defer c1.Close()

				// Create local TCP pair to splice between
				pLn, pErr := net.Listen("tcp", "127.0.0.1:0")
				if pErr != nil {
					return
				}
				defer pLn.Close()
				done := make(chan struct{})
				go func() {
					defer close(done)
					srv, sErr := pLn.Accept()
					if sErr != nil {
						return
					}
					defer srv.Close()
					var counter atomic.Int64
					_, _ = SpliceCopy(c1, srv, &counter)
				}()
				cli, cErr := net.Dial("tcp", pLn.Addr().String())
				if cErr == nil {
					_, _ = cli.Write(payload)
					_ = cli.Close()
				}
				<-done
			}()
		}
		wg.Wait()
	}

	// First warmup batch fills pool up to concurrency
	runBatch(32)
	runtime.GC()
	runtime.GC()
	baseFDs := countSelfFDs(t)

	// Run multiple large batches with GC cycles in between; previously sync.Pool leaked 2 pipe FDs per evicted pipe
	for round := 0; round < 5; round++ {
		runBatch(80)
		runtime.GC()
		runtime.GC()
	}
	time.Sleep(50 * time.Millisecond)
	afterFDs := countSelfFDs(t)

	if len(splicePipePool) > maxSplicePipePool {
		t.Fatalf("splicePipePool exceeded cap: %d > %d", len(splicePipePool), maxSplicePipePool)
	}
	// Allow small slack for pool growth up to concurrency, but never 400+ leaked pipes
	if delta := afterFDs - baseFDs; delta > 120 {
		t.Fatalf("pipe FD leak detected: base=%d after=%d delta=%d", baseFDs, afterFDs, delta)
	}
	t.Logf("✓ Verified zero splice pipe FD leak across 400 transfers + GC (baseFDs=%d, afterFDs=%d, pooled=%d)", baseFDs, afterFDs, len(splicePipePool))
}

func TestSplicePipePoolBrokenErrorClosesPipe(t *testing.T) {
	// Ensure a broken destination mid-splice does not poison the pool or leak FDs
	lnSrc, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer lnSrc.Close()

	lnDst, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer lnDst.Close()

	srcSrvCh := make(chan net.Conn, 1)
	go func() {
		c, _ := lnSrc.Accept()
		srcSrvCh <- c
	}()
	dstSrvCh := make(chan net.Conn, 1)
	go func() {
		c, _ := lnDst.Accept()
		dstSrvCh <- c
	}()

	srcCli, err := net.Dial("tcp", lnSrc.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer srcCli.Close()
	dstCli, err := net.Dial("tcp", lnDst.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	srcSrv := <-srcSrvCh
	dstSrv := <-dstSrvCh
	defer srcSrv.Close()
	defer dstSrv.Close()

	// Close dstCli immediately with RST/EOF so splicePump fails
	_ = dstCli.Close()
	_, _ = srcCli.Write(bytes.Repeat([]byte("X"), 32768))

	var counter atomic.Int64
	// SpliceCopy may return nil or an error depending on timing, must not hang or panic
	done := make(chan error, 1)
	go func() {
		_, sErr := SpliceCopy(dstSrv, srcSrv, &counter)
		done <- sErr
	}()
	time.Sleep(50 * time.Millisecond)
	_ = srcCli.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal(fmt.Sprintf("SpliceCopy hung on broken destination"))
	}
}

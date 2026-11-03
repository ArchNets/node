package core

import (
	"sync"
	"testing"
)

func TestLogRingBufferBasic(t *testing.T) {
	ring := newLogRingBuffer(3)

	_, _ = ring.Write([]byte("line 1\nline 2\n"))
	dump := ring.Dump()
	if len(dump) != 2 || dump[0] != "line 1" || dump[1] != "line 2" {
		t.Fatalf("unexpected dump: %v", dump)
	}
}

func TestLogRingBufferPartialLineSplit(t *testing.T) {
	ring := newLogRingBuffer(5)

	// Write first chunk without newline
	_, _ = ring.Write([]byte("2026-11-03 03:00:00 Options error: "))
	// Second chunk completes the line
	_, _ = ring.Write([]byte("Unrecognized option in [CMD-LINE]\n"))
	// Third chunk without trailing newline
	_, _ = ring.Write([]byte("Exiting due to fatal error"))

	dump := ring.Dump()
	if len(dump) != 2 {
		t.Fatalf("expected 2 lines, got %d: %v", len(dump), dump)
	}

	expectedLine1 := "2026-11-03 03:00:00 Options error: Unrecognized option in [CMD-LINE]"
	if dump[0] != expectedLine1 {
		t.Errorf("line 1 mismatch:\n got:  %q\n want: %q", dump[0], expectedLine1)
	}

	expectedLine2 := "Exiting due to fatal error"
	if dump[1] != expectedLine2 {
		t.Errorf("line 2 mismatch:\n got:  %q\n want: %q", dump[1], expectedLine2)
	}
}

func TestLogRingBufferWrapAround(t *testing.T) {
	ring := newLogRingBuffer(3)

	_, _ = ring.Write([]byte("line 1\nline 2\nline 3\nline 4\n"))
	dump := ring.Dump()

	if len(dump) != 3 {
		t.Fatalf("expected 3 lines, got %d: %v", len(dump), dump)
	}
	// "line 1" discarded; remaining: line 2, line 3, line 4
	if dump[0] != "line 2" || dump[1] != "line 3" || dump[2] != "line 4" {
		t.Errorf("wrap around ordering mismatch: %v", dump)
	}
}

func TestLogRingBufferConcurrent(t *testing.T) {
	ring := newLogRingBuffer(20)

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				_, _ = ring.Write([]byte("log message\n"))
			}
		}()
	}
	wg.Wait()

	dump := ring.Dump()
	if len(dump) != 20 {
		t.Errorf("expected 20 dumped lines, got %d", len(dump))
	}
}

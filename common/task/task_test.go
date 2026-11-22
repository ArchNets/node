package task

import (
	"sync/atomic"
	"testing"
	"time"
)

func TestTaskCloseIsNonBlocking(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	var runs atomic.Int32

	tk := &Task{
		Interval: 20 * time.Millisecond,
		Execute: func() error {
			if runs.Add(1) == 1 {
				close(started)
				<-release
			}
			return nil
		},
	}

	go func() {
		_ = tk.Start(true)
	}()

	<-started

	done := make(chan struct{})
	go func() {
		tk.Close()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(200 * time.Millisecond):
		close(release)
		t.Fatal("Task.Close() blocked on in-flight Execute()")
	}

	close(release)
	time.Sleep(80 * time.Millisecond)
	if got := runs.Load(); got != 1 {
		t.Fatalf("expected no re-executions after Close(), got %d", got)
	}
}

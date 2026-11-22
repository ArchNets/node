package task

import (
	"sync"
	"sync/atomic"
	"time"
)

// Task is a task that runs periodically.
type Task struct {
	// Interval of the task being run
	Interval time.Duration
	// Execute is the task function
	Execute func() error

	access   sync.Mutex
	timer    *time.Timer
	running  bool
	inFlight atomic.Bool
}

func (t *Task) isRunning() bool {
	t.access.Lock()
	defer t.access.Unlock()
	return t.running
}

func (t *Task) scheduleNext() {
	t.access.Lock()
	defer t.access.Unlock()
	if !t.running {
		return
	}
	t.timer = time.AfterFunc(t.Interval, func() {
		_ = t.checkedExecute(true)
	})
}

func (t *Task) checkedExecute(first bool) error {
	if !t.isRunning() {
		return nil
	}

	if first {
		if !t.inFlight.CompareAndSwap(false, true) {
			t.scheduleNext()
			return nil
		}
		err := t.Execute()
		t.inFlight.Store(false)
		if err != nil {
			t.access.Lock()
			t.running = false
			t.access.Unlock()
			return err
		}
	}

	t.scheduleNext()
	return nil
}

// Start implements common.Runnable.
func (t *Task) Start(first bool) error {
	t.access.Lock()
	if t.running {
		t.access.Unlock()
		return nil
	}
	t.running = true
	t.access.Unlock()
	if err := t.checkedExecute(first); err != nil {
		t.access.Lock()
		t.running = false
		t.access.Unlock()
		return err
	}
	return nil
}

// Close implements common.Closable without blocking on an in-flight Execute() call.
func (t *Task) Close() {
	t.access.Lock()
	defer t.access.Unlock()

	t.running = false
	if t.timer != nil {
		t.timer.Stop()
		t.timer = nil
	}
}

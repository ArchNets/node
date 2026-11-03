package core

import (
	"strings"
	"sync"
)

// logRingBuffer is a thread-safe ring buffer for capturing child process stdout/stderr.
// It buffers partial lines across Write() boundaries and commits only complete lines,
// flushing any unterminated tail when Dump() is called.
type logRingBuffer struct {
	mu      sync.Mutex
	lines   []string
	size    int
	pos     int
	full    bool
	pending string
}

func newLogRingBuffer(size int) *logRingBuffer {
	if size <= 0 {
		size = 50
	}
	return &logRingBuffer{
		lines: make([]string, size),
		size:  size,
	}
}

func (r *logRingBuffer) pushLineLocked(line string) {
	line = strings.TrimSpace(line)
	if line == "" {
		return
	}
	r.lines[r.pos] = line
	r.pos = (r.pos + 1) % r.size
	if r.pos == 0 {
		r.full = true
	}
}

func (r *logRingBuffer) Write(p []byte) (n int, err error) {
	if len(p) == 0 {
		return 0, nil
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	data := string(p)
	if r.pending != "" {
		data = r.pending + data
		r.pending = ""
	}

	// Split by newline
	for {
		idx := strings.IndexByte(data, '\n')
		if idx < 0 {
			// No more full lines; store remainder as pending tail
			r.pending = data
			break
		}
		line := strings.TrimRight(data[:idx], "\r")
		r.pushLineLocked(line)
		data = data[idx+1:]
	}

	return len(p), nil
}

// Dump returns all recorded lines in chronological order, flushing any
// unterminated partial line still pending.
func (r *logRingBuffer) Dump() []string {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Flush pending tail if present (e.g. process died without trailing newline)
	if r.pending != "" {
		tail := strings.TrimRight(r.pending, "\r\n")
		r.pending = ""
		r.pushLineLocked(tail)
	}

	if !r.full {
		res := make([]string, r.pos)
		copy(res, r.lines[:r.pos])
		return res
	}

	res := make([]string, r.size)
	copy(res, r.lines[r.pos:])
	copy(res[r.size-r.pos:], r.lines[:r.pos])
	return res
}

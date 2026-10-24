package transport

import (
	"context"
	"fmt"
	"net"
	"time"
)

const (
	DefaultFisherCount   = 3
	DefaultFisherStagger = 40 * time.Millisecond
)

// FisherDialer spawns multiple staggered parallel connection attempts and keeps the first socket
// that completes the handshake, cancelling and closing all slower candidates.
type FisherDialer struct {
	Count   int
	Stagger time.Duration
}

func NewFisherDialer(count int) *FisherDialer {
	if count <= 0 {
		count = DefaultFisherCount
	}
	if count > 8 {
		count = 8
	}
	return &FisherDialer{
		Count:   count,
		Stagger: DefaultFisherStagger,
	}
}

func (f *FisherDialer) DialContext(parentCtx context.Context, attemptFn func(ctx context.Context, index int) (net.Conn, error)) (net.Conn, error) {
	count := f.Count
	if count <= 1 {
		return attemptFn(parentCtx, 0)
	}

	ctx, cancel := context.WithCancel(parentCtx)
	defer cancel()

	type raceResult struct {
		conn net.Conn
		err  error
	}

	results := make(chan raceResult, count)

	for i := 0; i < count; i++ {
		idx := i
		go func() {
			if idx > 0 && f.Stagger > 0 {
				timer := time.NewTimer(time.Duration(idx) * f.Stagger)
				select {
				case <-timer.C:
				case <-ctx.Done():
					timer.Stop()
					results <- raceResult{err: ctx.Err()}
					return
				}
			}

			conn, err := attemptFn(ctx, idx)
			if err != nil {
				results <- raceResult{err: err}
				return
			}

			select {
			case results <- raceResult{conn: conn}:
			case <-ctx.Done():
				_ = conn.Close()
			}
		}()
	}

	var firstErr error
	for i := 0; i < count; i++ {
		res := <-results
		if res.conn != nil {
			cancel()
			remaining := count - i - 1
			if remaining > 0 {
				go func(rem int) {
					for j := 0; j < rem; j++ {
						r := <-results
						if r.conn != nil {
							_ = r.conn.Close()
						}
					}
				}(remaining)
			}
			return res.conn, nil
		}
		if firstErr == nil && res.err != nil {
			firstErr = res.err
		}
	}

	if firstErr != nil {
		return nil, firstErr
	}
	return nil, fmt.Errorf("fisher dialer failed all %d attempts", count)
}

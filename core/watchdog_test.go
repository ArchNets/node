package core

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/archnets/node/api/panel"
	"github.com/stretchr/testify/assert"
)

func TestWireguardWatchdog_ProbeTimeoutDoesNotStallScheduler(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c := &XrayCore{
		watchdogCtx:       ctx,
		watchdogCancel:    cancel,
		wgOutbounds:       make(map[string]*WireguardOutbound),
		wgFailures:        make(map[string]int),
		wgEndpointIndex:   make(map[string]int),
		wgHandlerMissing:  make(map[string]bool),
		wgEscalationCount: make(map[string]int),
	}

	c.wgOutbounds["wg-stall-test"] = &WireguardOutbound{}

	start := time.Now()
	err := c.WireguardWatchdog()
	elapsed := time.Since(start)

	assert.NoError(t, err)
	// WireguardWatchdog must return immediately (< 50ms) to avoid stalling the task scheduler
	assert.Less(t, elapsed, 50*time.Millisecond, "WireguardWatchdog execution took too long; it must be non-blocking")
}

func TestWireguardWatchdog_ConcurrentReloadAndWatchdogRace(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c := &XrayCore{
		watchdogCtx:       ctx,
		watchdogCancel:    cancel,
		wgOutbounds:       make(map[string]*WireguardOutbound),
		wgFailures:        make(map[string]int),
		wgEndpointIndex:   make(map[string]int),
		wgHandlerMissing:  make(map[string]bool),
		wgEscalationCount: make(map[string]int),
	}
	defer c.Close()

	done := make(chan struct{})
	go func() {
		time.Sleep(300 * time.Millisecond)
		close(done)
	}()

	// Concurrent reload vs watchdog execution
	go func() {
		for {
			select {
			case <-done:
				return
			default:
				sampleOb := panel.Outbound{
					Name:                   "wg-1",
					Protocol:               "wireguard",
					WireguardPrivateKey:    "private_key_v4",
					WireguardAddress:       "172.16.0.2/32",
					WireguardMTU:           1420,
					WireguardPeerPublicKey: "peer_pub_key",
					WireguardPeerEndpoint:  "162.159.192.1:2408",
				}
				m := map[string]*WireguardOutbound{
					"wg-1": {Outbound: sampleOb},
					"wg-2": {Outbound: sampleOb},
				}
				c.initWatchdog(m)
				c.wgMutex.Lock()
				if c.wgWatchdogPeriodic != nil {
					c.wgWatchdogPeriodic.Close()
					c.wgWatchdogPeriodic = nil
				}
				c.wgMutex.Unlock()
				time.Sleep(5 * time.Millisecond)
			}
		}
	}()

	go func() {
		for {
			select {
			case <-done:
				return
			default:
				_ = c.WireguardWatchdog()
				time.Sleep(5 * time.Millisecond)
			}
		}
	}()

	<-done
	cancel()
	_ = c.Close()
}

func TestWireguardWatchdog_EscalationToReload(t *testing.T) {
	tests := []struct {
		name             string
		escalationCount  int
		shouldTrigger    bool
		initialChanState int
	}{
		{
			name:             "escalate_at_threshold_3",
			escalationCount:  3,
			shouldTrigger:    true,
			initialChanState: 0,
		},
		{
			name:             "non_blocking_send_when_channel_full",
			escalationCount:  3,
			shouldTrigger:    true,
			initialChanState: 1, // Channel already has 1 item
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			c := &XrayCore{
				watchdogCtx:       ctx,
				watchdogCancel:    cancel,
				ReloadCh:          make(chan struct{}, 1),
				wgOutbounds:       make(map[string]*WireguardOutbound),
				wgFailures:        make(map[string]int),
				wgEndpointIndex:   make(map[string]int),
				wgHandlerMissing:  make(map[string]bool),
				wgEscalationCount: make(map[string]int),
			}

			if tt.initialChanState > 0 {
				c.ReloadCh <- struct{}{}
			}

			c.escalateToReload("test-tag", tt.escalationCount)

			if tt.shouldTrigger {
				select {
				case <-c.ReloadCh:
					// Signal successfully received/sent
				default:
					t.Fatal("expected reload signal on ReloadCh")
				}
			}
		})
	}
}

func TestXrayConn_SetReadDeadline_ExpiredDoesNotDeadlock(t *testing.T) {
	_, cancel := context.WithCancel(context.Background())
	defer cancel()

	conn := &xrayConn{
		ctxCancel: cancel,
	}

	doneRead := make(chan struct{})
	go func() {
		err := conn.SetReadDeadline(time.Now().Add(-1 * time.Second))
		assert.NoError(t, err)
		close(doneRead)
	}()

	select {
	case <-doneRead:
		// Completed without deadlock
	case <-time.After(2 * time.Second):
		t.Fatal("SetReadDeadline deadlocked on expired deadline")
	}

	doneWrite := make(chan struct{})
	go func() {
		err := conn.SetWriteDeadline(time.Now().Add(-1 * time.Second))
		assert.NoError(t, err)
		close(doneWrite)
	}()

	select {
	case <-doneWrite:
		// Completed without deadlock
	case <-time.After(2 * time.Second):
		t.Fatal("SetWriteDeadline deadlocked on expired deadline")
	}
}

func TestProbeAndRecoverOutbound_OverlappingRecoveryGuarded(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c := &XrayCore{
		watchdogCtx:       ctx,
		watchdogCancel:    cancel,
		wgOutbounds:       make(map[string]*WireguardOutbound),
		wgFailures:        make(map[string]int),
		wgEndpointIndex:   make(map[string]int),
		wgHandlerMissing:  make(map[string]bool),
		wgEscalationCount: make(map[string]int),
		wgRecovering:      make(map[string]bool),
	}
	defer c.Close()

	sampleOb := panel.Outbound{
		Name:                   "wg-overlapping-test",
		Protocol:               "wireguard",
		WireguardPrivateKey:    "private_key_v4",
		WireguardAddress:       "172.16.0.2/32",
		WireguardMTU:           1420,
		WireguardPeerPublicKey: "peer_pub_key",
		WireguardPeerEndpoint:  "162.159.192.1:2408",
	}

	wgOb := &WireguardOutbound{
		Outbound: sampleOb,
	}

	tag := "wg-overlapping-test"

	// Pre-set recovering state to true to simulate an active recovery
	c.wgMutex.Lock()
	c.wgRecovering[tag] = true
	c.wgMutex.Unlock()

	// Calling probeAndRecoverOutbound while wgRecovering[tag] is true should return immediately
	done := make(chan struct{})
	go func() {
		c.probeAndRecoverOutbound(tag, wgOb)
		close(done)
	}()

	select {
	case <-done:
		// Succeeded immediately because recovery was guarded
	case <-time.After(1 * time.Second):
		t.Fatal("probeAndRecoverOutbound did not return immediately when recovery was in progress")
	}

	// Reset recovering guard and launch two concurrent calls
	c.wgMutex.Lock()
	c.wgRecovering[tag] = false
	c.wgMutex.Unlock()

	var startBarrier sync.WaitGroup
	var doneBarrier sync.WaitGroup
	startBarrier.Add(1)

	for i := 0; i < 2; i++ {
		doneBarrier.Add(1)
		go func() {
			defer doneBarrier.Done()
			startBarrier.Wait()
			c.probeAndRecoverOutbound(tag, wgOb)
		}()
	}

	startBarrier.Done()
	doneBarrier.Wait()

	// Verify wgRecovering[tag] is reset to false after completion
	c.wgMutex.Lock()
	assert.False(t, c.wgRecovering[tag])
	c.wgMutex.Unlock()
}

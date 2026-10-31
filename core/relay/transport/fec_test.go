package transport

import (
	"bytes"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"
)

type pipePacketConn struct {
	localAddr net.Addr
	peer      *pipePacketConn
	ch        chan []byte
	closed    bool
	mu        sync.Mutex
}

func newPipePacketConnPair() (*pipePacketConn, *pipePacketConn) {
	a := &pipePacketConn{
		localAddr: &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 1111},
		ch:        make(chan []byte, 1024),
	}
	b := &pipePacketConn{
		localAddr: &net.UDPAddr{IP: net.ParseIP("10.0.0.2"), Port: 2222},
		ch:        make(chan []byte, 1024),
	}
	a.peer = b
	b.peer = a
	return a, b
}

func (p *pipePacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	pkt, ok := <-p.ch
	if !ok {
		return 0, nil, net.ErrClosed
	}
	n := copy(b, pkt)
	return n, p.peer.localAddr, nil
}

func (p *pipePacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return 0, net.ErrClosed
	}
	cp := append([]byte(nil), b...)
	select {
	case p.peer.ch <- cp:
		return len(b), nil
	default:
		return 0, fmt.Errorf("pipe buffer full")
	}
}

func (p *pipePacketConn) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.closed {
		p.closed = true
		close(p.ch)
	}
	return nil
}

func (p *pipePacketConn) LocalAddr() net.Addr                { return p.localAddr }
func (p *pipePacketConn) SetDeadline(t time.Time) error      { return nil }
func (p *pipePacketConn) SetReadDeadline(t time.Time) error  { return nil }
func (p *pipePacketConn) SetWriteDeadline(t time.Time) error { return nil }

func TestFECPacketConn_LossRecovery(t *testing.T) {
	rawA, rawB := newPipePacketConnPair()

	// Intercept rawA -> rawB to simulate dropping 2 out of 10 data packets
	dropCh := make(chan []byte, 1024)
	droppedPipe := &pipePacketConn{
		localAddr: rawB.localAddr,
		peer:      rawA,
		ch:        dropCh,
	}

	fecA, err := NewFECPacketConn(rawA, 10, 3) // 10 data, 3 parity
	if err != nil {
		t.Fatalf("NewFECPacketConn A: %v", err)
	}
	defer fecA.Close()

	fecB, err := NewFECPacketConn(droppedPipe, 10, 3)
	if err != nil {
		t.Fatalf("NewFECPacketConn B: %v", err)
	}
	defer fecB.Close()

	// Pump packets from rawA.peer.ch to dropCh, dropping index 2 and index 6 of group
	go func() {
		defer close(dropCh)
		for pkt := range rawB.ch {
			if len(pkt) >= FECHeaderLen && pkt[0] == fecKindData {
				idx := pkt[5]
				if idx == 2 || idx == 6 {
					continue // simulate packet drop on the border!
				}
			}
			dropCh <- pkt
		}
	}()

	// Send 10 packets from A to B
	sentMessages := make([][]byte, 10)
	for i := 0; i < 10; i++ {
		msg := []byte(fmt.Sprintf("GAME_PACKET_TICK_%03d_PAYLOAD", i))
		sentMessages[i] = msg
		if _, err := fecA.WriteTo(msg, rawB.localAddr); err != nil {
			t.Fatalf("WriteTo %d: %v", i, err)
		}
	}

	// Read all 10 packets from B; packets 2 and 6 must be recovered by FEC!
	received := make([][]byte, 0, 10)
	readBuf := make([]byte, 2048)
	for len(received) < 10 {
		n, _, err := fecB.ReadFrom(readBuf)
		if err != nil {
			t.Fatalf("ReadFrom error after %d packets: %v", len(received), err)
		}
		received = append(received, append([]byte(nil), readBuf[:n]...))
	}

	if len(received) != 10 {
		t.Fatalf("expected 10 recovered packets, got %d", len(received))
	}

	// Verify all 10 payloads were delivered in full
	foundMap := make(map[string]bool)
	for _, r := range received {
		foundMap[string(r)] = true
	}
	for i, want := range sentMessages {
		if !foundMap[string(want)] {
			t.Errorf("missing packet %d (%s) from FEC recovery", i, string(want))
		}
	}
	t.Logf("✓ Verified: 100%% of packets recovered across 20%% simulated border packet drop")
}

func TestFECPacketConn_SparsePacketFlush(t *testing.T) {
	rawA, rawB := newPipePacketConnPair()
	dropCh := make(chan []byte, 1024)
	droppedPipe := &pipePacketConn{
		localAddr: rawB.localAddr,
		peer:      rawA,
		ch:        dropCh,
	}

	fecA, _ := NewFECPacketConn(rawA, 10, 3)
	defer fecA.Close()
	fecB, _ := NewFECPacketConn(droppedPipe, 10, 3)
	defer fecB.Close()

	// Drop the lone data packet on the wire so ONLY the 8ms-flushed parity shards arrive!
	go func() {
		defer close(dropCh)
		for pkt := range rawB.ch {
			if len(pkt) >= FECHeaderLen && pkt[0] == fecKindData {
				continue // Drop the lone data packet!
			}
			dropCh <- pkt
		}
	}()

	// Send just 1 lone packet (sparse game tick)
	testMsg := []byte("SPARSE_GAME_TICK_RECOVERED_FROM_PARITY")
	_, err := fecA.WriteTo(testMsg, rawB.localAddr)
	if err != nil {
		t.Fatalf("WriteTo: %v", err)
	}

	readBuf := make([]byte, 1024)
	n, _, err := fecB.ReadFrom(readBuf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if !bytes.Equal(readBuf[:n], testMsg) {
		t.Fatalf("got %s, want %s", readBuf[:n], testMsg)
	}
	t.Logf("✓ Verified: Dropped lone sparse gaming packet reconstructed from 8ms parity flush!")
}

func TestFECPacketConn_EncryptedHeaders(t *testing.T) {
	rawA, rawB := newPipePacketConnPair()
	fecA, err := NewFECPacketConnWithSecret(rawA, 8, 4, "secret-tunnel-password")
	if err != nil {
		t.Fatalf("fecA: %v", err)
	}
	defer fecA.Close()

	fecB, err := NewFECPacketConnWithSecret(rawB, 8, 4, "secret-tunnel-password")
	if err != nil {
		t.Fatalf("fecB: %v", err)
	}
	defer fecB.Close()

	testMsg := []byte("OBFUSCATED_HEADER_PAYLOAD")
	_, err = fecA.WriteTo(testMsg, rawB.localAddr)
	if err != nil {
		t.Fatalf("WriteTo: %v", err)
	}

	readBuf := make([]byte, 1024)
	n, _, err := fecB.ReadFrom(readBuf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if !bytes.Equal(readBuf[:n], testMsg) {
		t.Fatalf("got %s, want %s", readBuf[:n], testMsg)
	}
	t.Logf("✓ Verified: Encrypted/obfuscated FEC headers round-trip cleanly")
}

package core

import (
	"bytes"
	"testing"
)

func TestRoundTripIPv4(t *testing.T) {
	remoteIP := []byte{8, 8, 8, 8}
	remotePort := uint16(53)
	payload := []byte("hello udp world, this is a DNS-ish payload")

	preambleSize := 7 + len(remoteIP) // matches newPortForward's calc
	buf := make([]byte, udpgwMaxMessageSize)

	if err := writeUdpgwPreamble(preambleSize, 0, 42, remoteIP, remotePort, uint16(len(payload)), buf); err != nil {
		t.Fatalf("write failed: %v", err)
	}
	full := append([]byte{}, buf[:preambleSize+len(payload)]...)
	copy(full[preambleSize:], payload)

	msg, err := readUdpgwMessage(bytes.NewReader(full), make([]byte, udpgwMaxMessageSize))
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}
	if msg.connID != 42 {
		t.Fatalf("connID mismatch: got %d", msg.connID)
	}
	if !ipEqual(msg.remoteIP, remoteIP) {
		t.Fatalf("ip mismatch: got %v want %v", msg.remoteIP, remoteIP)
	}
	if msg.remotePort != remotePort {
		t.Fatalf("port mismatch: got %d want %d", msg.remotePort, remotePort)
	}
	if !bytes.Equal(msg.packet, payload) {
		t.Fatalf("payload mismatch: got %q want %q", msg.packet, payload)
	}
}

func TestRoundTripIPv6(t *testing.T) {
	remoteIP := []byte{0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0x88, 0x88} // 2001:4860:4860::8888
	remotePort := uint16(443)
	payload := []byte("v6 payload")

	preambleSize := 7 + len(remoteIP) // 23
	buf := make([]byte, udpgwMaxMessageSize)
	flags := uint8(udpgwFlagIPv6)

	if err := writeUdpgwPreamble(preambleSize, flags, 7, remoteIP, remotePort, uint16(len(payload)), buf); err != nil {
		t.Fatalf("write failed: %v", err)
	}
	full := append([]byte{}, buf[:preambleSize+len(payload)]...)
	copy(full[preambleSize:], payload)
	// writeUdpgwPreamble writes flags at buf[2] but we need it in the actual
	// message too -- writeUdpgwPreamble takes flags as a param and writes it,
	// so full already has it correctly since we sliced from buf.

	msg, err := readUdpgwMessage(bytes.NewReader(full), make([]byte, udpgwMaxMessageSize))
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}
	if msg.connID != 7 {
		t.Fatalf("connID mismatch: got %d", msg.connID)
	}
	if len(msg.remoteIP) != 16 || !ipEqual(msg.remoteIP, remoteIP) {
		t.Fatalf("ipv6 mismatch: got %v want %v", msg.remoteIP, remoteIP)
	}
	if msg.remotePort != remotePort {
		t.Fatalf("port mismatch: got %d want %d", msg.remotePort, remotePort)
	}
	if !bytes.Equal(msg.packet, payload) {
		t.Fatalf("payload mismatch: got %q want %q", msg.packet, payload)
	}
}

func TestKeepaliveSkipped(t *testing.T) {
	buf := make([]byte, 16)
	// size=3 (flags+connID only, no addr/payload), flags=keepalive, connID=0
	buf[0], buf[1] = 3, 0
	buf[2] = udpgwFlagKeepalive
	buf[3], buf[4] = 0, 0

	msg, err := readUdpgwMessage(bytes.NewReader(buf[:5]), make([]byte, udpgwMaxMessageSize))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if msg != nil {
		t.Fatalf("expected nil message for keepalive, got %+v", msg)
	}
}

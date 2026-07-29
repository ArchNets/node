package core

import (
	"net"
	"testing"
	"time"
)

func TestShadowTLSVersionValidation(t *testing.T) {
	invalidVersions := []int{0, 1, 4, -1}
	for _, v := range invalidVersions {
		core, err := NewShadowTLSCore("test", 10000, v, "www.google.com:443", true, 20000)
		if err == nil {
			t.Fatalf("expected error for invalid version %d, got nil", v)
		}
		if core != nil {
			t.Fatalf("expected nil core for invalid version %d", v)
		}
	}

	validVersions := []int{2, 3}
	for _, v := range validVersions {
		core, err := NewShadowTLSCore("test", 10000, v, "www.google.com:443", true, 20000)
		if err != nil {
			t.Fatalf("unexpected error for valid version %d: %v", v, err)
		}
		if core.Version != v {
			t.Fatalf("expected core.Version to be %d, got %d", v, core.Version)
		}
	}
}

func TestCopyWithAccountingClosing(t *testing.T) {
	clientConn, serverConn := net.Pipe()

	core, err := NewShadowTLSCore("test", 10000, 3, "www.google.com:443", true, 20000)
	if err != nil {
		t.Fatalf("failed to create core: %v", err)
	}

	done := make(chan struct{})
	go func() {
		core.copyWithAccounting(serverConn, clientConn, 1, false)
		close(done)
	}()

	// Close clientConn to simulate stream termination
	clientConn.Close()

	select {
	case <-done:
		// copyWithAccounting successfully returned on read error/EOF
	case <-time.After(2 * time.Second):
		t.Fatal("copyWithAccounting did not return after conn was closed")
	}
}

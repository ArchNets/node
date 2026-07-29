package core

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/archnets/node/api/panel"
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

func TestShadowTLSCore_StartWithZeroUsers_NoError(t *testing.T) {
	port := 28543
	shadowsocksPort := 28544

	core, err := NewShadowTLSCore("test-zero-users", port, 3, "www.google.com:443", true, shadowsocksPort)
	if err != nil {
		t.Fatalf("failed to create core: %v", err)
	}

	// 1. Start with 0 users should return nil (no error)
	err = core.Start()
	if err != nil {
		t.Fatalf("expected Start() with 0 users to return nil, got: %v", err)
	}
	defer core.Stop()

	// 2. Port should NOT accept connections yet because service/listener is pending
	addr := net.JoinHostPort("127.0.0.1", fmt.Sprintf("%d", port))
	conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
	if err == nil {
		conn.Close()
		t.Fatalf("expected port %s to NOT accept connections when pending zero users", addr)
	}

	// 3. Adding 1 user should create service and start listener
	core.AddUsers([]panel.UserInfo{
		{Id: 1, Uuid: "test-user-uuid-1"},
	})

	// 4. Port should now accept TCP connections
	conn, err = net.DialTimeout("tcp", addr, 1*time.Second)
	if err != nil {
		t.Fatalf("expected port %s to accept connections after user sync, got: %v", addr, err)
	}
	conn.Close()
}

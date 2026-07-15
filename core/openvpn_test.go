package core

import (
	"os"
	"testing"

	"github.com/archnets/node/api/panel"
)

func TestOpenVPNCoreAddDelUsers(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "ovpn-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	core, err := NewOpenVPNCore("test-ovpn", 1194, "udp", "10.9.0.0/24", tmpDir, "", "", "test-key")
	if err != nil {
		t.Fatalf("failed to create core: %v", err)
	}

	users := []panel.UserInfo{
		{Id: 1, Uuid: "user-uuid-1"},
		{Id: 2, Uuid: "user-uuid-2"},
	}
	core.AddUsers(users)

	core.users.mu.RLock()
	if len(core.users.uuidToID) != 2 {
		t.Errorf("expected 2 users, got %d", len(core.users.uuidToID))
	}
	if core.users.uuidToID["user-uuid-1"] != 1 {
		t.Errorf("expected ID 1, got %d", core.users.uuidToID["user-uuid-1"])
	}
	core.users.mu.RUnlock()

	core.DelUsers([]panel.UserInfo{{Id: 1, Uuid: "user-uuid-1"}})

	core.users.mu.RLock()
	if len(core.users.uuidToID) != 1 {
		t.Errorf("expected 1 user, got %d", len(core.users.uuidToID))
	}
	if _, exists := core.users.uuidToID["user-uuid-1"]; exists {
		t.Errorf("user-uuid-1 should have been deleted")
	}
	core.users.mu.RUnlock()
}

func TestOpenVPNCoreTrafficDelta(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "ovpn-test-traffic")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	core, err := NewOpenVPNCore("test-ovpn-traffic", 1194, "udp", "10.9.0.0/24", tmpDir, "", "", "test-key")
	if err != nil {
		t.Fatalf("failed to create core: %v", err)
	}

	// Mock active session
	sess := &ovpnSession{
		UID:  42,
		UUID: "user-uuid-42",
		CID:  "client-cid-1",
	}
	core.sessions.Store("client-cid-1", sess)

	// First bytecount event (e.g. 100 bytes in, 200 bytes out)
	ev1 := ovpnEvent{
		kind: "BYTECOUNT_CLI",
		cid:  "client-cid-1",
		in:   100,
		out:  200,
	}
	core.handleByteCount(ev1)

	// Check accumulated traffic
	traffic1 := core.GetTrafficAndReset()
	t1, ok := traffic1[42]
	if !ok {
		t.Fatalf("traffic stats for user 42 not found")
	}
	if t1.Upload != 100 {
		t.Errorf("expected upload 100, got %d", t1.Upload)
	}
	if t1.Download != 200 {
		t.Errorf("expected download 200, got %d", t1.Download)
	}

	// Second event: cumulative increases to 150 in, 350 out
	ev2 := ovpnEvent{
		kind: "BYTECOUNT_CLI",
		cid:  "client-cid-1",
		in:   150,
		out:  350,
	}
	core.handleByteCount(ev2)

	// Delta should be +50 in, +150 out
	traffic2 := core.GetTrafficAndReset()
	t2, ok := traffic2[42]
	if !ok {
		t.Fatalf("traffic stats for user 42 not found after second event")
	}
	if t2.Upload != 50 {
		t.Errorf("expected delta upload 50, got %d", t2.Upload)
	}
	if t2.Download != 150 {
		t.Errorf("expected delta download 150, got %d", t2.Download)
	}
}

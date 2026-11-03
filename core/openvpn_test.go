package core

import (
	"net"
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

func TestOpenVPNHandleClientConnectAuth(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "ovpn-test-auth")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	core, err := NewOpenVPNCore("test-ovpn-auth-udp", 1194, "udp", "10.9.0.0/24", tmpDir, "", "", "test-key")
	if err != nil {
		t.Fatalf("failed to create core: %v", err)
	}
	core.LimiterTag = "test-ovpn-base"

	users := []panel.UserInfo{
		{Id: 10, Uuid: "uuid-user-10"},
	}
	core.AddUsers(users)

	// Fallback to common_name when username is empty (standard client certificate mode)
	core.users.mu.RLock()
	uid, ok := core.users.uuidToID["uuid-user-10"]
	core.users.mu.RUnlock()
	if !ok || uid != 10 {
		t.Errorf("expected user ID 10 for uuid-user-10, got %d, ok=%v", uid, ok)
	}
}

func TestOpenVPNMgmtDoubleClose(t *testing.T) {
	// Create a dummy in-memory net.Pipe to test mgmt client lifecycle
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()

	c := &ovpnMgmtClient{
		conn:           clientConn,
		pendingReplies: make(chan string, 16),
		events:         make(chan ovpnEvent, 16),
		done:           make(chan struct{}),
	}

	// First Close should succeed
	if err := c.Close(); err != nil {
		t.Errorf("first Close() failed: %v", err)
	}

	// Second Close must not panic and must succeed cleanly
	if err := c.Close(); err != nil {
		t.Errorf("second Close() failed: %v", err)
	}
}

func TestOpenVPNReauthTrafficCounterPreservation(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "ovpn-test-reauth")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	core, err := NewOpenVPNCore("test-ovpn-reauth", 1194, "udp", "10.9.0.0/24", tmpDir, "", "", "test-key")
	if err != nil {
		t.Fatalf("failed to create core: %v", err)
	}

	core.AddUsers([]panel.UserInfo{{Id: 99, Uuid: "test-reauth-uuid"}})

	// 1. Initial connect
	evConnect := ovpnEvent{
		kind: "CLIENT_CONNECT",
		cid:  "cid-reauth-1",
		kid:  "0",
		env: map[string]string{
			"username":      "test-reauth-uuid",
			"untrusted_ip": "1.2.3.4",
		},
	}
	core.handleClientConnect(evConnect, false)

	// Verify session stored with 0 byte counts
	val, ok := core.sessions.Load("cid-reauth-1")
	if !ok {
		t.Fatalf("session not stored after initial connect")
	}
	sess := val.(*ovpnSession)
	if sess.LastBytesIn != 0 || sess.LastBytesOut != 0 {
		t.Errorf("expected initial 0 bytes, got in=%d out=%d", sess.LastBytesIn, sess.LastBytesOut)
	}

	// 2. Transmit 500 MB in, 200 MB out
	core.handleByteCount(ovpnEvent{
		kind: "BYTECOUNT_CLI",
		cid:  "cid-reauth-1",
		in:   500 * 1024 * 1024,
		out:  200 * 1024 * 1024,
	})

	traffic1 := core.GetTrafficAndReset()
	if traffic1[99].Upload != 500*1024*1024 || traffic1[99].Download != 200*1024*1024 {
		t.Fatalf("unexpected traffic recorded: %+v", traffic1[99])
	}

	// 3. One hour later: TLS Renegotiation triggers CLIENT_REAUTH with kid=1
	evReauth := ovpnEvent{
		kind: "CLIENT_REAUTH",
		cid:  "cid-reauth-1",
		kid:  "1",
		env: map[string]string{
			"username":      "test-reauth-uuid",
			"untrusted_ip": "1.2.3.4",
		},
	}
	core.handleClientConnect(evReauth, true)

	// Check that previous counters were preserved!
	val2, ok := core.sessions.Load("cid-reauth-1")
	if !ok {
		t.Fatalf("session missing after reauth")
	}
	sess2 := val2.(*ovpnSession)
	if sess2.LastBytesIn != 500*1024*1024 || sess2.LastBytesOut != 200*1024*1024 {
		t.Errorf("reauth lost prior byte counters: got in=%d, out=%d", sess2.LastBytesIn, sess2.LastBytesOut)
	}

	// 4. Next bytecount report after reauth has slightly increased traffic
	core.handleByteCount(ovpnEvent{
		kind: "BYTECOUNT_CLI",
		cid:  "cid-reauth-1",
		in:   505 * 1024 * 1024, // +5 MB
		out:  202 * 1024 * 1024, // +2 MB
	})

	traffic2 := core.GetTrafficAndReset()
	if traffic2[99].Upload != 5*1024*1024 {
		t.Errorf("traffic double-counted after reauth! Expected 5MB upload, got %d", traffic2[99].Upload)
	}
	if traffic2[99].Download != 2*1024*1024 {
		t.Errorf("traffic double-counted after reauth! Expected 2MB download, got %d", traffic2[99].Download)
	}
}

func TestLogRingBuffer(t *testing.T) {
	ring := newLogRingBuffer(3)

	_, _ = ring.Write([]byte("line 1\nline 2\n"))
	dump1 := ring.Dump()
	if len(dump1) != 2 || dump1[0] != "line 1" || dump1[1] != "line 2" {
		t.Fatalf("dump1 unexpected: %v", dump1)
	}

	// Overwrite ring buffer capacity (capacity = 3)
	_, _ = ring.Write([]byte("line 3\nline 4\n"))
	dump2 := ring.Dump()
	if len(dump2) != 3 {
		t.Fatalf("expected 3 lines, got %d: %v", len(dump2), dump2)
	}
	// Oldest "line 1" was discarded; should be [line 2, line 3, line 4]
	if dump2[0] != "line 2" || dump2[1] != "line 3" || dump2[2] != "line 4" {
		t.Errorf("unexpected ring buffer ordering: %v", dump2)
	}
}

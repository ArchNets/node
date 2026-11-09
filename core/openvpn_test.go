package core

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/archnets/node/api/panel"
)

type fakeOvpnResponder struct {
	mu             sync.Mutex
	authorizations []struct{ cid, kid string }
	denials        []struct{ cid, kid, reason string }
	kills          []string
	authCh         chan struct{ cid, kid string }
	denyCh         chan struct{ cid, kid, reason string }
	authErr        error
}

func newFakeOvpnResponder() *fakeOvpnResponder {
	return &fakeOvpnResponder{
		authCh: make(chan struct{ cid, kid string }, 10),
		denyCh: make(chan struct{ cid, kid, reason string }, 10),
	}
}

func (f *fakeOvpnResponder) authorizeClient(cid, kid string) error {
	f.mu.Lock()
	f.authorizations = append(f.authorizations, struct{ cid, kid string }{cid, kid})
	err := f.authErr
	f.mu.Unlock()
	f.authCh <- struct{ cid, kid string }{cid, kid}
	return err
}

func (f *fakeOvpnResponder) denyClient(cid, kid, reason string) error {
	f.mu.Lock()
	f.denials = append(f.denials, struct{ cid, kid, reason string }{cid, kid, reason})
	f.mu.Unlock()
	f.denyCh <- struct{ cid, kid, reason string }{cid, kid, reason}
	return nil
}

func (f *fakeOvpnResponder) killClient(cid string) error {
	f.mu.Lock()
	f.kills = append(f.kills, cid)
	f.mu.Unlock()
	return nil
}

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

	fakeResp := newFakeOvpnResponder()

	// 1. Authorize valid user
	evValid := ovpnEvent{
		kind: "CLIENT_CONNECT",
		cid:  "cid-10",
		kid:  "0",
		env: map[string]string{
			"common_name":   "uuid-user-10",
			"untrusted_ip": "1.2.3.4",
		},
	}
	core.handleClientConnect(evValid, false, fakeResp)

	select {
	case auth := <-fakeResp.authCh:
		if auth.cid != "cid-10" || auth.kid != "0" {
			t.Errorf("unexpected authorize payload: %+v", auth)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timed out waiting for authorizeClient")
	}

	// 2. Deny unknown user
	evInvalid := ovpnEvent{
		kind: "CLIENT_CONNECT",
		cid:  "cid-unknown",
		kid:  "0",
		env: map[string]string{
			"username":      "uuid-user-nonexistent",
			"untrusted_ip": "1.2.3.4",
		},
	}
	core.handleClientConnect(evInvalid, false, fakeResp)

	select {
	case deny := <-fakeResp.denyCh:
		if deny.cid != "cid-unknown" || deny.reason != "unknown user" {
			t.Errorf("unexpected deny payload: %+v", deny)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timed out waiting for denyClient")
	}
}

func TestOpenVPNHandleClientConnectAuthFailureCleansSession(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "ovpn-test-fail-auth")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	core, err := NewOpenVPNCore("test-ovpn-fail-auth", 1194, "udp", "10.9.0.0/24", tmpDir, "", "", "test-key")
	if err != nil {
		t.Fatalf("failed to create core: %v", err)
	}

	core.AddUsers([]panel.UserInfo{{Id: 77, Uuid: "uuid-user-77"}})
	fakeResp := newFakeOvpnResponder()
	fakeResp.authErr = fmt.Errorf("management socket closed")

	ev := ovpnEvent{
		kind: "CLIENT_CONNECT",
		cid:  "cid-fail-77",
		kid:  "0",
		env: map[string]string{
			"username":      "uuid-user-77",
			"untrusted_ip": "1.2.3.4",
		},
	}
	core.handleClientConnect(ev, false, fakeResp)

	// Wait for authorizeClient call to complete
	select {
	case <-fakeResp.authCh:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timed out waiting for authorizeClient")
	}

	// Yield for goroutine to execute o.sessions.Delete
	time.Sleep(20 * time.Millisecond)

	// Session must NOT remain in o.sessions
	if _, ok := core.sessions.Load("cid-fail-77"); ok {
		t.Errorf("session should have been deleted upon authorizeClient failure")
	}
}

func TestOpenVPNMgmtDoubleClose(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()

	c := &ovpnMgmtClient{
		conn:           clientConn,
		pendingReplies: make(chan string, 16),
		events:         make(chan ovpnEvent, 16),
		done:           make(chan struct{}),
	}

	if err := c.Close(); err != nil {
		t.Errorf("first Close() failed: %v", err)
	}

	if err := c.Close(); err != nil {
		t.Errorf("second Close() failed: %v", err)
	}
}

func TestOpenVPNMgmtConcurrentSend(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()

	c := &ovpnMgmtClient{
		conn:           clientConn,
		reader:         bufio.NewReader(clientConn),
		pendingReplies: make(chan string, 16),
		events:         make(chan ovpnEvent, 16),
		done:           make(chan struct{}),
	}
	go c.readLoop()
	defer c.Close()

	// Mock OpenVPN server replying to commands
	go func() {
		scanner := bufio.NewScanner(serverConn)
		for scanner.Scan() {
			cmd := scanner.Text()
			switch {
			case strings.HasPrefix(cmd, "slow-cmd"):
				time.Sleep(50 * time.Millisecond)
				_, _ = serverConn.Write([]byte("SUCCESS: slow reply\n"))
			case strings.HasPrefix(cmd, "fast-cmd"):
				_, _ = serverConn.Write([]byte("SUCCESS: fast reply\n"))
			default:
				_, _ = serverConn.Write([]byte("SUCCESS: default reply\n"))
			}
		}
	}()

	var wg sync.WaitGroup
	var replySlow, replyFast string
	var errSlow, errFast error

	wg.Add(2)
	go func() {
		defer wg.Done()
		replySlow, errSlow = c.send("slow-cmd")
	}()

	go func() {
		defer wg.Done()
		// Small delay to ensure slow-cmd acquires writeMu first
		time.Sleep(10 * time.Millisecond)
		replyFast, errFast = c.send("fast-cmd")
	}()

	wg.Wait()

	if errSlow != nil {
		t.Errorf("slow-cmd failed: %v", errSlow)
	}
	if replySlow != "SUCCESS: slow reply" {
		t.Errorf("slow reply crosstalk! got: %q", replySlow)
	}

	if errFast != nil {
		t.Errorf("fast-cmd failed: %v", errFast)
	}
	if replyFast != "SUCCESS: fast reply" {
		t.Errorf("fast reply crosstalk! got: %q", replyFast)
	}
}

func TestOpenVPNMgmtSendErrorReply(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()

	c := &ovpnMgmtClient{
		conn:           clientConn,
		reader:         bufio.NewReader(clientConn),
		pendingReplies: make(chan string, 16),
		events:         make(chan ovpnEvent, 16),
		done:           make(chan struct{}),
	}
	go c.readLoop()
	defer c.Close()

	go func() {
		scanner := bufio.NewScanner(serverConn)
		if scanner.Scan() {
			_, _ = serverConn.Write([]byte("ERROR: client-auth command failed: invalid kid\n"))
		}
	}()

	reply, err := c.send("client-auth-nt 1 2")
	if err == nil {
		t.Fatalf("expected error on ERROR: reply, got nil (reply: %q)", reply)
	}
	if !strings.Contains(err.Error(), "ERROR: client-auth command failed: invalid kid") {
		t.Errorf("error does not contain server reply: %v", err)
	}
}

func TestOpenVPNMgmtReadLoopReauthParsing(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()

	c := &ovpnMgmtClient{
		conn:           clientConn,
		reader:         bufio.NewReader(clientConn),
		pendingReplies: make(chan string, 16),
		events:         make(chan ovpnEvent, 16),
		done:           make(chan struct{}),
	}
	go c.readLoop()
	defer c.Close()

	payload := ">CLIENT:REAUTH,42,1\n>CLIENT:ENV,username=reauth-user\n>CLIENT:ENV,END\n"
	_, _ = serverConn.Write([]byte(payload))

	select {
	case ev := <-c.events:
		if ev.kind != "CLIENT_REAUTH" {
			t.Errorf("expected kind CLIENT_REAUTH, got %q", ev.kind)
		}
		if ev.cid != "42" || ev.kid != "1" {
			t.Errorf("expected cid 42, kid 1, got cid=%s kid=%s", ev.cid, ev.kid)
		}
		if ev.env["username"] != "reauth-user" {
			t.Errorf("expected username reauth-user, got %q", ev.env["username"])
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timed out waiting for CLIENT_REAUTH event")
	}
}

func TestOpenVPNMgmtReadLoopMalformedLinesNoPanic(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()

	c := &ovpnMgmtClient{
		conn:           clientConn,
		reader:         bufio.NewReader(clientConn),
		pendingReplies: make(chan string, 16),
		events:         make(chan ovpnEvent, 16),
		done:           make(chan struct{}),
	}
	go c.readLoop()
	defer c.Close()

	// Write malformed notification lines that lack commas or fields
	malformed := ">CLIENT:CONNECT\n>CLIENT:CONNECT,onlycid\n>CLIENT:REAUTH\n>CLIENT:REAUTH,onlycid\n>CLIENT:DISCONNECT\n>BYTECOUNT_CLI:incomplete\n>UNKNOWN:EVENT\n"
	_, _ = serverConn.Write([]byte(malformed))

	// Write a valid event afterwards to confirm readLoop is still alive
	valid := ">CLIENT:DISCONNECT,999\n"
	_, _ = serverConn.Write([]byte(valid))

	select {
	case ev := <-c.events:
		if ev.kind != "CLIENT_DISCONNECT" || ev.cid != "999" {
			t.Errorf("expected valid disconnect event, got %+v", ev)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("readLoop hung or died on malformed lines")
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
	fakeResp := newFakeOvpnResponder()

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
	core.handleClientConnect(evConnect, false, fakeResp)
	<-fakeResp.authCh

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
	core.handleClientConnect(evReauth, true, fakeResp)
	<-fakeResp.authCh

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

func TestOpenVPNCoreDoubleStop(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "ovpn-test-stop")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	core, err := NewOpenVPNCore("test-ovpn-stop", 1194, "udp", "10.9.0.0/24", tmpDir, "", "", "test-key")
	if err != nil {
		t.Fatalf("failed to create core: %v", err)
	}

	// First Stop on an unstarted core
	if err := core.Stop(); err != nil {
		t.Errorf("first Stop() failed: %v", err)
	}

	// Second Stop must not panic
	if err := core.Stop(); err != nil {
		t.Errorf("second Stop() failed: %v", err)
	}
}

func TestExtractOpenVPNClientIP(t *testing.T) {
	tests := []struct {
		name string
		env  map[string]string
		want string
	}{
		{
			name: "standard IPv4 in untrusted_ip",
			env:  map[string]string{"untrusted_ip": "5.188.190.113"},
			want: "5.188.190.113",
		},
		{
			name: "dual-stack IPv4-mapped IPv6 in untrusted_ip6",
			env:  map[string]string{"untrusted_ip6": "::ffff:5.188.190.113"},
			want: "5.188.190.113",
		},
		{
			name: "native IPv6 in untrusted_ip6 without port must not strip last segment",
			env:  map[string]string{"untrusted_ip6": "2a01:4f8:1c1b:186d::1"},
			want: "2a01:4f8:1c1b:186d::1",
		},
		{
			name: "bracketed IPv6 with port",
			env:  map[string]string{"trusted_ip6": "[2a01:4f8:1c1b:186d::1]:54321"},
			want: "2a01:4f8:1c1b:186d::1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := extractOpenVPNClientIP(tt.env); got != tt.want {
				t.Errorf("extractOpenVPNClientIP(%v) = %q, want %q", tt.env, got, tt.want)
			}
		})
	}
}

func TestOpenVPNWriteServerConfDynamicPerformance(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "ovpn-conf-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	core, err := NewOpenVPNCore("test-dyn-conf", 6444, "udp", "10.11.0.0/16", tmpDir, "ca.crt", "server.crt", "key")
	if err != nil {
		t.Fatalf("NewOpenVPNCore failed: %v", err)
	}
	core.TunMTU = 1400
	core.Sndbuf = 393216
	core.Rcvbuf = 393216
	core.TxQueueLen = 4000

	confPath := filepath.Join(tmpDir, "server.conf")
	if err := core.writeServerConf(confPath, "ca.crt", "server.crt", "server.key", "ta.key"); err != nil {
		t.Fatalf("writeServerConf failed: %v", err)
	}

	data, err := os.ReadFile(confPath)
	if err != nil {
		t.Fatalf("failed to read generated conf: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, "tun-mtu 1400") || !strings.Contains(content, "push \"tun-mtu 1400\"") {
		t.Errorf("expected dynamic tun-mtu 1400, got:\n%s", content)
	}
	if !strings.Contains(content, "sndbuf 393216") || !strings.Contains(content, "push \"sndbuf 393216\"") {
		t.Errorf("expected dynamic sndbuf 393216, got:\n%s", content)
	}
	if !strings.Contains(content, "txqueuelen 4000") {
		t.Errorf("expected dynamic txqueuelen 4000, got:\n%s", content)
	}
}

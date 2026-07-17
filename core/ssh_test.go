package core

import (
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/archnets/node/api/panel"
	"golang.org/x/crypto/ssh"
)

func TestNewSSHCore(t *testing.T) {
	// Test creating SSH core with auto-generated host key
	sshCore, err := NewSSHCore("test-ssh", 0, "", "") // port 0 = auto-assign
	if err != nil {
		t.Fatalf("Failed to create SSHCore: %v", err)
	}

	if sshCore.Tag != "test-ssh" {
		t.Errorf("Expected tag 'test-ssh', got '%s'", sshCore.Tag)
	}

	if sshCore.users == nil {
		t.Error("Users map should not be nil")
	}

	if sshCore.traffic == nil {
		t.Error("Traffic map should not be nil")
	}
}

func TestSSHCoreAddDelUsers(t *testing.T) {
	sshCore, err := NewSSHCore("test-ssh", 0, "", "")
	if err != nil {
		t.Fatalf("Failed to create SSHCore: %v", err)
	}

	// Add users
	users := []panel.UserInfo{
		{Id: 1, Uuid: "user-uuid-1"},
		{Id: 2, Uuid: "user-uuid-2"},
		{Id: 3, Uuid: "user-uuid-3"},
	}
	sshCore.AddUsers(users)

	// Verify users were added
	sshCore.users.mu.RLock()
	if len(sshCore.users.uuidToID) != 3 {
		t.Errorf("Expected 3 users, got %d", len(sshCore.users.uuidToID))
	}
	if sshCore.users.uuidToID["user-uuid-1"] != 1 {
		t.Error("User 1 not found or has wrong ID")
	}
	sshCore.users.mu.RUnlock()

	// Delete some users
	delUsers := []panel.UserInfo{
		{Id: 2, Uuid: "user-uuid-2"},
	}
	sshCore.DelUsers(delUsers)

	// Verify user was deleted
	sshCore.users.mu.RLock()
	if len(sshCore.users.uuidToID) != 2 {
		t.Errorf("Expected 2 users after deletion, got %d", len(sshCore.users.uuidToID))
	}
	if _, exists := sshCore.users.uuidToID["user-uuid-2"]; exists {
		t.Error("User 2 should have been deleted")
	}
	sshCore.users.mu.RUnlock()
}

func TestSSHCoreTrafficAccounting(t *testing.T) {
	sshCore, err := NewSSHCore("test-ssh", 0, "", "")
	if err != nil {
		t.Fatalf("Failed to create SSHCore: %v", err)
	}

	// Add traffic for user 1
	sshCore.addTraffic(1, 1000, false) // upload
	sshCore.addTraffic(1, 2000, true)  // download
	sshCore.addTraffic(1, 500, false)  // more upload

	// Add traffic for user 2
	sshCore.addTraffic(2, 5000, true) // download

	// Get and reset traffic
	traffic := sshCore.GetTrafficAndReset()

	// Verify user 1 traffic
	if traffic[1] == nil {
		t.Fatal("Traffic for user 1 should exist")
	}
	if traffic[1].Upload != 1500 {
		t.Errorf("Expected upload 1500, got %d", traffic[1].Upload)
	}
	if traffic[1].Download != 2000 {
		t.Errorf("Expected download 2000, got %d", traffic[1].Download)
	}

	// Verify user 2 traffic
	if traffic[2] == nil {
		t.Fatal("Traffic for user 2 should exist")
	}
	if traffic[2].Download != 5000 {
		t.Errorf("Expected download 5000, got %d", traffic[2].Download)
	}

	// Verify traffic was reset
	traffic2 := sshCore.GetTrafficAndReset()
	if len(traffic2) != 0 {
		t.Error("Traffic should be empty after reset")
	}
}

func TestSSHCoreStartStop(t *testing.T) {
	sshCore, err := NewSSHCore("test-ssh", 0, "", "") // port 0 = auto-assign
	if err != nil {
		t.Fatalf("Failed to create SSHCore: %v", err)
	}

	// Start server
	err = sshCore.Start()
	if err != nil {
		t.Fatalf("Failed to start SSH server: %v", err)
	}

	// Verify server is running
	if !sshCore.running.Load() {
		t.Error("Server should be running")
	}

	// Get the actual port
	addr := sshCore.listener.Addr().(*net.TCPAddr)
	t.Logf("SSH server started on port %d", addr.Port)

	// Stop server
	err = sshCore.Stop()
	if err != nil {
		t.Fatalf("Failed to stop SSH server: %v", err)
	}

	// Verify server is stopped
	if sshCore.running.Load() {
		t.Error("Server should not be running")
	}
}

func TestSSHCoreAuthentication(t *testing.T) {
	sshCore, err := NewSSHCore("test-ssh", 0, "", "")
	if err != nil {
		t.Fatalf("Failed to create SSHCore: %v", err)
	}

	// Add a test user
	users := []panel.UserInfo{
		{Id: 1, Uuid: "test-user-uuid"},
	}
	sshCore.AddUsers(users)

	// Start server
	err = sshCore.Start()
	if err != nil {
		t.Fatalf("Failed to start SSH server: %v", err)
	}
	defer sshCore.Stop()

	addr := sshCore.listener.Addr().(*net.TCPAddr)

	// Test successful authentication
	t.Run("ValidAuth", func(t *testing.T) {
		config := &ssh.ClientConfig{
			User: "test-user-uuid",
			Auth: []ssh.AuthMethod{
				ssh.Password("test-user-uuid"),
			},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			Timeout:         5 * time.Second,
		}

		client, err := ssh.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", addr.Port), config)
		if err != nil {
			t.Fatalf("Failed to connect with valid credentials: %v", err)
		}
		client.Close()
	})

	// Test invalid password
	t.Run("InvalidPassword", func(t *testing.T) {
		config := &ssh.ClientConfig{
			User: "test-user-uuid",
			Auth: []ssh.AuthMethod{
				ssh.Password("wrong-password"),
			},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			Timeout:         5 * time.Second,
		}

		_, err := ssh.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", addr.Port), config)
		if err == nil {
			t.Error("Should not connect with wrong password")
		}
	})

	// Test unknown user
	t.Run("UnknownUser", func(t *testing.T) {
		config := &ssh.ClientConfig{
			User: "unknown-user",
			Auth: []ssh.AuthMethod{
				ssh.Password("unknown-user"),
			},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			Timeout:         5 * time.Second,
		}

		_, err := ssh.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", addr.Port), config)
		if err == nil {
			t.Error("Should not connect with unknown user")
		}
	})
}

func TestSSHCoreShellRejected(t *testing.T) {
	sshCore, err := NewSSHCore("test-ssh", 0, "", "")
	if err != nil {
		t.Fatalf("Failed to create SSHCore: %v", err)
	}

	users := []panel.UserInfo{
		{Id: 1, Uuid: "test-user-uuid"},
	}
	sshCore.AddUsers(users)

	err = sshCore.Start()
	if err != nil {
		t.Fatalf("Failed to start SSH server: %v", err)
	}
	defer sshCore.Stop()

	addr := sshCore.listener.Addr().(*net.TCPAddr)

	config := &ssh.ClientConfig{
		User: "test-user-uuid",
		Auth: []ssh.AuthMethod{
			ssh.Password("test-user-uuid"),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}

	client, err := ssh.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", addr.Port), config)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer client.Close()

	// Try to open a session and request shell - should fail
	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}
	defer session.Close()

	// Request shell - this should be rejected
	err = session.Shell()
	if err == nil {
		t.Error("Shell request should be rejected")
	}
}

func TestSSHCorePortForward(t *testing.T) {
	sshCore, err := NewSSHCore("test-ssh", 0, "", "")
	if err != nil {
		t.Fatalf("Failed to create SSHCore: %v", err)
	}

	users := []panel.UserInfo{
		{Id: 1, Uuid: "test-user-uuid"},
	}
	sshCore.AddUsers(users)

	err = sshCore.Start()
	if err != nil {
		t.Fatalf("Failed to start SSH server: %v", err)
	}
	defer sshCore.Stop()

	sshAddr := sshCore.listener.Addr().(*net.TCPAddr)

	// Start a simple echo server to forward to
	echoListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to start echo server: %v", err)
	}
	defer echoListener.Close()

	echoAddr := echoListener.Addr().(*net.TCPAddr)

	// Echo server goroutine
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, err := echoListener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		io.Copy(conn, conn) // Echo back
	}()

	// Connect SSH client
	config := &ssh.ClientConfig{
		User: "test-user-uuid",
		Auth: []ssh.AuthMethod{
			ssh.Password("test-user-uuid"),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}

	client, err := ssh.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", sshAddr.Port), config)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer client.Close()

	// Open port forward channel to echo server
	conn, err := client.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", echoAddr.Port))
	if err != nil {
		t.Fatalf("Failed to open port forward: %v", err)
	}
	defer conn.Close()

	// Send data through tunnel
	testData := []byte("Hello through SSH tunnel!")
	_, err = conn.Write(testData)
	if err != nil {
		t.Fatalf("Failed to write to tunnel: %v", err)
	}

	// Read echo response
	buf := make([]byte, len(testData))
	_, err = io.ReadFull(conn, buf)
	if err != nil {
		t.Fatalf("Failed to read from tunnel: %v", err)
	}

	if string(buf) != string(testData) {
		t.Errorf("Echo mismatch: expected %s, got %s", testData, buf)
	}

	// Verify traffic was accounted
	time.Sleep(100 * time.Millisecond) // Allow traffic accounting to complete
	traffic := sshCore.GetTrafficAndReset()
	if traffic[1] == nil {
		t.Error("Traffic should be recorded for user 1")
	} else {
		total := traffic[1].Upload + traffic[1].Download
		if total < int64(len(testData)) {
			t.Errorf("Expected at least %d bytes traffic, got %d", len(testData), total)
		}
		t.Logf("Traffic recorded: upload=%d, download=%d", traffic[1].Upload, traffic[1].Download)
	}
}

func TestSSHCoreGetOnlineUsers(t *testing.T) {
	sshCore, err := NewSSHCore("test-ssh", 0, "", "")
	if err != nil {
		t.Fatalf("Failed to create SSHCore: %v", err)
	}

	users := []panel.UserInfo{
		{Id: 1, Uuid: "user-1"},
		{Id: 2, Uuid: "user-2"},
	}
	sshCore.AddUsers(users)

	err = sshCore.Start()
	if err != nil {
		t.Fatalf("Failed to start SSH server: %v", err)
	}
	defer sshCore.Stop()

	addr := sshCore.listener.Addr().(*net.TCPAddr)

	// Initially no online users
	online := sshCore.GetOnlineUsers()
	if len(online) != 0 {
		t.Errorf("Expected 0 online users, got %d", len(online))
	}

	// Connect user 1
	config := &ssh.ClientConfig{
		User: "user-1",
		Auth: []ssh.AuthMethod{
			ssh.Password("user-1"),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}

	client, err := ssh.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", addr.Port), config)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}

	// Give time for session to be registered
	time.Sleep(100 * time.Millisecond)

	online = sshCore.GetOnlineUsers()
	if len(online) != 1 {
		t.Errorf("Expected 1 online user, got %d", len(online))
	}
	if len(online) > 0 && online[0].UID != 1 {
		t.Errorf("Expected user 1 online, got user %d", online[0].UID)
	}

	// Disconnect
	client.Close()
	time.Sleep(100 * time.Millisecond)

	online = sshCore.GetOnlineUsers()
	if len(online) != 0 {
		t.Errorf("Expected 0 online users after disconnect, got %d", len(online))
	}
}

func TestExtractIP(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"192.168.1.1:22", "192.168.1.1"},
		{"[::1]:22", "::1"},
		{"[2001:db8::1]:22", "2001:db8::1"},
		{"::ffff:192.168.1.1:22", "192.168.1.1"},
		{"127.0.0.1:8080", "127.0.0.1"},
	}

	for _, test := range tests {
		result := extractIP(test.input)
		if result != test.expected {
			t.Errorf("extractIP(%s) = %s, expected %s", test.input, result, test.expected)
		}
	}
}

func TestSSHCoreStopWithStuckHandshake(t *testing.T) {
	sshCore, err := NewSSHCore("test-ssh-stuck", 0, "", "")
	if err != nil {
		t.Fatalf("Failed to create SSHCore: %v", err)
	}

	err = sshCore.Start()
	if err != nil {
		t.Fatalf("Failed to start SSH server: %v", err)
	}

	addr := sshCore.listener.Addr().(*net.TCPAddr)

	// Connect a raw TCP client but send no data (stuck handshake)
	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", addr.Port))
	if err != nil {
		t.Fatalf("Failed to connect raw TCP client: %v", err)
	}
	defer conn.Close()

	// Wait for acceptLoop to process the connection
	time.Sleep(50 * time.Millisecond)

	// Verify the connection is tracked in pendingConns
	count := 0
	sshCore.pendingConns.Range(func(key, value interface{}) bool {
		count++
		return true
	})
	if count != 1 {
		t.Errorf("Expected 1 pending connection, got %d", count)
	}

	// Stop the server and measure time
	start := time.Now()
	err = sshCore.Stop()
	if err != nil {
		t.Fatalf("Failed to stop SSH server: %v", err)
	}
	duration := time.Since(start)

	if duration > 2*time.Second {
		t.Errorf("Stop took too long: %v, expected it to finish quickly", duration)
	}

	// Verify the client connection was closed by checking if we get EOF (not timeout)
	conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	readBuf := make([]byte, 1024)
	for {
		_, err = conn.Read(readBuf)
		if err != nil {
			break
		}
	}
	if err == nil {
		t.Error("Client connection was not closed by Stop()")
	} else if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		t.Error("Client connection was not closed by Stop() (read timed out)")
	}
}

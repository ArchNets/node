package core

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/archnets/node/api/panel"
	"github.com/archnets/node/common/format"
	"github.com/archnets/node/limiter"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

// SSHCore manages the SSH tunnel server
type SSHCore struct {
	Tag        string
	Port       int
	config     *ssh.ServerConfig
	listener   net.Listener
	users      *SSHUserMap
	limiterRef *limiter.Limiter
	sessions   sync.Map // map[string]*SSHSession - key: "uid:ip"
	running    atomic.Bool
	wg         sync.WaitGroup

	// Traffic accounting
	trafficMu sync.RWMutex
	traffic   map[int]*UserTraffic // key: uid
}

// SSHUserMap stores user credentials for authentication
type SSHUserMap struct {
	mu       sync.RWMutex
	uuidToID map[string]int    // UUID -> user ID
	idToUUID map[int]string    // user ID -> UUID
	users    map[string]string // UUID -> password (for password auth) or empty for UUID-only auth
}

// SSHSession tracks an active SSH connection
type SSHSession struct {
	UID         int
	IP          string
	UUID        string
	ConnectedAt time.Time
	conn        ssh.Conn
}

// UserTraffic tracks upload/download bytes per user
type UserTraffic struct {
	Upload   int64
	Download int64
}

// NewSSHCore creates a new SSH tunnel server
func NewSSHCore(tag string, port int, hostKeyPath string) (*SSHCore, error) {
	sshCore := &SSHCore{
		Tag:  tag,
		Port: port,
		users: &SSHUserMap{
			uuidToID: make(map[string]int),
			idToUUID: make(map[int]string),
			users:    make(map[string]string),
		},
		traffic: make(map[int]*UserTraffic),
	}

	// Load or generate host key
	hostKey, err := loadOrGenerateHostKey(hostKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to setup host key: %w", err)
	}

	// Configure SSH server
	sshCore.config = &ssh.ServerConfig{
		PasswordCallback: sshCore.passwordCallback,
		MaxAuthTries:     3,
	}
	sshCore.config.AddHostKey(hostKey)

	return sshCore, nil
}

// passwordCallback handles password authentication
// Users authenticate with their UUID as username and UUID as password (or custom password)
func (s *SSHCore) passwordCallback(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
	s.users.mu.RLock()
	defer s.users.mu.RUnlock()

	uuid := conn.User()
	remoteAddr := conn.RemoteAddr().String()
	ip := extractIP(remoteAddr)

	// Check if user exists
	uid, exists := s.users.uuidToID[uuid]
	if !exists {
		log.WithFields(log.Fields{
			"uuid": uuid,
			"ip":   ip,
		}).Warn("SSH auth failed: unknown user")
		return nil, fmt.Errorf("unknown user")
	}

	// Verify password (UUID is used as password by default)
	expectedPass := s.users.users[uuid]
	if expectedPass == "" {
		expectedPass = uuid // Default: use UUID as password
	}
	if string(password) != expectedPass {
		log.WithFields(log.Fields{
			"uuid": uuid,
			"ip":   ip,
		}).Warn("SSH auth failed: invalid password")
		return nil, fmt.Errorf("invalid password")
	}

	// Check device limit via limiter
	if s.limiterRef != nil {
		tagUUID := format.UserTag(s.Tag, uuid)
		_, reject := s.limiterRef.CheckLimit(tagUUID, ip, true, true)
		if reject {
			log.WithFields(log.Fields{
				"uid": uid,
				"ip":  ip,
			}).Warn("SSH auth rejected: device limit exceeded")
			return nil, fmt.Errorf("device limit exceeded")
		}
	}

	log.WithFields(log.Fields{
		"uid": uid,
		"ip":  ip,
	}).Info("SSH auth successful")

	return &ssh.Permissions{
		Extensions: map[string]string{
			"uid":  fmt.Sprintf("%d", uid),
			"uuid": uuid,
			"ip":   ip,
		},
	}, nil
}

// Start starts the SSH server
func (s *SSHCore) Start() error {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", s.Port))
	if err != nil {
		return fmt.Errorf("failed to listen on port %d: %w", s.Port, err)
	}
	s.listener = listener
	s.running.Store(true)

	log.WithFields(log.Fields{
		"tag":  s.Tag,
		"port": s.Port,
	}).Info("SSH server started")

	go s.acceptLoop()
	return nil
}

// Stop stops the SSH server gracefully
func (s *SSHCore) Stop() error {
	s.running.Store(false)
	if s.listener != nil {
		s.listener.Close()
	}

	// Close all active sessions
	s.sessions.Range(func(key, value interface{}) bool {
		if session, ok := value.(*SSHSession); ok {
			session.conn.Close()
		}
		return true
	})

	s.wg.Wait()
	log.WithField("tag", s.Tag).Info("SSH server stopped")
	return nil
}

// acceptLoop accepts incoming connections
func (s *SSHCore) acceptLoop() {
	for s.running.Load() {
		conn, err := s.listener.Accept()
		if err != nil {
			if s.running.Load() {
				log.WithError(err).Error("SSH accept error")
			}
			continue
		}

		s.wg.Add(1)
		go s.handleConnection(conn)
	}
}

// handleConnection handles a single SSH connection
func (s *SSHCore) handleConnection(netConn net.Conn) {
	defer s.wg.Done()
	defer netConn.Close()

	// Perform SSH handshake
	sshConn, chans, reqs, err := ssh.NewServerConn(netConn, s.config)
	if err != nil {
		log.WithError(err).Debug("SSH handshake failed")
		return
	}
	defer sshConn.Close()

	// Extract user info from permissions
	uid := 0
	uuid := ""
	ip := ""
	if sshConn.Permissions != nil {
		fmt.Sscanf(sshConn.Permissions.Extensions["uid"], "%d", &uid)
		uuid = sshConn.Permissions.Extensions["uuid"]
		ip = sshConn.Permissions.Extensions["ip"]
	}

	// Track session
	sessionKey := fmt.Sprintf("%d:%s", uid, ip)
	session := &SSHSession{
		UID:         uid,
		IP:          ip,
		UUID:        uuid,
		ConnectedAt: time.Now(),
		conn:        sshConn,
	}
	s.sessions.Store(sessionKey, session)
	defer s.sessions.Delete(sessionKey)

	log.WithFields(log.Fields{
		"uid": uid,
		"ip":  ip,
		"tag": s.Tag,
	}).Info("SSH session started")

	// Handle global requests (keepalive, etc.)
	go ssh.DiscardRequests(reqs)

	// Handle channel requests
	for newChannel := range chans {
		s.handleChannel(newChannel, uid)
	}

	log.WithFields(log.Fields{
		"uid": uid,
		"ip":  ip,
		"tag": s.Tag,
	}).Info("SSH session ended")
}

// handleChannel handles SSH channel requests
func (s *SSHCore) handleChannel(newChannel ssh.NewChannel, uid int) {
	switch newChannel.ChannelType() {
	case "direct-tcpip":
		// Port forwarding - this is what we allow
		s.handleDirectTCPIP(newChannel, uid)
	case "session":
		// Session channel - accept but reject shell/exec requests
		s.handleSession(newChannel, uid)
	default:
		log.WithFields(log.Fields{
			"type": newChannel.ChannelType(),
			"uid":  uid,
		}).Debug("Rejecting unknown channel type")
		newChannel.Reject(ssh.UnknownChannelType, "only tunneling allowed")
	}
}

// directTCPIPData represents the extra data for direct-tcpip channels
type directTCPIPData struct {
	DestHost   string
	DestPort   uint32
	OriginHost string
	OriginPort uint32
}

// handleDirectTCPIP handles port forwarding requests (the main tunnel functionality)
func (s *SSHCore) handleDirectTCPIP(newChannel ssh.NewChannel, uid int) {
	var data directTCPIPData
	if err := ssh.Unmarshal(newChannel.ExtraData(), &data); err != nil {
		newChannel.Reject(ssh.ConnectionFailed, "failed to parse forward data")
		return
	}

	// Use net.JoinHostPort for proper IPv6 support
	dest := net.JoinHostPort(data.DestHost, fmt.Sprintf("%d", data.DestPort))
	log.WithFields(log.Fields{
		"uid":  uid,
		"dest": dest,
	}).Info("SSH port forward request")

	// Connect to destination
	destConn, err := net.DialTimeout("tcp", dest, 10*time.Second)
	if err != nil {
		newChannel.Reject(ssh.ConnectionFailed, fmt.Sprintf("failed to connect to %s", dest))
		return
	}

	// Accept the channel
	channel, requests, err := newChannel.Accept()
	if err != nil {
		destConn.Close()
		return
	}

	// Discard any channel-specific requests
	go ssh.DiscardRequests(requests)

	// Bidirectional copy with traffic accounting
	go func() {
		defer channel.Close()
		defer destConn.Close()
		s.copyWithAccounting(destConn, channel, uid, true) // download
	}()

	go func() {
		defer channel.Close()
		defer destConn.Close()
		s.copyWithAccounting(channel, destConn, uid, false) // upload
	}()
}

// handleSession handles session channel requests (we reject shell/exec)
func (s *SSHCore) handleSession(newChannel ssh.NewChannel, uid int) {
	channel, requests, err := newChannel.Accept()
	if err != nil {
		return
	}
	defer channel.Close()

	// Handle session requests - reject everything that would give shell access
	for req := range requests {
		switch req.Type {
		case "shell", "exec", "pty-req":
			log.WithFields(log.Fields{
				"type": req.Type,
				"uid":  uid,
			}).Debug("Rejecting shell/exec request")
			if req.WantReply {
				req.Reply(false, nil)
			}
		case "subsystem":
			// Could potentially allow SFTP here in the future
			if req.WantReply {
				req.Reply(false, nil)
			}
		default:
			if req.WantReply {
				req.Reply(false, nil)
			}
		}
	}
}

// copyWithAccounting copies data between connections and tracks traffic
func (s *SSHCore) copyWithAccounting(dst io.Writer, src io.Reader, uid int, isDownload bool) {
	buf := make([]byte, 32*1024)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			written, writeErr := dst.Write(buf[:n])
			if written > 0 {
				s.addTraffic(uid, int64(written), isDownload)
			}
			if writeErr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// addTraffic adds traffic to user's counter
func (s *SSHCore) addTraffic(uid int, bytes int64, isDownload bool) {
	s.trafficMu.Lock()
	defer s.trafficMu.Unlock()

	if s.traffic[uid] == nil {
		s.traffic[uid] = &UserTraffic{}
	}

	if isDownload {
		s.traffic[uid].Download += bytes
	} else {
		s.traffic[uid].Upload += bytes
	}
}

// GetTrafficAndReset returns traffic stats and resets counters
func (s *SSHCore) GetTrafficAndReset() map[int]*UserTraffic {
	s.trafficMu.Lock()
	defer s.trafficMu.Unlock()

	result := s.traffic
	s.traffic = make(map[int]*UserTraffic)
	return result
}

// SetLimiter sets the limiter reference for device limiting
func (s *SSHCore) SetLimiter(l *limiter.Limiter) {
	s.limiterRef = l
}

// AddUsers adds users to the SSH server
func (s *SSHCore) AddUsers(users []panel.UserInfo) {
	s.users.mu.Lock()
	defer s.users.mu.Unlock()

	for _, user := range users {
		s.users.uuidToID[user.Uuid] = user.Id
		s.users.idToUUID[user.Id] = user.Uuid
		s.users.users[user.Uuid] = "" // Use UUID as password
	}

	log.WithFields(log.Fields{
		"tag":   s.Tag,
		"count": len(users),
	}).Info("SSH users added")
}

// DelUsers removes users from the SSH server
func (s *SSHCore) DelUsers(users []panel.UserInfo) {
	s.users.mu.Lock()
	defer s.users.mu.Unlock()

	for _, user := range users {
		delete(s.users.uuidToID, user.Uuid)
		delete(s.users.idToUUID, user.Id)
		delete(s.users.users, user.Uuid)
	}

	log.WithFields(log.Fields{
		"tag":   s.Tag,
		"count": len(users),
	}).Info("SSH users removed")
}

// GetOnlineUsers returns list of currently connected users
func (s *SSHCore) GetOnlineUsers() []panel.OnlineUser {
	var online []panel.OnlineUser
	s.sessions.Range(func(key, value interface{}) bool {
		if session, ok := value.(*SSHSession); ok {
			online = append(online, panel.OnlineUser{
				UID: session.UID,
				IP:  session.IP,
			})
		}
		return true
	})
	return online
}

// Helper functions

func loadOrGenerateHostKey(path string) (ssh.Signer, error) {
	// If path is empty, use default location
	if path == "" {
		path = filepath.Join(os.TempDir(), "archnet_ssh_host_key")
	}

	// Try to load existing key
	keyBytes, err := os.ReadFile(path)
	if err == nil {
		signer, err := ssh.ParsePrivateKey(keyBytes)
		if err == nil {
			log.WithField("path", path).Info("Loaded existing SSH host key")
			return signer, nil
		}
	}

	// Generate new key
	log.WithField("path", path).Info("Generating new SSH host key")
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, err
	}

	// Encode to PEM
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	// Save to file
	if err := os.WriteFile(path, privateKeyPEM, 0600); err != nil {
		log.WithError(err).Warn("Failed to save SSH host key")
	}

	return ssh.NewSignerFromKey(privateKey)
}

func extractIP(remoteAddr string) string {
	ip := remoteAddr
	if idx := strings.LastIndex(ip, ":"); idx != -1 {
		ip = ip[:idx]
	}
	// Handle IPv6 with brackets
	ip = strings.TrimPrefix(ip, "[")
	ip = strings.TrimSuffix(ip, "]")
	// Handle IPv4-mapped IPv6
	ip = strings.TrimPrefix(ip, "::ffff:")
	return ip
}

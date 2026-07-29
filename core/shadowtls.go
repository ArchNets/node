package core

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/archnets/node/api/panel"
	"github.com/archnets/node/common/format"
	"github.com/archnets/node/limiter"
	shadowtls "github.com/sagernet/sing-shadowtls"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	log "github.com/sirupsen/logrus"
)

// ShadowTLSCore manages the ShadowTLS server
type ShadowTLSCore struct {
	Tag             string
	Port            int
	Version         int    // 3 is recommended
	HandshakeServer string // e.g., "www.google.com:443"
	StrictMode      bool
	ShadowsocksPort int // Local Shadowsocks port to forward to

	service        *shadowtls.Service
	listener       net.Listener
	users          *ShadowTLSUserMap
	limiterRef     *limiter.Limiter
	running        atomic.Bool
	servicePending atomic.Bool
	wg             sync.WaitGroup

	// Traffic accounting
	trafficMu sync.RWMutex
	traffic   map[int]*UserTraffic // key: uid
}

// ShadowTLSUserMap stores user credentials
type ShadowTLSUserMap struct {
	mu       sync.RWMutex
	uuidToID map[string]int // UUID -> user ID
	idToUUID map[int]string // user ID -> UUID
}

// shadowTLSLogger adapts logrus to sing's logger interface
type shadowTLSLogger struct {
	tag string
}

func (l *shadowTLSLogger) Trace(args ...any) {
	log.WithField("tag", l.tag).Trace(args...)
}
func (l *shadowTLSLogger) Debug(args ...any) {
	log.WithField("tag", l.tag).Debug(args...)
}
func (l *shadowTLSLogger) Info(args ...any) {
	log.WithField("tag", l.tag).Info(args...)
}
func (l *shadowTLSLogger) Warn(args ...any) {
	log.WithField("tag", l.tag).Warn(args...)
}
func (l *shadowTLSLogger) Error(args ...any) {
	log.WithField("tag", l.tag).Error(args...)
}
func (l *shadowTLSLogger) Fatal(args ...any) {
	log.WithField("tag", l.tag).Fatal(args...)
}
func (l *shadowTLSLogger) Panic(args ...any) {
	log.WithField("tag", l.tag).Panic(args...)
}
func (l *shadowTLSLogger) TraceContext(ctx context.Context, args ...any) {
	log.WithField("tag", l.tag).Trace(args...)
}
func (l *shadowTLSLogger) DebugContext(ctx context.Context, args ...any) {
	log.WithField("tag", l.tag).Debug(args...)
}
func (l *shadowTLSLogger) InfoContext(ctx context.Context, args ...any) {
	log.WithField("tag", l.tag).Info(args...)
}
func (l *shadowTLSLogger) WarnContext(ctx context.Context, args ...any) {
	log.WithField("tag", l.tag).Warn(args...)
}
func (l *shadowTLSLogger) ErrorContext(ctx context.Context, args ...any) {
	log.WithField("tag", l.tag).Error(args...)
}
func (l *shadowTLSLogger) FatalContext(ctx context.Context, args ...any) {
	log.WithField("tag", l.tag).Fatal(args...)
}
func (l *shadowTLSLogger) PanicContext(ctx context.Context, args ...any) {
	log.WithField("tag", l.tag).Panic(args...)
}

var _ logger.ContextLogger = (*shadowTLSLogger)(nil)

const idleTimeout = 5 * time.Minute

// What changed: Rejected version values outside [2, 3] by returning an error instead of silently mutating invalid versions to 3.
// Why: Silently mutating the version creates a protocol mismatch between server and client when version 1 is supplied.
func NewShadowTLSCore(tag string, port int, version int, handshakeServer string, strictMode bool, shadowsocksPort int) (*ShadowTLSCore, error) {
	if version < 2 || version > 3 {
		return nil, fmt.Errorf("ShadowTLS: version must be 2 or 3, got %d", version)
	}

	core := &ShadowTLSCore{
		Tag:             tag,
		Port:            port,
		Version:         version,
		HandshakeServer: handshakeServer,
		StrictMode:      strictMode,
		ShadowsocksPort: shadowsocksPort,
		users: &ShadowTLSUserMap{
			uuidToID: make(map[string]int),
			idToUUID: make(map[int]string),
		},
		traffic: make(map[int]*UserTraffic),
	}

	return core, nil
}

// Start starts the ShadowTLS server
func (s *ShadowTLSCore) Start() error {
	s.running.Store(true)

	// Build users list for sing-shadowtls
	users := s.buildUserList()

	// Parse handshake server address
	handshakeAddr := M.ParseSocksaddr(s.HandshakeServer)
	if !handshakeAddr.IsValid() {
		return fmt.Errorf("failed to parse handshake server: %s", s.HandshakeServer)
	}

	if len(users) == 0 {
		log.WithFields(log.Fields{
			"tag":       s.Tag,
			"port":      s.Port,
			"version":   s.Version,
			"handshake": s.HandshakeServer,
		}).Warn("ShadowTLS started with no users; service deferred until first user sync")
		s.servicePending.Store(true)
		return nil
	}

	// Create handshake config
	handshakeConfig := shadowtls.HandshakeConfig{
		Server: handshakeAddr,
		Dialer: N.SystemDialer,
	}

	// Create sing-shadowtls service
	service, err := shadowtls.NewService(shadowtls.ServiceConfig{
		Version:    s.Version,
		Users:      users,
		Handshake:  handshakeConfig,
		StrictMode: s.StrictMode,
		Handler:    s,
		Logger:     &shadowTLSLogger{tag: s.Tag},
	})
	if err != nil {
		return fmt.Errorf("failed to create shadowtls service: %w", err)
	}
	s.service = service

	// Start listener
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", s.Port))
	if err != nil {
		return fmt.Errorf("failed to listen on port %d: %w", s.Port, err)
	}
	s.listener = listener

	log.WithFields(log.Fields{
		"tag":       s.Tag,
		"port":      s.Port,
		"version":   s.Version,
		"handshake": s.HandshakeServer,
	}).Info("ShadowTLS server started")

	go s.acceptLoop()
	return nil
}

// Stop stops the ShadowTLS server
func (s *ShadowTLSCore) Stop() error {
	s.running.Store(false)
	s.servicePending.Store(false)
	if s.listener != nil {
		s.listener.Close()
		s.listener = nil
	}
	s.service = nil

	s.wg.Wait()
	log.WithField("tag", s.Tag).Info("ShadowTLS server stopped")
	return nil
}

// acceptLoop accepts incoming connections
func (s *ShadowTLSCore) acceptLoop() {
	for s.running.Load() {
		listener := s.listener
		if listener == nil {
			break
		}
		conn, err := listener.Accept()
		if err != nil {
			if s.running.Load() {
				log.WithError(err).Error("ShadowTLS accept error")
			}
			continue
		}

		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			svc := s.service
			if svc == nil {
				conn.Close()
				return
			}
			ctx := context.Background()
			source := M.SocksaddrFromNet(conn.RemoteAddr())

			err := svc.NewConnection(ctx, conn, source, M.Socksaddr{}, func(it error) {
				conn.Close()
			})
			if err != nil {
				log.WithError(err).Debug("ShadowTLS connection error")
			}
		}()
	}
}

// NewConnectionEx implements N.TCPConnectionHandlerEx
// This is called after ShadowTLS authentication succeeds
func (s *ShadowTLSCore) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	defer func() {
		if onClose != nil {
			onClose(nil)
		}
	}()

	// Get authenticated user from context
	userName, _ := auth.UserFromContext[string](ctx)
	ip := source.AddrString()

	s.users.mu.RLock()
	uid, exists := s.users.uuidToID[userName]
	s.users.mu.RUnlock()

	if !exists {
		log.WithFields(log.Fields{
			"user": userName,
			"ip":   ip,
		}).Warn("ShadowTLS: authenticated user not found in user map")
		conn.Close()
		return
	}

	// Check device limit
	if s.limiterRef != nil {
		tagUUID := format.UserTag(s.Tag, userName)
		_, reject := s.limiterRef.CheckLimit(tagUUID, ip, true)
		if reject {
			log.WithFields(log.Fields{
				"uid": uid,
				"ip":  ip,
			}).Warn("ShadowTLS: device limit exceeded")
			conn.Close()
			return
		}
	}

	log.WithFields(log.Fields{
		"uid": uid,
		"ip":  ip,
	}).Debug("ShadowTLS connection authenticated")

	// Handle the proxy request - read destination from SOCKS5-like header
	// The client sends: [ATYP(1)][ADDR(variable)][PORT(2)]
	s.handleProxyRequest(conn, uid, ip)
}

// What changed: Added doc comment on local Shadowsocks requirement, and added closeBoth helper using sync.Once to close both conns when either direction ends.
// Why: Ensures a matching Shadowsocks server setup is documented and dead connection ends clean up both sides immediately.
// handleProxyRequest forwards the connection to local Shadowsocks.
// Note: A matching local Shadowsocks inbound (configured with the same cipher/password
// that the client uses, and bound to 127.0.0.1:<ShadowsocksPort>) MUST be provisioned
// separately, or ShadowTLS will forward to nothing and connections will fail.
func (s *ShadowTLSCore) handleProxyRequest(conn net.Conn, uid int, clientIP string) {
	// Connect to local Shadowsocks server
	ssAddr := fmt.Sprintf("127.0.0.1:%d", s.ShadowsocksPort)
	ssConn, err := net.DialTimeout("tcp", ssAddr, 10*time.Second)
	if err != nil {
		log.WithError(err).WithField("dest", ssAddr).Error("ShadowTLS: failed to connect to local Shadowsocks")
		conn.Close()
		return
	}

	var closeOnce sync.Once
	closeBoth := func() {
		closeOnce.Do(func() {
			conn.Close()
			ssConn.Close()
		})
	}
	defer closeBoth()

	log.WithFields(log.Fields{
		"uid":    uid,
		"ssPort": s.ShadowsocksPort,
	}).Debug("ShadowTLS: forwarding to local Shadowsocks")

	// Bidirectional copy with traffic accounting
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		defer closeBoth()
		s.copyWithAccounting(ssConn, conn, uid, false) // upload (client -> shadowsocks)
	}()

	go func() {
		defer wg.Done()
		defer closeBoth()
		s.copyWithAccounting(conn, ssConn, uid, true) // download (shadowsocks -> client)
	}()

	wg.Wait()
}

// What changed: Changed parameters to net.Conn, added setReadDeadline with idleTimeout (5 minutes) before each Read call.
// Why: Prevents dead connection leaks by timing out inactive reads and returning to trigger connection cleanup.
// copyWithAccounting copies data between connections, enforces idleTimeout, and tracks traffic
func (s *ShadowTLSCore) copyWithAccounting(dst net.Conn, src net.Conn, uid int, isDownload bool) {
	buf := make([]byte, 32*1024)
	for {
		_ = src.SetReadDeadline(time.Now().Add(idleTimeout))
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
func (s *ShadowTLSCore) addTraffic(uid int, bytes int64, isDownload bool) {
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

// buildUserList builds the user list for sing-shadowtls
func (s *ShadowTLSCore) buildUserList() []shadowtls.User {
	s.users.mu.RLock()
	defer s.users.mu.RUnlock()

	var users []shadowtls.User
	for uuid := range s.users.uuidToID {
		users = append(users, shadowtls.User{
			Name:     uuid,
			Password: uuid, // Use UUID as password
		})
	}
	return users
}

// AddUsers adds users to the ShadowTLS server
func (s *ShadowTLSCore) AddUsers(userInfos []panel.UserInfo) {
	s.users.mu.Lock()
	for _, user := range userInfos {
		s.users.uuidToID[user.Uuid] = user.Id
		s.users.idToUUID[user.Id] = user.Uuid
	}
	s.users.mu.Unlock()

	// Rebuild or initialize service with new users (sing-shadowtls doesn't support dynamic user updates)
	if s.running.Load() {
		users := s.buildUserList()
		if len(users) > 0 {
			handshakeAddr := M.ParseSocksaddr(s.HandshakeServer)
			if !handshakeAddr.IsValid() {
				log.Error("Failed to parse handshake server for user update")
				return
			}

			newService, err := shadowtls.NewService(shadowtls.ServiceConfig{
				Version: s.Version,
				Users:   users,
				Handshake: shadowtls.HandshakeConfig{
					Server: handshakeAddr,
					Dialer: N.SystemDialer,
				},
				StrictMode: s.StrictMode,
				Handler:    s,
				Logger:     &shadowTLSLogger{tag: s.Tag},
			})
			if err != nil {
				log.WithError(err).Error("Failed to recreate shadowtls service")
				return
			}
			s.service = newService

			if s.servicePending.Load() || s.listener == nil {
				listener, err := net.Listen("tcp", fmt.Sprintf(":%d", s.Port))
				if err != nil {
					log.WithError(err).Errorf("ShadowTLS: failed to bind listener on port %d after user sync", s.Port)
					return
				}
				s.listener = listener
				s.servicePending.Store(false)
				log.WithFields(log.Fields{
					"tag":  s.Tag,
					"port": s.Port,
				}).Info("ShadowTLS service and listener started after initial user sync")
				go s.acceptLoop()
			}
		}
	}

	log.WithFields(log.Fields{
		"tag":   s.Tag,
		"count": len(userInfos),
	}).Debug("ShadowTLS users added")
}

// DelUsers removes users from the ShadowTLS server
func (s *ShadowTLSCore) DelUsers(userInfos []panel.UserInfo) {
	s.users.mu.Lock()
	for _, user := range userInfos {
		delete(s.users.uuidToID, user.Uuid)
		delete(s.users.idToUUID, user.Id)
	}
	s.users.mu.Unlock()

	// Rebuild service or enter pending state if zero users
	if s.running.Load() {
		users := s.buildUserList()
		if len(users) == 0 {
			s.servicePending.Store(true)
			s.service = nil
			if s.listener != nil {
				s.listener.Close()
				s.listener = nil
			}
			log.WithField("tag", s.Tag).Warn("ShadowTLS user count reached 0; stopping listener and returning to pending state")
		} else if s.service != nil {
			handshakeAddr := M.ParseSocksaddr(s.HandshakeServer)
			newService, err := shadowtls.NewService(shadowtls.ServiceConfig{
				Version: s.Version,
				Users:   users,
				Handshake: shadowtls.HandshakeConfig{
					Server: handshakeAddr,
					Dialer: N.SystemDialer,
				},
				StrictMode: s.StrictMode,
				Handler:    s,
				Logger:     &shadowTLSLogger{tag: s.Tag},
			})
			if err == nil {
				s.service = newService
			}
		}
	}

	log.WithFields(log.Fields{
		"tag":   s.Tag,
		"count": len(userInfos),
	}).Debug("ShadowTLS users removed")
}

// GetTrafficAndReset returns traffic statistics and resets counters
func (s *ShadowTLSCore) GetTrafficAndReset() map[int]*UserTraffic {
	s.trafficMu.Lock()
	defer s.trafficMu.Unlock()

	result := s.traffic
	s.traffic = make(map[int]*UserTraffic)
	return result
}

// GetOnlineUsers returns currently connected users
func (s *ShadowTLSCore) GetOnlineUsers() []panel.OnlineUser {
	// ShadowTLS connections are short-lived per request,
	// so we don't track persistent sessions like SSH
	return nil
}

// SetLimiter sets the limiter reference for IP/device limiting
func (s *ShadowTLSCore) SetLimiter(l *limiter.Limiter) {
	s.limiterRef = l
}

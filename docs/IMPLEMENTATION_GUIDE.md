# Multi-Protocol Implementation Guide

## Quick Start: Adding SSH Tunnel Support

This guide walks through implementing SSH tunneling as the first additional protocol. SSH is chosen first because:
- Pure Go implementation (no external dependencies)
- Built-in authentication and encryption
- Easy to test with standard SSH clients
- Great for validating the protocol interface design

After SSH, we'll add WireGuard as the second protocol.

## Step 1: Define the Protocol Interface

Create `core/protocol.go`:

```go
package core

import "github.com/archnets/node/api/panel"

type ProtocolCore interface {
    // Start initializes and starts the protocol core
    Start(config interface{}) error
    
    // Close stops the protocol core and cleans up resources
    Close() error
    
    // AddNode adds a new node/inbound configuration
    AddNode(tag string, info *panel.NodeInfo) error
    
    // DelNode removes a node/inbound configuration
    DelNode(tag string) error
    
    // AddUsers adds users to the specified node
    AddUsers(params *AddUsersParams) (int, error)
    
    // RemoveUsers removes users from the specified node
    RemoveUsers(tag string, users []panel.UserInfo) (int, error)
    
    // GetUserTraffic retrieves traffic statistics for users
    GetUserTraffic(tag string, reset bool) ([]UserTraffic, error)
    
    // GetProtocolType returns the protocol type identifier
    GetProtocolType() string
}

type UserTraffic struct {
    UID      int
    Upload   int64
    Download int64
}
```

## Step 2: Refactor XrayCore

Update `core/xray.go` to implement the interface explicitly:

```go
// Ensure XrayCore implements ProtocolCore
var _ ProtocolCore = (*XrayCore)(nil)

func (v *XrayCore) GetProtocolType() string {
    return "xray"
}

// Rename existing Start method if needed to match interface
// Update GetUserTraffic signature to match interface
```

## Step 3: Create Core Factory

Create `core/factory.go`:

```go
package core

import (
    "fmt"
    "github.com/archnets/node/conf"
    "github.com/archnets/node/api/panel"
)

func NewProtocolCore(protocolType string, config *conf.Conf, client *panel.ClientV2) (ProtocolCore, error) {
    switch protocolType {
    case "xray", "vless", "vmess", "trojan", "shadowsocks", "hysteria2":
        return New(config, client), nil
    case "ssh", "ssh-tunnel":
        return NewSSHTunnelCore(config, client)
    case "wireguard", "wg":
        return NewWireGuardCore(config, client)
    default:
        return nil, fmt.Errorf("unsupported protocol type: %s", protocolType)
    }
}
```

## Step 4: Implement SSH Tunnel Core

Create `core/ssh.go`:

```go
package core

import (
    "context"
    "fmt"
    "io"
    "net"
    "sync"
    "sync/atomic"
    "time"
    
    "github.com/archnets/node/api/panel"
    "github.com/archnets/node/conf"
    "github.com/armon/go-socks5"
    "github.com/juju/ratelimit"
    log "github.com/sirupsen/logrus"
    "golang.org/x/crypto/ssh"
)

type SSHTunnelCore struct {
    Config       *conf.Conf
    Client       *panel.ClientV2
    listener     net.Listener
    sshConfig    *ssh.ServerConfig
    hostKey      ssh.Signer
    listenAddr   string
    listenPort   int
    users        map[string]*SSHUser
    userLock     sync.RWMutex
    sessions     map[string]*SSHSession
    sessionLock  sync.RWMutex
    tag          string
    limiter      interface{} // Will be set by controller
    ctx          context.Context
    cancel       context.CancelFunc
}

type SSHUser struct {
    UID      int
    UUID     string
    Username string
    Password string
}

type SSHSession struct {
    SessionID  string
    UID        int
    UUID       string
    RemoteAddr string
    BytesIn    int64
    BytesOut   int64
    StartTime  time.Time
    conn       *CountedConn
}

type CountedConn struct {
    net.Conn
    bytesRead    int64
    bytesWritten int64
}

func (c *CountedConn) Read(b []byte) (n int, err error) {
    n, err = c.Conn.Read(b)
    atomic.AddInt64(&c.bytesRead, int64(n))
    return
}

func (c *CountedConn) Write(b []byte) (n int, err error) {
    n, err = c.Conn.Write(b)
    atomic.AddInt64(&c.bytesWritten, int64(n))
    return
}

func NewSSHTunnelCore(config *conf.Conf, client *panel.ClientV2) (*SSHTunnelCore, error) {
    // Generate host key
    hostKey, err := generateHostKey()
    if err != nil {
        return nil, fmt.Errorf("failed to generate host key: %w", err)
    }
    
    ctx, cancel := context.WithCancel(context.Background())
    
    core := &SSHTunnelCore{
        Config:     config,
        Client:     client,
        hostKey:    hostKey,
        listenAddr: "0.0.0.0",
        listenPort: 2222,
        users:      make(map[string]*SSHUser),
        sessions:   make(map[string]*SSHSession),
        ctx:        ctx,
        cancel:     cancel,
    }
    
    // Setup SSH server config
    core.sshConfig = &ssh.ServerConfig{
        PasswordCallback: core.passwordCallback,
        PublicKeyCallback: core.publicKeyCallback,
    }
    core.sshConfig.AddHostKey(hostKey)
    
    return core, nil
}

func generateHostKey() (ssh.Signer, error) {
    // In production, load from file or generate and save
    // For now, generate ephemeral key
    privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
    if err != nil {
        return nil, err
    }
    return ssh.NewSignerFromKey(privateKey)
}

func (s *SSHTunnelCore) Start(config interface{}) error {
    addr := fmt.Sprintf("%s:%d", s.listenAddr, s.listenPort)
    listener, err := net.Listen("tcp", addr)
    if err != nil {
        return fmt.Errorf("failed to listen on %s: %w", addr, err)
    }
    
    s.listener = listener
    log.WithField("addr", addr).Info("SSH tunnel server started")
    
    // Accept connections
    go s.acceptConnections()
    
    return nil
}

func (s *SSHTunnelCore) acceptConnections() {
    for {
        conn, err := s.listener.Accept()
        if err != nil {
            select {
            case <-s.ctx.Done():
                return
            default:
                log.WithError(err).Error("Failed to accept connection")
                continue
            }
        }
        
        go s.handleConnection(conn)
    }
}

func (s *SSHTunnelCore) handleConnection(nConn net.Conn) {
    defer nConn.Close()
    
    // Wrap connection for traffic counting
    countedConn := &CountedConn{Conn: nConn}
    
    // SSH handshake
    sshConn, chans, reqs, err := ssh.NewServerConn(countedConn, s.sshConfig)
    if err != nil {
        log.WithError(err).Debug("SSH handshake failed")
        return
    }
    defer sshConn.Close()
    
    // Get user from permissions
    perms := sshConn.Permissions
    if perms == nil || perms.Extensions == nil {
        return
    }
    
    uuid := perms.Extensions["uuid"]
    uid := perms.Extensions["uid"]
    
    // Create session
    sessionID := fmt.Sprintf("%s-%d", uuid, time.Now().Unix())
    session := &SSHSession{
        SessionID:  sessionID,
        UUID:       uuid,
        RemoteAddr: sshConn.RemoteAddr().String(),
        StartTime:  time.Now(),
        conn:       countedConn,
    }
    fmt.Sscanf(uid, "%d", &session.UID)
    
    s.sessionLock.Lock()
    s.sessions[sessionID] = session
    s.sessionLock.Unlock()
    
    defer func() {
        s.sessionLock.Lock()
        delete(s.sessions, sessionID)
        s.sessionLock.Unlock()
    }()
    
    log.WithFields(log.Fields{
        "user": sshConn.User(),
        "addr": sshConn.RemoteAddr(),
    }).Info("SSH connection established")
    
    // Handle channels and requests
    go ssh.DiscardRequests(reqs)
    s.handleChannels(chans, session)
}

func (s *SSHTunnelCore) handleChannels(chans <-chan ssh.NewChannel, session *SSHSession) {
    for newChannel := range chans {
        go s.handleChannel(newChannel, session)
    }
}

func (s *SSHTunnelCore) handleChannel(newChannel ssh.NewChannel, session *SSHSession) {
    // Only accept "direct-tcpip" for port forwarding
    if t := newChannel.ChannelType(); t != "direct-tcpip" && t != "session" {
        newChannel.Reject(ssh.UnknownChannelType, fmt.Sprintf("unknown channel type: %s", t))
        return
    }
    
    channel, requests, err := newChannel.Accept()
    if err != nil {
        log.WithError(err).Error("Failed to accept channel")
        return
    }
    defer channel.Close()
    
    // Handle different channel types
    switch newChannel.ChannelType() {
    case "session":
        // SOCKS5 proxy mode
        s.handleSOCKS5(channel, session)
    case "direct-tcpip":
        // Direct port forwarding
        s.handleDirectTCPIP(channel, requests, session)
    }
}

func (s *SSHTunnelCore) handleSOCKS5(channel ssh.Channel, session *SSHSession) {
    // Create SOCKS5 server
    conf := &socks5.Config{
        Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
            return net.Dial(network, addr)
        },
    }
    
    server, err := socks5.New(conf)
    if err != nil {
        log.WithError(err).Error("Failed to create SOCKS5 server")
        return
    }
    
    // Serve SOCKS5 over SSH channel
    if err := server.ServeConn(channel); err != nil {
        log.WithError(err).Debug("SOCKS5 connection closed")
    }
}

func (s *SSHTunnelCore) handleDirectTCPIP(channel ssh.Channel, requests <-chan *ssh.Request, session *SSHSession) {
    // Parse destination from channel data
    // This is simplified - real implementation needs proper parsing
    go ssh.DiscardRequests(requests)
    
    // For now, just close the channel
    // Full implementation would forward to destination
}

func (s *SSHTunnelCore) passwordCallback(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
    s.userLock.RLock()
    user, exists := s.users[conn.User()]
    s.userLock.RUnlock()
    
    if !exists {
        return nil, fmt.Errorf("user not found")
    }
    
    if user.Password != string(password) {
        return nil, fmt.Errorf("invalid password")
    }
    
    return &ssh.Permissions{
        Extensions: map[string]string{
            "uid":  fmt.Sprintf("%d", user.UID),
            "uuid": user.UUID,
        },
    }, nil
}

func (s *SSHTunnelCore) publicKeyCallback(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
    // TODO: Implement public key authentication
    return nil, fmt.Errorf("public key auth not implemented")
}

func (s *SSHTunnelCore) Close() error {
    s.cancel()
    
    if s.listener != nil {
        s.listener.Close()
    }
    
    s.sessionLock.Lock()
    s.sessions = nil
    s.sessionLock.Unlock()
    
    return nil
}

func (s *SSHTunnelCore) AddNode(tag string, info *panel.NodeInfo) error {
    s.tag = tag
    log.WithField("tag", tag).Info("Adding SSH tunnel node")
    return nil
}

func (s *SSHTunnelCore) DelNode(tag string) error {
    log.WithField("tag", tag).Info("Removing SSH tunnel node")
    return nil
}

func (s *SSHTunnelCore) AddUsers(params *AddUsersParams) (int, error) {
    s.userLock.Lock()
    defer s.userLock.Unlock()
    
    added := 0
    for _, user := range params.Users {
        // Use UUID as username, generate password from UUID
        // In production, get password from panel
        sshUser := &SSHUser{
            UID:      user.Id,
            UUID:     user.Uuid,
            Username: user.Uuid,
            Password: user.Uuid, // Simplified - should be secure password
        }
        
        s.users[user.Uuid] = sshUser
        added++
    }
    
    log.WithField("count", added).Info("Added SSH users")
    return added, nil
}

func (s *SSHTunnelCore) RemoveUsers(tag string, users []panel.UserInfo) (int, error) {
    s.userLock.Lock()
    defer s.userLock.Unlock()
    
    removed := 0
    for _, user := range users {
        if _, exists := s.users[user.Uuid]; exists {
            delete(s.users, user.Uuid)
            removed++
        }
    }
    
    return removed, nil
}

func (s *SSHTunnelCore) GetUserTraffic(tag string, reset bool) ([]UserTraffic, error) {
    s.sessionLock.RLock()
    defer s.sessionLock.RUnlock()
    
    trafficMap := make(map[int]*UserTraffic)
    
    for _, session := range s.sessions {
        if traffic, exists := trafficMap[session.UID]; exists {
            traffic.Upload += atomic.LoadInt64(&session.conn.bytesWritten)
            traffic.Download += atomic.LoadInt64(&session.conn.bytesRead)
        } else {
            trafficMap[session.UID] = &UserTraffic{
                UID:      session.UID,
                Upload:   atomic.LoadInt64(&session.conn.bytesWritten),
                Download: atomic.LoadInt64(&session.conn.bytesRead),
            }
        }
    }
    
    var traffic []UserTraffic
    for _, t := range trafficMap {
        traffic = append(traffic, *t)
    }
    
    return traffic, nil
}

func (s *SSHTunnelCore) GetProtocolType() string {
    return "ssh"
}
```

## Step 5: Add Missing Import

Add to the imports in `core/ssh.go`:

```go
import (
    "crypto/rand"
    "crypto/rsa"
    // ... other imports
)
```

## Step 6: Update Controller

Modify `node/controller.go`:

```go
type Controller struct {
    core                    core.ProtocolCore  // Changed from *vCore.XrayCore
    apiClient               *panel.ClientV1
    tag                     string
    limiter                 *limiter.Limiter
    userList                []panel.UserInfo
    aliveMap                map[int]int
    info                    *panel.NodeInfo
    userListMonitorPeriodic *task.Task
    userReportPeriodic      *task.Task
    renewCertPeriodic       *task.Task
    onlineIpReportPeriodic  *task.Task
}

func NewController(protocolCore core.ProtocolCore, api *panel.ClientV1, info *panel.NodeInfo) *Controller {
    controller := &Controller{
        core:      protocolCore,
        apiClient: api,
        info:      info,
    }
    return controller
}
```

## Step 7: Update Node Initialization

Modify `node/node.go`:

```go
func New(config *conf.Conf, serverconfig *panel.ServerConfigResponse) (*Node, error) {
    node := &Node{
        controllers: make([]*Controller, 0),
    }
    
    for _, nodeconfig := range *serverconfig.Data.Protocols {
        if !nodeconfig.Enable {
            continue
        }
        
        // Create protocol-specific core
        protocolCore, err := core.NewProtocolCore(
            nodeconfig.Type,
            config,
            nil, // client will be created per protocol
        )
        if err != nil {
            return nil, fmt.Errorf("failed to create %s core: %w", nodeconfig.Type, err)
        }
        
        n := &panel.NodeInfo{
            Id:                     config.ApiConfig.ServerId,
            Type:                   nodeconfig.Type,
            TrafficReportThreshold: serverconfig.Data.TrafficReportThreshold,
            PushInterval:           pushinterval,
            PullInterval:           pullinterval,
            Protocol:               &nodeconfig,
        }
        
        p, err := panel.NewClientV1(&conf.NodeApiConfig{
            APIHost:   config.ApiConfig.ApiHost,
            NodeType:  nodeconfig.Type,
            NodeID:    config.ApiConfig.ServerId,
            SecretKey: config.ApiConfig.SecretKey,
        })
        if err != nil {
            return nil, err
        }
        
        node.controllers = append(node.controllers, NewController(protocolCore, p, n))
    }
    
    return node, nil
}
```

## Step 8: Add SSH-Specific Limiter Integration

SSH has built-in rate limiting through Go's io package. Create `limiter/ssh_enforcer.go`:

```go
package limiter

import (
    "fmt"
    "os/exec"
    
    log "github.com/sirupsen/logrus"
)

type RateLimitedConn struct {
    net.Conn
    readBucket  *ratelimit.Bucket
    writeBucket *ratelimit.Bucket
}

func NewRateLimitedConn(conn net.Conn, limitBps int64) *RateLimitedConn {
    var readBucket, writeBucket *ratelimit.Bucket
    
    if limitBps > 0 {
        // Create buckets for read and write
        readBucket = ratelimit.NewBucketWithQuantum(time.Second, limitBps, limitBps)
        writeBucket = ratelimit.NewBucketWithQuantum(time.Second, limitBps, limitBps)
    }
    
    return &RateLimitedConn{
        Conn:        conn,
        readBucket:  readBucket,
        writeBucket: writeBucket,
    }
}

func (r *RateLimitedConn) Read(b []byte) (n int, err error) {
    if r.readBucket != nil {
        // Wait for tokens
        r.readBucket.Wait(int64(len(b)))
    }
    return r.Conn.Read(b)
}

func (r *RateLimitedConn) Write(b []byte) (n int, err error) {
    if r.writeBucket != nil {
        // Wait for tokens
        r.writeBucket.Wait(int64(len(b)))
    }
    return r.Conn.Write(b)
}

// Update SSH core to use rate-limited connections
func (s *SSHTunnelCore) handleConnection(nConn net.Conn) {
    defer nConn.Close()
    
    // Check limiter and get speed limit
    // This would be integrated with the actual limiter
    var limitBps int64 = 0 // Get from limiter
    
    // Wrap with rate limiter
    rateLimitedConn := NewRateLimitedConn(nConn, limitBps)
    
    // Wrap for traffic counting
    countedConn := &CountedConn{Conn: rateLimitedConn}
    
    // Continue with SSH handshake...
}
```

## Step 9: Testing

Create `core/ssh_test.go`:

```go
package core

import (
    "testing"
    
    "github.com/archnets/node/api/panel"
    "github.com/archnets/node/conf"
)

func TestSSHTunnelCore(t *testing.T) {
    config := &conf.Conf{}
    
    ssh, err := NewSSHTunnelCore(config, nil)
    if err != nil {
        t.Fatalf("Failed to create SSH tunnel core: %v", err)
    }
    defer ssh.Close()
    
    // Test interface implementation
    var _ ProtocolCore = ssh
    
    // Test protocol type
    if ssh.GetProtocolType() != "ssh" {
        t.Errorf("Expected protocol type 'ssh', got '%s'", ssh.GetProtocolType())
    }
}

func TestSSHAddUsers(t *testing.T) {
    config := &conf.Conf{}
    ssh, _ := NewSSHTunnelCore(config, nil)
    defer ssh.Close()
    
    users := []panel.UserInfo{
        {Id: 1, Uuid: "user1-uuid"},
        {Id: 2, Uuid: "user2-uuid"},
    }
    
    params := &AddUsersParams{
        Tag:   "test-node",
        Users: users,
    }
    
    added, err := ssh.AddUsers(params)
    if err != nil {
        t.Fatalf("Failed to add users: %v", err)
    }
    
    if added != 2 {
        t.Errorf("Expected 2 users added, got %d", added)
    }
}

func TestSSHConnection(t *testing.T) {
    config := &conf.Conf{}
    ssh, _ := NewSSHTunnelCore(config, nil)
    defer ssh.Close()
    
    // Add a test user
    users := []panel.UserInfo{
        {Id: 1, Uuid: "test-user"},
    }
    ssh.AddUsers(&AddUsersParams{Tag: "test", Users: users})
    
    // Start server
    err := ssh.Start(nil)
    if err != nil {
        t.Fatalf("Failed to start SSH server: %v", err)
    }
    
    // Try to connect (would need actual SSH client)
    // This is a placeholder for integration testing
}
```

## Step 10: Dependencies

Add to `go.mod`:

```bash
go get golang.org/x/crypto/ssh
go get github.com/armon/go-socks5
go get github.com/juju/ratelimit
```

## Step 11: System Requirements

Document system requirements in README:

```markdown
### SSH Tunnel Support

To use SSH tunnel protocol:

1. No special system requirements - pure Go implementation

2. Configure firewall:
   ```bash
   sudo ufw allow 2222/tcp
   ```

3. Client usage examples:
   ```bash
   # SOCKS5 proxy
   ssh -D 1080 -N user@server -p 2222
   
   # Port forwarding
   ssh -L 8080:destination:80 user@server -p 2222
   
   # Dynamic forwarding
   ssh -D 0.0.0.0:1080 -N user@server -p 2222
   ```
```

## Next Steps

1. **Test the implementation** with real SSH clients
2. **Add public key authentication** support
3. **Implement proper password management** (get from panel)
4. **Add configuration options** for SSH-specific settings (compression, ciphers)
5. **Move on to WireGuard** following the same pattern
6. **Add direct-tcpip forwarding** for full SSH tunnel support

## Common Issues & Solutions

### Issue: Port already in use

**Solution:** Change the SSH port in configuration or stop conflicting service:
```bash
# Check what's using the port
sudo lsof -i :2222

# Change port in config
listenPort: 2223
```

### Issue: Connection refused

**Solution:** Check firewall and ensure server is listening:
```bash
# Check if server is listening
netstat -tlnp | grep 2222

# Allow through firewall
sudo ufw allow 2222/tcp
```

### Issue: Authentication failed

**Solution:** Verify user credentials are correctly synced from panel:
```bash
# Check logs for auth attempts
journalctl -u archnets-node -f | grep SSH
```

### Issue: SOCKS5 proxy not working

**Solution:** Ensure client is using correct SOCKS5 settings:
```bash
# Test with curl
curl --socks5 localhost:1080 https://ifconfig.me

# Verify SSH tunnel
ssh -D 1080 -N -v user@server -p 2222
```

## Performance Tuning

1. **Increase TCP buffer sizes:**
   ```bash
   sysctl -w net.core.rmem_max=16777216
   sysctl -w net.core.wmem_max=16777216
   sysctl -w net.ipv4.tcp_rmem="4096 87380 16777216"
   sysctl -w net.ipv4.tcp_wmem="4096 65536 16777216"
   ```

2. **Enable TCP BBR congestion control:**
   ```bash
   sysctl -w net.core.default_qdisc=fq
   sysctl -w net.ipv4.tcp_congestion_control=bbr
   ```

3. **Optimize SSH server settings:**
   ```go
   // In SSH config
   config.MaxAuthTries = 3
   config.ServerVersion = "SSH-2.0-ArchNets"
   
   // Enable compression for better performance
   config.Compression = ssh.CompressionDelayed
   ```

4. **Connection pooling:**
   - Reuse SSH connections where possible
   - Implement connection keep-alive
   - Set appropriate timeouts

5. **Concurrent connection limits:**
   ```go
   // Limit concurrent connections per user
   maxConnectionsPerUser := 5
   ```

## Client Configuration Examples

### Linux/macOS

```bash
# Add to ~/.ssh/config
Host archnets-vpn
    HostName your-server.com
    Port 2222
    User your-uuid
    DynamicForward 1080
    ServerAliveInterval 60
    ServerAliveCountMax 3
    Compression yes
```

### Windows (PuTTY)

1. Session → Host Name: your-server.com
2. Session → Port: 2222
3. Connection → SSH → Tunnels → Source port: 1080
4. Connection → SSH → Tunnels → Select "Dynamic"
5. Connection → SSH → Tunnels → Click "Add"

### Android (Termux)

```bash
pkg install openssh
ssh -D 1080 -N your-uuid@your-server.com -p 2222
```

### iOS (Termius)

1. Add new host
2. Set hostname and port
3. Configure SOCKS5 proxy in Port Forwarding
4. Enable "Dynamic Port Forwarding"

This guide provides a complete foundation for adding SSH tunnel support. The same pattern can be applied to WireGuard, OpenVPN, and IPSec implementations.

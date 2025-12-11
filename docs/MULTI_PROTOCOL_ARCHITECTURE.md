# Multi-Protocol Architecture Design

## Overview

This document outlines the architecture for extending the ArchNets Node to support multiple VPN protocols beyond Xray-core, including OpenVPN, WireGuard, L2TP/IPSec, and IKEv2.

## Current Architecture Analysis

### Existing Components

1. **XrayCore** (`core/xray.go`)
   - Manages Xray-core instance lifecycle
   - Handles inbound/outbound configuration
   - Manages users and traffic statistics
   - Protocol-specific implementation

2. **Controller** (`node/controller.go`)
   - Orchestrates protocol lifecycle
   - Manages user synchronization with panel
   - Handles periodic tasks (user updates, traffic reporting)
   - Works with limiter for traffic control

3. **Limiter** (`limiter/limiter.go`)
   - Protocol-agnostic traffic limiting
   - Device limit enforcement
   - Speed limit enforcement per user
   - Uses tag-based user identification

4. **Panel API** (`api/panel/`)
   - Communication with backend
   - User list retrieval
   - Traffic reporting
   - Configuration updates

### Key Insight

The limiter and panel API are already protocol-agnostic. The main work is abstracting the core protocol handling.

## Proposed Architecture

### 1. Core Protocol Interface

Create a common interface that all protocol implementations must satisfy:

```go
// core/protocol.go
package core

type ProtocolCore interface {
    // Lifecycle management
    Start(config interface{}) error
    Close() error
    
    // Node management
    AddNode(tag string, info *panel.NodeInfo) error
    DelNode(tag string) error
    
    // User management
    AddUsers(params *AddUsersParams) (int, error)
    RemoveUsers(tag string, users []panel.UserInfo) (int, error)
    
    // Traffic statistics
    GetUserTraffic(tag string, reset bool) ([]UserTraffic, error)
    
    // Protocol-specific info
    GetProtocolType() string
}

type UserTraffic struct {
    UID      int
    Upload   int64
    Download int64
}
```

### 2. Protocol-Specific Implementations

#### 2.1 OpenVPN Core (`core/openvpn.go`)

**Implementation Strategy:**
- Use OpenVPN management interface for control
- Leverage client-connect/client-disconnect scripts for user tracking
- Use status file for traffic statistics

**Key Components:**
```go
type OpenVPNCore struct {
    Config          *conf.Conf
    Client          *panel.ClientV2
    managementConn  net.Conn
    processCmd      *exec.Cmd
    users           map[string]*OpenVPNUser
    statsCollector  *OpenVPNStatsCollector
}
```

**Traffic Limiting Integration:**
- Use `tc` (traffic control) with HTB qdisc for speed limiting
- Hook into client-connect script to call limiter.CheckLimit()
- Reject connections in client-connect if device limit exceeded
- Apply per-user bandwidth shaping via tc filters

**Configuration Generation:**
- Generate server.conf dynamically based on NodeInfo
- Create per-user certificates or use username/password auth
- Configure management interface on localhost socket

**Traffic Collection:**
```bash
# OpenVPN status file format parsing
# Common Name,Real Address,Bytes Received,Bytes Sent,Connected Since
user1,192.168.1.100:12345,1048576,2097152,2024-01-01 10:00:00
```

**Limiter Integration Points:**
1. `client-connect` script → Check device limit and speed limit
2. Periodic status file parsing → Collect traffic stats
3. `tc` rules → Enforce speed limits at kernel level

#### 2.2 WireGuard Core (`core/wireguard.go`)

**Implementation Strategy:**
- Use `wgctrl` Go library for WireGuard management
- eBPF or iptables for per-user traffic accounting and limiting
- Netlink for interface management

**Key Components:**
```go
type WireGuardCore struct {
    Config         *conf.Conf
    Client         *panel.ClientV2
    wgClient       *wgctrl.Client
    interfaceName  string
    privateKey     wgtypes.Key
    listenPort     int
    peers          map[string]*WireGuardPeer
    trafficMonitor *WGTrafficMonitor
}

type WireGuardPeer struct {
    PublicKey    wgtypes.Key
    AllowedIPs   []net.IPNet
    UID          int
    UUID         string
}
```

**Traffic Limiting Integration:**
- **Option A: eBPF** (Recommended for performance)
  - Write eBPF program to track per-peer traffic
  - Implement rate limiting in eBPF TC hook
  - Use cilium/ebpf Go library
  
- **Option B: iptables/nftables**
  - Create per-user chains with accounting
  - Use hashlimit module for rate limiting
  - Parse iptables counters for traffic stats

**Configuration:**
```ini
[Interface]
PrivateKey = <server_private_key>
Address = 10.0.0.1/24
ListenPort = 51820

[Peer]
PublicKey = <user_public_key>
AllowedIPs = 10.0.0.2/32
```

**Limiter Integration Points:**
1. Peer addition → Check device limit via limiter
2. eBPF/iptables hooks → Enforce speed limits
3. WireGuard handshake tracking → Detect active connections
4. Periodic peer stats query → Collect traffic data

**Traffic Collection:**
```go
// Using wgctrl
device, _ := wgClient.Device(interfaceName)
for _, peer := range device.Peers {
    upload := peer.TransmitBytes
    download := peer.ReceiveBytes
    // Report to panel
}
```

#### 2.3 SSH Tunnel Core (`core/ssh.go`)

**Implementation Strategy:**
- Use SSH server (OpenSSH or custom Go SSH server)
- SOCKS5 proxy or port forwarding for tunneling
- SSH subsystem for traffic routing
- Custom authentication backend

**Key Components:**
```go
type SSHTunnelCore struct {
    Config         *conf.Conf
    Client         *panel.ClientV2
    sshServer      *ssh.Server
    listenAddr     string
    listenPort     int
    hostKey        ssh.Signer
    users          map[string]*SSHUser
    sessions       map[string]*SSHSession
    trafficMonitor *SSHTrafficMonitor
}

type SSHUser struct {
    UID          int
    UUID         string
    Username     string
    Password     string // or public key
    AllowedIPs   []string
}

type SSHSession struct {
    SessionID    string
    UID          int
    RemoteAddr   string
    BytesIn      int64
    BytesOut     int64
    StartTime    time.Time
}
```

**Traffic Limiting Integration:**
- Wrap SSH connection with rate-limited reader/writer
- Use Go's `io.Pipe` with rate limiting middleware
- Track per-session traffic in real-time
- Reject new sessions if device limit exceeded

**Configuration:**
```yaml
ssh:
  port: 2222
  host_key: /etc/node/ssh_host_key
  auth_methods:
    - password
    - publickey
  tunnel_modes:
    - socks5
    - port_forward
    - dynamic
```

**Implementation Approaches:**

**Option A: OpenSSH with Custom Auth**
- Use OpenSSH server with `AuthorizedKeysCommand`
- Custom script queries panel for user validation
- Use `ForceCommand` to restrict to tunneling only
- Parse auth logs for connection tracking

**Option B: Go SSH Server (Recommended)**
- Full control over authentication
- Built-in traffic accounting
- Easy integration with limiter
- No external dependencies

```go
// Example Go SSH server integration
func (s *SSHTunnelCore) handleSSHConnection(nConn net.Conn, config *ssh.ServerConfig) {
    conn, chans, reqs, err := ssh.NewServerConn(nConn, config)
    if err != nil {
        return
    }
    defer conn.Close()
    
    // Get user info from auth
    user := s.users[conn.User()]
    
    // Check device limit
    taguuid := format.UserTag(s.tag, user.UUID)
    bucket, reject := s.limiter.CheckLimit(taguuid, conn.RemoteAddr().String(), true, true)
    if reject {
        return
    }
    
    // Handle channels with rate limiting
    go s.handleChannels(chans, user, bucket)
    go ssh.DiscardRequests(reqs)
}
```

**Limiter Integration Points:**
1. Connection establishment → Check device limit
2. Channel creation → Apply speed limit wrapper
3. Periodic stats collection → Report traffic
4. Session close → Update online device list

**Traffic Collection:**
```go
// Wrap net.Conn with traffic counter
type CountedConn struct {
    net.Conn
    bytesRead    int64
    bytesWritten int64
    uid          int
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
```

**SOCKS5 Proxy Integration:**
```go
// Built-in SOCKS5 server for SSH tunnel
func (s *SSHTunnelCore) handleSOCKS5(channel ssh.Channel, user *SSHUser, bucket *ratelimit.Bucket) {
    // Rate-limited SOCKS5 proxy
    proxy := socks5.New(&socks5.Config{
        Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
            conn, err := net.Dial(network, addr)
            if err != nil {
                return nil, err
            }
            // Wrap with rate limiter
            if bucket != nil {
                return &RateLimitedConn{Conn: conn, Bucket: bucket}, nil
            }
            return conn, nil
        },
    })
    proxy.ServeConn(channel)
}
```

**Authentication Methods:**

1. **Password Authentication:**
```go
config.PasswordCallback = func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
    user, err := s.validateUser(conn.User(), string(password))
    if err != nil {
        return nil, err
    }
    return &ssh.Permissions{
        Extensions: map[string]string{
            "uid":  strconv.Itoa(user.UID),
            "uuid": user.UUID,
        },
    }, nil
}
```

2. **Public Key Authentication:**
```go
config.PublicKeyCallback = func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
    user, err := s.validateUserKey(conn.User(), key)
    if err != nil {
        return nil, err
    }
    return &ssh.Permissions{
        Extensions: map[string]string{
            "uid":  strconv.Itoa(user.UID),
            "uuid": user.UUID,
        },
    }, nil
}
```

**Advantages of SSH Tunneling:**
- Works everywhere (SSH is rarely blocked)
- Native client support on all platforms
- Strong encryption (same as SSH)
- Can multiplex multiple connections
- Port forwarding flexibility

**Disadvantages:**
- Higher overhead than WireGuard
- Not designed specifically for VPN use
- Requires SSH client configuration
- Less efficient for high-throughput scenarios

#### 2.4 IPSec Core (L2TP/IPSec + IKEv2) (`core/ipsec.go`)

**Implementation Strategy:**
- Use strongSwan as IPSec daemon
- VICI (Versatile IKE Control Interface) for management
- Custom plugin or VICI events for traffic accounting

**Key Components:**
```go
type IPSecCore struct {
    Config         *conf.Conf
    Client         *panel.ClientV2
    viciClient     *vici.Session
    connections    map[string]*IPSecConnection
    trafficMonitor *IPSecTrafficMonitor
    mode           string // "ikev2" or "l2tp"
}

type IPSecConnection struct {
    Name       string
    UID        int
    UUID       string
    RemoteID   string
    LocalID    string
    AuthMethod string // "eap", "psk", "cert"
}
```

**Traffic Limiting Integration:**
- strongSwan updown scripts for connection events
- iptables marking for per-user traffic shaping
- VICI events for real-time connection tracking

**Configuration (IKEv2):**
```
conn ikev2-vpn
    left=%any
    leftsubnet=0.0.0.0/0
    leftcert=server.pem
    right=%any
    rightdns=8.8.8.8
    rightsourceip=10.0.0.0/24
    auto=add
    eap_identity=%identity
```

**Configuration (L2TP/IPSec):**
- IPSec layer: strongSwan
- L2TP layer: xl2tpd
- PPP layer: pppd with radius or local auth

**Limiter Integration Points:**
1. VICI `child-updown` event → Check device limit
2. updown script → Call limiter on connection/disconnection
3. iptables with tc → Enforce speed limits
4. VICI `list-sas` → Query active connections and traffic

**Traffic Collection:**
```go
// Using VICI
sas, _ := viciClient.ListSas("")
for _, sa := range sas {
    bytesIn := sa.BytesIn
    bytesOut := sa.BytesOut
    // Map to user and report
}
```

### 3. Modified Controller

Update `node/controller.go` to work with any protocol:

```go
type Controller struct {
    core                    ProtocolCore  // Changed from *vCore.XrayCore
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
```

### 4. Core Factory Pattern

Create a factory to instantiate the correct core based on protocol type:

```go
// core/factory.go
package core

func NewProtocolCore(protocolType string, config *conf.Conf, client *panel.ClientV2) (ProtocolCore, error) {
    switch protocolType {
    case "xray", "vless", "vmess", "trojan", "shadowsocks":
        return NewXrayCore(config, client), nil
    case "ssh", "ssh-tunnel":
        return NewSSHTunnelCore(config, client), nil
    case "openvpn":
        return NewOpenVPNCore(config, client), nil
    case "wireguard":
        return NewWireGuardCore(config, client), nil
    case "ikev2":
        return NewIPSecCore(config, client, "ikev2"), nil
    case "l2tp":
        return NewIPSecCore(config, client, "l2tp"), nil
    default:
        return nil, fmt.Errorf("unsupported protocol: %s", protocolType)
    }
}
```

### 5. Limiter Adaptations

The limiter is mostly ready, but needs minor enhancements:

**Add protocol-specific hooks:**
```go
// limiter/hooks.go
package limiter

type TrafficHook interface {
    OnConnectionStart(taguuid, ip string) error
    OnConnectionEnd(taguuid, ip string) error
    OnTrafficUpdate(taguuid string, upload, download int64) error
}

// For protocols that need external enforcement (WireGuard, OpenVPN)
type ExternalEnforcer interface {
    ApplySpeedLimit(taguuid, ip string, limitBps int64) error
    RemoveSpeedLimit(taguuid, ip string) error
    ApplyDeviceLimit(taguuid string, maxDevices int) error
}
```

**Protocol-specific enforcers:**
- `TCEnforcer` - Uses Linux tc for OpenVPN
- `EBPFEnforcer` - Uses eBPF for WireGuard
- `IPTablesEnforcer` - Uses iptables for IPSec

### 6. Panel API Extensions

Update panel communication to support protocol-specific data:

```go
// api/panel/protocol.go
type ProtocolConfig struct {
    Type     string                 `json:"type"`
    Enable   bool                   `json:"enable"`
    Settings map[string]interface{} `json:"settings"`
}

// Protocol-specific settings examples:
// OpenVPN: {"auth_type": "cert", "cipher": "AES-256-GCM"}
// WireGuard: {"mtu": 1420, "persistent_keepalive": 25}
// IKEv2: {"auth_method": "eap-mschapv2", "split_tunnel": true}
```

## Implementation Roadmap

### Phase 1: Core Abstraction (Week 1-2)

1. Define `ProtocolCore` interface
2. Refactor `XrayCore` to implement the interface
3. Update `Controller` to use interface instead of concrete type
4. Create core factory
5. Test with existing Xray functionality

### Phase 2: SSH Tunnel Implementation (Week 3)

**Why SSH first?**
- Easiest to implement in pure Go
- No external dependencies
- Built-in authentication and encryption
- Great for testing the protocol interface

**Tasks:**
1. Implement `SSHTunnelCore` using golang.org/x/crypto/ssh
2. Add password and public key authentication
3. Implement SOCKS5 proxy handler
4. Add rate-limited connection wrappers
5. Integrate with limiter for device/speed limits
6. Test with standard SSH clients

**Dependencies:**
```bash
go get golang.org/x/crypto/ssh
go get github.com/armon/go-socks5
```

### Phase 3: WireGuard Implementation (Week 4-5)

**Why WireGuard second?**
- Modern protocol, growing popularity
- Good learning experience for kernel integration
- Requires external traffic control (good test case)

**Tasks:**
1. Implement `WireGuardCore` struct and interface methods
2. Create WireGuard configuration generator
3. Implement eBPF traffic monitor (or iptables fallback)
4. Integrate with limiter
5. Add user management (peer add/remove)
6. Test traffic reporting and limiting

**Dependencies:**
```bash
go get golang.zx2c4.com/wireguard/wgctrl
go get github.com/cilium/ebpf  # For eBPF option
```

### Phase 4: OpenVPN Implementation (Week 6-7)

**Tasks:**
1. Implement `OpenVPNCore` struct and interface methods
2. Create OpenVPN server configuration generator
3. Implement management interface client
4. Create client-connect/disconnect scripts
5. Implement tc-based traffic shaping
6. Add certificate management
7. Test with various auth methods

**Dependencies:**
- OpenVPN binary (system package)
- PKI management library (optional)

### Phase 5: IPSec Implementation (Week 8-9)

**Tasks:**
1. Implement `IPSecCore` for IKEv2
2. Integrate with strongSwan via VICI
3. Create IPSec configuration generator
4. Implement updown scripts
5. Add L2TP support (xl2tpd integration)
6. Test with multiple clients (iOS, Android, Windows)

**Dependencies:**
```bash
go get github.com/strongswan/govici
```
- strongSwan (system package)
- xl2tpd (for L2TP, system package)

### Phase 6: Testing & Optimization (Week 10-11)

1. Integration testing with all protocols
2. Performance benchmarking
3. Memory and CPU profiling
4. Concurrent connection testing
5. Failover and recovery testing
6. Documentation updates

## Technical Challenges & Solutions

### Challenge 1: Traffic Accounting Accuracy


**Problem:** Different protocols report traffic at different layers (L2, L3, L4)

**Solution:**
- Standardize on IP layer (L3) accounting
- Document overhead percentages for each protocol
- Add configurable traffic multiplier in panel

### Challenge 2: Speed Limiting Granularity

**Problem:** Xray has built-in limiting, others need external tools

**Solution:**
- Abstract limiting behind `ExternalEnforcer` interface
- Use kernel-level tools (tc, eBPF) for consistent enforcement
- Consider moving Xray to external limiting for consistency

### Challenge 3: User Authentication Mapping

**Problem:** Each protocol has different auth mechanisms

**Solution:**
- Create auth adapter layer
- Map panel UUID to protocol-specific identifiers:
  - OpenVPN: Common Name in certificate or username
  - WireGuard: Public key
  - IPSec: EAP identity or certificate DN
- Store mapping in controller

### Challenge 4: Connection State Synchronization

**Problem:** Panel needs real-time connection status

**Solution:**
- Implement event-driven architecture
- Use channels for connection events
- Batch updates to reduce API calls
- Add WebSocket support for real-time updates (future)

### Challenge 5: Certificate Management

**Problem:** Multiple protocols need TLS/certificates

**Solution:**
- Centralize cert management in `node/cert.go`
- Support ACME (Let's Encrypt) for all protocols
- Implement cert rotation without downtime
- Share certificates where possible

## File Structure

```
core/
├── protocol.go          # ProtocolCore interface
├── factory.go           # Core factory
├── xray.go             # Existing Xray implementation
├── ssh.go              # SSH tunnel implementation
├── ssh_socks5.go       # SOCKS5 proxy handler
├── ssh_auth.go         # SSH authentication handlers
├── openvpn.go          # OpenVPN implementation
├── openvpn_config.go   # OpenVPN config generation
├── openvpn_mgmt.go     # Management interface client
├── wireguard.go        # WireGuard implementation
├── wireguard_ebpf.go   # eBPF traffic monitor
├── ipsec.go            # IPSec implementation
├── ipsec_vici.go       # VICI client wrapper
└── traffic.go          # Common traffic types

limiter/
├── limiter.go          # Existing limiter
├── hooks.go            # Protocol hooks interface
├── enforcer.go         # Enforcer interface
├── tc_enforcer.go      # Linux tc implementation
├── ebpf_enforcer.go    # eBPF implementation
└── iptables_enforcer.go # iptables implementation

scripts/
├── openvpn/
│   ├── client-connect.sh
│   └── client-disconnect.sh
└── ipsec/
    └── updown.sh
```

## Configuration Example

```yaml
# config.yml
api:
  host: "https://panel.example.com"
  secret_key: "your-secret"
  server_id: 1

protocols:
  - type: "xray"
    enable: true
    
  - type: "ssh"
    enable: true
    settings:
      port: 2222
      auth_methods: ["password", "publickey"]
      tunnel_mode: "socks5"
      compression: true
    
  - type: "wireguard"
    enable: true
    settings:
      interface: "wg0"
      port: 51820
      mtu: 1420
      
  - type: "openvpn"
    enable: true
    settings:
      port: 1194
      protocol: "udp"
      cipher: "AES-256-GCM"
      auth_type: "certificate"
      
  - type: "ikev2"
    enable: true
    settings:
      auth_method: "eap-mschapv2"
      split_tunnel: false
```

## Testing Strategy

### Unit Tests
- Each core implementation
- Limiter with different protocols
- Configuration generators
- Traffic accounting accuracy

### Integration Tests
- Multi-protocol concurrent operation
- User synchronization across protocols
- Traffic reporting aggregation
- Limiter enforcement

### Load Tests
- 1000+ concurrent connections per protocol
- Traffic limiting under load
- Memory usage over time
- CPU usage profiling

### Client Compatibility Tests
- **SSH:** Native SSH clients (OpenSSH, PuTTY, Termius, ConnectBot)
- **WireGuard:** Official clients (Windows, macOS, Linux, iOS, Android)
- **OpenVPN:** OpenVPN Connect, Tunnelblick, OpenVPN for Android
- **IKEv2:** Native clients (iOS, macOS, Windows, Android)

## Security Considerations

1. **Privilege Separation**
   - Run protocol daemons as non-root where possible
   - Use capabilities instead of full root
   - Separate config generation from daemon control

2. **Input Validation**
   - Validate all panel data before applying
   - Sanitize user-provided data in configs
   - Rate limit API requests

3. **Credential Management**
   - Store private keys securely
   - Rotate certificates regularly
   - Use secure random generation

4. **Network Isolation**
   - Separate management interfaces
   - Firewall rules for each protocol
   - VPN client isolation options

## Performance Optimization

1. **Connection Pooling**
   - Reuse management connections
   - Pool database connections
   - Cache user lists

2. **Batch Operations**
   - Batch user additions/removals
   - Aggregate traffic reports
   - Batch configuration updates

3. **Efficient Traffic Accounting**
   - Use eBPF for WireGuard (zero-copy)
   - Memory-mapped status files for OpenVPN
   - VICI streaming for IPSec

4. **Resource Limits**
   - Set max connections per protocol
   - Limit memory per core instance
   - CPU affinity for performance cores

## Migration Path

For existing deployments:

1. **Backward Compatibility**
   - Keep existing Xray-only mode working
   - Add feature flag for multi-protocol
   - Gradual rollout per node

2. **Data Migration**
   - No database changes needed
   - Panel API already supports protocol types
   - User data remains unchanged

3. **Deployment Strategy**
   - Deploy as opt-in feature first
   - Test on staging nodes
   - Gradual production rollout
   - Rollback plan ready

## Monitoring & Observability

Add metrics for each protocol:

```go
// Prometheus metrics
protocol_connections_total{protocol="wireguard"}
protocol_traffic_bytes{protocol="openvpn",direction="upload"}
protocol_errors_total{protocol="ikev2",type="auth_failed"}
limiter_rejections_total{reason="device_limit"}
```

## Future Enhancements

1. **Additional Protocols**
   - Hysteria2 (already mentioned in README)
   - Shadowsocks standalone
   - SOCKS5 proxy (standalone, not via SSH)
   - HTTP/HTTPS proxy
   - V2Ray (if not covered by Xray)

2. **Advanced Features**
   - Protocol fallback/failover
   - Multi-protocol load balancing
   - Smart protocol selection
   - Protocol obfuscation

3. **Management Improvements**
   - Web UI for node management
   - Real-time connection monitoring
   - Automated troubleshooting
   - Performance analytics

## Conclusion

This architecture provides a clean, extensible way to support multiple VPN protocols while maintaining the existing limiter functionality. The key is the `ProtocolCore` interface that abstracts protocol-specific details while providing a consistent API for the controller.

The implementation can be done incrementally, starting with WireGuard as a proof of concept, then expanding to OpenVPN and IPSec. Each protocol brings its own challenges, but the unified architecture makes them manageable.

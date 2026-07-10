package core

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/archnets/node/api/panel"
	"github.com/archnets/node/common/format"
	"github.com/archnets/node/limiter"
	log "github.com/sirupsen/logrus"
)

// OpenVPNCore manages a single real `openvpn` server process, controlled
// through its management interface for dynamic (no-restart) user add/remove,
// auth decisions, and traffic accounting.
type OpenVPNCore struct {
	Tag           string
	Port          int
	Proto         string // "udp" or "tcp"
	WorkDir       string // per-node directory for config/certs/socket
	CertFile      string // real cert path (from panel CertMode="file"/"acme"), optional
	KeyFile       string // real key path, optional
	TlsCryptKey   string // tls-crypt static key content, optional
	InterfaceName string
	TProxyPort    int

	cmd        *exec.Cmd
	mgmt       *ovpnMgmtClient
	socketPath string

	users      *ovpnUserMap
	sessions   sync.Map // cid -> *ovpnSession
	limiterRef *limiter.Limiter
	running    atomic.Bool

	trafficMu sync.RWMutex
	traffic   map[int]*UserTraffic // key: uid
}

type ovpnUserMap struct {
	mu       sync.RWMutex
	uuidToID map[string]int
	idToUUID map[int]string
}

type ovpnSession struct {
	UID          int
	UUID         string
	IP           string
	CID          string
	LastBytesIn  int64
	LastBytesOut int64
}

// NewOpenVPNCore creates (but does not start) an OpenVPN-backed core.
func NewOpenVPNCore(tag string, port int, proto, workDir, certFile, keyFile, tlsCryptKey string) (*OpenVPNCore, error) {
	if proto != "udp" && proto != "tcp" {
		proto = "udp"
	}
	if err := os.MkdirAll(workDir, 0700); err != nil {
		return nil, fmt.Errorf("create work dir: %w", err)
	}

	return &OpenVPNCore{
		Tag:           tag,
		Port:          port,
		Proto:         proto,
		WorkDir:       workDir,
		CertFile:      certFile,
		KeyFile:       keyFile,
		TlsCryptKey:   tlsCryptKey,
		InterfaceName: fmt.Sprintf("ovpn-%d", port),
		users: &ovpnUserMap{
			uuidToID: make(map[string]int),
			idToUUID: make(map[int]string),
		},
		traffic:    make(map[int]*UserTraffic),
		socketPath: filepath.Join(workDir, "mgmt.sock"),
	}, nil
}

// Start writes the server config, ensures cert/key/tls-crypt material exists,
// launches the real openvpn binary, and connects to its management socket.
func (o *OpenVPNCore) Start() error {
	caFile, serverCertFile, serverKeyFile, err := o.ensureCertMaterial()
	if err != nil {
		return fmt.Errorf("ensure cert material: %w", err)
	}

	taKeyPath := filepath.Join(o.WorkDir, "ta.key")
	if o.TlsCryptKey == "" {
		return fmt.Errorf("missing tls-crypt key")
	}
	if err := os.WriteFile(taKeyPath, []byte(o.TlsCryptKey), 0600); err != nil {
		return fmt.Errorf("write tls-crypt key: %w", err)
	}

	confPath := filepath.Join(o.WorkDir, "server.conf")
	if err := o.writeServerConf(confPath, caFile, serverCertFile, serverKeyFile, taKeyPath); err != nil {
		return fmt.Errorf("write server.conf: %w", err)
	}

	_ = os.Remove(o.socketPath) // stale socket from a previous run

	o.cmd = exec.Command("openvpn", "--config", confPath)
	o.cmd.Stdout = log.StandardLogger().WriterLevel(log.DebugLevel)
	o.cmd.Stderr = log.StandardLogger().WriterLevel(log.WarnLevel)

	if err := o.cmd.Start(); err != nil {
		return fmt.Errorf("start openvpn process: %w", err)
	}

	// Setup NAT/TProxy rules
	if err := o.setupNAT(); err != nil {
		log.WithError(err).Warn("openvpn: failed to setup NAT")
	}

	// Wait for the management socket to appear.
	mgmt, err := waitForManagementSocket(o.socketPath, 5*time.Second)
	if err != nil {
		// Check if OpenVPN exited early (config error, missing file, etc.)
		if waitErr := o.cmd.Wait(); waitErr != nil {
			log.WithFields(log.Fields{"tag": o.Tag, "exit_error": waitErr}).Error("openvpn process exited prematurely")
		} else {
			_ = o.cmd.Process.Kill()
		}
		return fmt.Errorf("connect to management socket: %w", err)
	}
	o.mgmt = mgmt

	if err := o.mgmt.enableStateNotify(); err != nil {
		log.WithError(err).Warn("openvpn: failed to enable state notifications")
	}
	if err := o.mgmt.enableByteCount(10); err != nil {
		log.WithError(err).Warn("openvpn: failed to enable bytecount reporting")
	}

	o.running.Store(true)
	go o.eventLoop()

	log.WithFields(log.Fields{
		"tag":   o.Tag,
		"port":  o.Port,
		"proto": o.Proto,
	}).Info("OpenVPN server started")

	return nil
}

// Stop terminates the openvpn process and closes the management connection.
func (o *OpenVPNCore) Stop() error {
	o.running.Store(false)

	o.teardownNAT()

	if o.mgmt != nil {
		_ = o.mgmt.Close()
	}
	if o.cmd != nil && o.cmd.Process != nil {
		_ = o.cmd.Process.Kill()
		_ = o.cmd.Wait()
	}
	_ = os.Remove(o.socketPath)

	// SIGKILL doesn't give OpenVPN a chance to run its own interface
	// teardown, so the TUN/DCO interface can be left behind. The next
	// Start() then fails to reattach to it (TUNSETIFF: Invalid argument)
	// because its state doesn't match a fresh attach request. Force
	// cleanup explicitly rather than relying on process death alone.
	if err := execCommand(fmt.Sprintf("ip link delete %s", o.InterfaceName)); err != nil {
		log.WithFields(log.Fields{
			"tag":       o.Tag,
			"interface": o.InterfaceName,
			"err":       err,
		}).Debug("ip link delete for openvpn interface failed (likely already gone, not fatal)")
	}

	log.WithField("tag", o.Tag).Info("OpenVPN server stopped")
	return nil
}

// AddUsers registers users as valid credentials.
func (o *OpenVPNCore) AddUsers(users []panel.UserInfo) {
	o.users.mu.Lock()
	defer o.users.mu.Unlock()

	for _, u := range users {
		o.users.uuidToID[u.Uuid] = u.Id
		o.users.idToUUID[u.Id] = u.Uuid
	}

	log.WithFields(log.Fields{"tag": o.Tag, "count": len(users)}).Info("OpenVPN users added")
}

// DelUsers removes credentials and kills any currently-active session.
func (o *OpenVPNCore) DelUsers(users []panel.UserInfo) {
	o.users.mu.Lock()
	for _, u := range users {
		delete(o.users.uuidToID, u.Uuid)
		delete(o.users.idToUUID, u.Id)
	}
	o.users.mu.Unlock()

	o.sessions.Range(func(_, v interface{}) bool {
		sess := v.(*ovpnSession)
		for _, u := range users {
			if sess.UUID == u.Uuid && o.mgmt != nil {
				_ = o.mgmt.killClient(sess.CID)
			}
		}
		return true
	})

	log.WithFields(log.Fields{"tag": o.Tag, "count": len(users)}).Info("OpenVPN users removed")
}

func (o *OpenVPNCore) GetTrafficAndReset() map[int]*UserTraffic {
	o.trafficMu.Lock()
	defer o.trafficMu.Unlock()
	result := o.traffic
	o.traffic = make(map[int]*UserTraffic)
	return result
}

func (o *OpenVPNCore) GetOnlineUsers() []panel.OnlineUser {
	var online []panel.OnlineUser
	o.sessions.Range(func(_, v interface{}) bool {
		sess := v.(*ovpnSession)
		online = append(online, panel.OnlineUser{UID: sess.UID, IP: sess.IP})
		return true
	})
	return online
}

func (o *OpenVPNCore) SetLimiter(l *limiter.Limiter) {
	o.limiterRef = l
}

// eventLoop consumes management-socket events.
func (o *OpenVPNCore) eventLoop() {
	for ev := range o.mgmt.events {
		switch ev.kind {
		case "CLIENT_CONNECT":
			o.handleClientConnect(ev)
		case "CLIENT_ESTABLISHED":
			// no-op
		case "CLIENT_DISCONNECT":
			o.sessions.Delete(ev.cid)
		case "BYTECOUNT_CLI":
			o.handleByteCount(ev)
		}
	}
}

func (o *OpenVPNCore) handleClientConnect(ev ovpnEvent) {
	// management-client-auth defers username/password auth to this handler.
	// The client profile includes <cert>/<key> to satisfy mobile/Windows apps
	// that prompt when no cert is present, but actual auth is username-based:
	// the UUID is sent as username via auth-user-pass, and username-as-common-name
	// maps it to common_name on the server side.
	username := ev.env["username"]
	ip := extractIP(ev.env["untrusted_ip"])
	if ip == "" {
		ip = extractIP(ev.env["trusted_ip"])
	}

	o.users.mu.RLock()
	uid, ok := o.users.uuidToID[username]
	o.users.mu.RUnlock()

	if !ok {
		log.WithFields(log.Fields{"tag": o.Tag, "username": username, "ip": ip}).
			Warn("OpenVPN auth rejected: unknown user")
		_ = o.mgmt.denyClient(ev.cid, ev.kid, "unknown user")
		return
	}

	if o.limiterRef != nil {
		tagUUID := format.UserTag(o.Tag, username)
		_, reject := o.limiterRef.CheckLimit(tagUUID, ip, true)
		if reject {
			log.WithFields(log.Fields{"tag": o.Tag, "uid": uid, "ip": ip}).
				Warn("OpenVPN auth rejected: device limit exceeded")
			_ = o.mgmt.denyClient(ev.cid, ev.kid, "device limit exceeded")
			return
		}
	}

	o.sessions.Store(ev.cid, &ovpnSession{UID: uid, UUID: username, IP: ip, CID: ev.cid})

	if err := o.mgmt.authorizeClient(ev.cid, ev.kid); err != nil {
		log.WithError(err).Error("OpenVPN: failed to send client-auth-nt")
		return
	}

	log.WithFields(log.Fields{"tag": o.Tag, "uid": uid, "ip": ip}).Info("OpenVPN auth accepted")
}

func (o *OpenVPNCore) handleByteCount(ev ovpnEvent) {
	v, ok := o.sessions.Load(ev.cid)
	if !ok {
		return
	}
	sess := v.(*ovpnSession)

	o.trafficMu.Lock()
	defer o.trafficMu.Unlock()
	if o.traffic[sess.UID] == nil {
		o.traffic[sess.UID] = &UserTraffic{}
	}

	deltaUpload := ev.in - sess.LastBytesIn
	deltaDownload := ev.out - sess.LastBytesOut

	if deltaUpload < 0 {
		deltaUpload = 0
	}
	if deltaDownload < 0 {
		deltaDownload = 0
	}

	o.traffic[sess.UID].Upload += deltaUpload
	o.traffic[sess.UID].Download += deltaDownload

	sess.LastBytesIn = ev.in
	sess.LastBytesOut = ev.out
}

// ensureCertMaterial reads the CA cert/key from disk (written by requestCert),
// generates a server certificate signed by that CA with TLS Web Server Auth EKU,
// and returns (caFile, serverCertFile, serverKeyFile).
func (o *OpenVPNCore) ensureCertMaterial() (caFile, serverCertFile, serverKeyFile string, err error) {
	if o.CertFile == "" || o.KeyFile == "" {
		return "", "", "", fmt.Errorf("missing CA cert or key path")
	}
	if _, err := os.Stat(o.CertFile); err != nil {
		return "", "", "", fmt.Errorf("CA cert file does not exist: %w", err)
	}
	if _, err := os.Stat(o.KeyFile); err != nil {
		return "", "", "", fmt.Errorf("CA key file does not exist: %w", err)
	}

	// Paths for the generated server cert/key
	srvCertPath := filepath.Join(o.WorkDir, "server.crt")
	srvKeyPath := filepath.Join(o.WorkDir, "server.key")

	// Regenerate on every start to pick up any CA rotation from the panel.
	caCert, caKey, err := loadCACertAndKey(o.CertFile, o.KeyFile)
	if err != nil {
		return "", "", "", fmt.Errorf("load CA material: %w", err)
	}

	if err := generateServerCert(caCert, caKey, srvCertPath, srvKeyPath); err != nil {
		return "", "", "", fmt.Errorf("generate server cert: %w", err)
	}

	log.WithField("tag", o.Tag).Info("OpenVPN server certificate generated and signed by CA")
	return o.CertFile, srvCertPath, srvKeyPath, nil
}

// loadCACertAndKey reads a PEM-encoded CA certificate and private key from disk.
func loadCACertAndKey(certPath, keyPath string) (*x509.Certificate, interface{}, error) {
	// Parse CA cert
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, nil, fmt.Errorf("read CA cert: %w", err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, nil, fmt.Errorf("no PEM block found in CA cert")
	}
	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse CA cert: %w", err)
	}

	// Parse CA key (supports EC and PKCS8)
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("read CA key: %w", err)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, nil, fmt.Errorf("no PEM block found in CA key")
	}

	var caKey interface{}
	switch keyBlock.Type {
	case "EC PRIVATE KEY":
		caKey, err = x509.ParseECPrivateKey(keyBlock.Bytes)
	case "PRIVATE KEY":
		caKey, err = x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	case "RSA PRIVATE KEY":
		caKey, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	default:
		return nil, nil, fmt.Errorf("unsupported CA key type: %s", keyBlock.Type)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("parse CA key: %w", err)
	}

	return caCert, caKey, nil
}

// generateServerCert creates an ECDSA P-256 server certificate signed by the CA,
// with the TLS Web Server Authentication EKU that OpenVPN clients require
// when configured with remote-cert-tls server.
func generateServerCert(caCert *x509.Certificate, caKey interface{}, certPath, keyPath string) error {
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate server key: %w", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("generate serial: %w", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "ArchNet OpenVPN Server",
		},
		NotBefore:             time.Now().Add(-5 * time.Minute),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &serverKey.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("sign server cert: %w", err)
	}

	// Write server cert
	certOut, err := os.OpenFile(certPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("create server cert file: %w", err)
	}
	defer certOut.Close()
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		return fmt.Errorf("write server cert PEM: %w", err)
	}

	// Write server key
	keyDER, err := x509.MarshalECPrivateKey(serverKey)
	if err != nil {
		return fmt.Errorf("marshal server key: %w", err)
	}
	keyOut, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("create server key file: %w", err)
	}
	defer keyOut.Close()
	if err := pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}); err != nil {
		return fmt.Errorf("write server key PEM: %w", err)
	}

	return nil
}

func (o *OpenVPNCore) writeServerConf(path, caFile, certFile, keyFile, taKeyPath string) error {
	conf := fmt.Sprintf(`port %d
proto %s
dev %s
dev-type tun

ca %s
cert %s
key %s
dh none
tls-crypt %s

# Client profiles include <cert>/<key> to satisfy OpenVPN Connect apps
# (Windows/Android/iOS) that prompt when no cert is present. The server
# does NOT verify those certs — auth is username-based via management.
verify-client-cert none
username-as-common-name

# Every device authenticates with the same UUID-as-username, so OpenVPN
# would cap each user to one connection without this. CheckLimit remains
# the sole enforcer of the actual per-user device count.
duplicate-cn

# Hand every connection decision to this process instead of deciding locally.
management %s unix
management-client-auth

topology subnet
server 10.9.0.0 255.255.255.0
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 1.1.1.1"

keepalive 10 60
cipher AES-256-GCM
auth SHA256

user nobody
group nogroup

verb 3
`, o.Port, o.Proto, o.InterfaceName, caFile, certFile, keyFile, taKeyPath, o.socketPath)

	return os.WriteFile(path, []byte(conf), 0600)
}

func waitForManagementSocket(path string, timeout time.Duration) (*ovpnMgmtClient, error) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			c, err := dialOpenVPNManagement(path)
			if err == nil {
				return c, nil
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	return nil, fmt.Errorf("timed out waiting for management socket at %s", path)
}

func (o *OpenVPNCore) SetTProxyPort(port int) {
	o.TProxyPort = port
}

func (o *OpenVPNCore) setupNAT() error {
	// Enable IP forwarding
	if err := execCommand("sysctl -w net.ipv4.ip_forward=1"); err != nil {
		log.WithError(err).Warn("Failed to enable IP forwarding")
	}

	subnet := "10.9.0.0/24"

	defaultIface, err := getDefaultInterface()
	if err != nil {
		log.WithError(err).Warn("Failed to get default interface, defaulting to eth0")
		defaultIface = "eth0"
	}

	// Always add FORWARD ACCEPT rules for the OpenVPN interface
	if err := execCommand(fmt.Sprintf("iptables -C FORWARD -i %s -j ACCEPT", o.InterfaceName)); err != nil {
		if err := execCommand(fmt.Sprintf("iptables -A FORWARD -i %s -j ACCEPT", o.InterfaceName)); err != nil {
			log.WithError(err).Warn("Failed to add FORWARD input rule for OpenVPN")
		}
	}
	if err := execCommand(fmt.Sprintf("iptables -C FORWARD -o %s -j ACCEPT", o.InterfaceName)); err != nil {
		if err := execCommand(fmt.Sprintf("iptables -A FORWARD -o %s -j ACCEPT", o.InterfaceName)); err != nil {
			log.WithError(err).Warn("Failed to add FORWARD output rule for OpenVPN")
		}
	}

	if o.TProxyPort > 0 {
		tproxyAvailable := execCommand("iptables -t mangle -m TPROXY -h") == nil ||
			execCommand("modprobe xt_TPROXY") == nil

		if !tproxyAvailable {
			log.WithField("interface", o.InterfaceName).Warn(
				"TPROXY module not available, falling back to MASQUERADE for OpenVPN NAT")
			o.TProxyPort = 0
			return o.setupMasquerade(subnet, defaultIface)
		}

		// 1. Global IP rules
		if err := execCommand("ip rule show fwmark 1 lookup 100"); err != nil {
			_ = execCommand("ip rule add fwmark 1 lookup 100")
		}
		_ = execCommand("ip route replace local 0.0.0.0/0 dev lo table 100")

		// 2. Interface-specific mangle chain
		chainName := fmt.Sprintf("XRAY_%s", o.InterfaceName)

		if err := execCommand(fmt.Sprintf("iptables -t mangle -N %s", chainName)); err != nil {
			execCommand(fmt.Sprintf("iptables -t mangle -F %s", chainName))
		}

		// Return traffic destined to local pool
		execCommand(fmt.Sprintf("iptables -t mangle -A %s -d %s -j RETURN", chainName, subnet))

		// TPROXY capture rules
		if err := execCommand(fmt.Sprintf("iptables -t mangle -A %s -p tcp -j TPROXY --on-port %d --tproxy-mark 1", chainName, o.TProxyPort)); err != nil {
			log.WithFields(log.Fields{
				"chain": chainName,
				"port":  o.TProxyPort,
				"err":   err,
			}).Error("Failed to add TPROXY TCP rule — OpenVPN traffic will not be routed through Xray")
		}
		if err := execCommand(fmt.Sprintf("iptables -t mangle -A %s -p udp -j TPROXY --on-port %d --tproxy-mark 1", chainName, o.TProxyPort)); err != nil {
			log.WithFields(log.Fields{
				"chain": chainName,
				"port":  o.TProxyPort,
				"err":   err,
			}).Error("Failed to add TPROXY UDP rule — OpenVPN traffic will not be routed through Xray")
		}

		// Apply chain to PREROUTING
		checkCmd := fmt.Sprintf("iptables -t mangle -C PREROUTING -i %s -j %s", o.InterfaceName, chainName)
		if err := execCommand(checkCmd); err != nil {
			execCommand(fmt.Sprintf("iptables -t mangle -A PREROUTING -i %s -j %s", o.InterfaceName, chainName))
		}

		// Also add MASQUERADE
		_ = o.setupMasquerade(subnet, defaultIface)
	} else {
		return o.setupMasquerade(subnet, defaultIface)
	}

	return nil
}

func (o *OpenVPNCore) setupMasquerade(subnet, defaultIface string) error {
	checkCmd := fmt.Sprintf("iptables -t nat -C POSTROUTING -s %s -o %s -j MASQUERADE", subnet, defaultIface)
	if err := execCommand(checkCmd); err != nil {
		addCmd := fmt.Sprintf("iptables -t nat -A POSTROUTING -s %s -o %s -j MASQUERADE", subnet, defaultIface)
		if err := execCommand(addCmd); err != nil {
			return fmt.Errorf("failed to add MASQUERADE rule: %w", err)
		}
	}
	return nil
}

func (o *OpenVPNCore) teardownNAT() {
	subnet := "10.9.0.0/24"

	defaultIface, err := getDefaultInterface()
	if err != nil {
		defaultIface = "eth0"
	}

	_ = execCommand(fmt.Sprintf("iptables -D FORWARD -i %s -j ACCEPT", o.InterfaceName))
	_ = execCommand(fmt.Sprintf("iptables -D FORWARD -o %s -j ACCEPT", o.InterfaceName))

	_ = execCommand(fmt.Sprintf("iptables -t nat -D POSTROUTING -s %s -o %s -j MASQUERADE", subnet, defaultIface))

	if o.TProxyPort > 0 {
		chainName := fmt.Sprintf("XRAY_%s", o.InterfaceName)
		_ = execCommand(fmt.Sprintf("iptables -t mangle -D PREROUTING -i %s -j %s", o.InterfaceName, chainName))
		_ = execCommand(fmt.Sprintf("iptables -t mangle -F %s", chainName))
		_ = execCommand(fmt.Sprintf("iptables -t mangle -X %s", chainName))
	}
}

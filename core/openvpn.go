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
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/archnets/node/api/panel"
	"github.com/archnets/node/common/format"
	"github.com/archnets/node/limiter"
	log "github.com/sirupsen/logrus"
)

type ovpnResponder interface {
	authorizeClient(cid, kid string) error
	denyClient(cid, kid, reason string) error
	killClient(cid string) error
}

// OpenVPNCore manages a single real `openvpn` server process, controlled
// through its management interface for dynamic (no-restart) user add/remove,
// auth decisions, and traffic accounting.
type OpenVPNCore struct {
	Tag                 string
	LimiterTag          string // Base node tag used for limiter lookup (e.g. "openvpn-1-1194")
	Port                int
	Proto               string // "udp" or "tcp"
	Subnet              string // client pool in CIDR notation
	WorkDir             string // per-node directory for config/certs/socket
	CertFile            string // real cert path (from panel CertMode="file"/"acme"), optional
	KeyFile             string // real key path, optional
	TlsCryptKey         string // tls-crypt static key content, optional
	InterfaceName       string
	TProxyPort          int
	TProxySubnet        string
	TProxyBypassUDP     bool
	DropICMPUnreachable bool
	ByteCountInterval   int
	OnUnexpectedExit    func()

	cmd        *exec.Cmd
	mgmt       atomic.Pointer[ovpnMgmtClient]
	socketPath string

	logWriter *openvpnLogWriter

	users      *ovpnUserMap
	sessions   sync.Map // cid -> *ovpnSession
	limiterRef *limiter.Limiter
	running    atomic.Bool
	waitDone   chan struct{}
	logRing    *logRingBuffer

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
func NewOpenVPNCore(tag string, port int, proto, subnet, workDir, certFile, keyFile, tlsCryptKey string) (*OpenVPNCore, error) {
	if proto != "udp" && proto != "tcp" {
		proto = "udp"
	}
	if subnet == "" {
		subnet = "10.9.0.0/24"
	}
	_, pool, err := net.ParseCIDR(subnet)
	if err != nil {
		return nil, fmt.Errorf("invalid OpenVPN subnet %q: %w", subnet, err)
	}
	subnet = pool.String()
	// 0711 (not 0700): the openvpn process drops privileges to
	// nobody/nogroup (see writeServerConf) and re-reads key material after
	// the drop. Opening a file requires the traverse (x) bit on every
	// directory in the path, so 0700 root-only dirs cause a fatal ta.key
	// read error on the first client connection. 0711 grants traversal to
	// known filenames while keeping directory listings root-only.
	if err := os.MkdirAll(workDir, 0711); err != nil {
		return nil, fmt.Errorf("create work dir: %w", err)
	}
	// MkdirAll does not fix permissions on directories that already exist
	// (earlier versions created them 0700), so enforce traversal explicitly
	// on the per-instance dir and its parent (/etc/archnets/openvpn).
	_ = os.Chmod(workDir, 0711)
	_ = os.Chmod(filepath.Dir(workDir), 0711)

	return &OpenVPNCore{
		Tag:           tag,
		Port:          port,
		Proto:         proto,
		Subnet:        subnet,
		WorkDir:       workDir,
		CertFile:      certFile,
		KeyFile:       keyFile,
		TlsCryptKey:   tlsCryptKey,
		InterfaceName: fmt.Sprintf("ovpn-%s-%d", proto, port),
		users: &ovpnUserMap{
			uuidToID: make(map[string]int),
			idToUUID: make(map[int]string),
		},
		traffic:    make(map[int]*UserTraffic),
		socketPath: filepath.Join(workDir, "mgmt.sock"),
	}, nil
}

type openvpnLogWriter struct {
	tag     string
	ring    *logRingBuffer
	pending string
	mu      sync.Mutex
}

func newOpenVPNLogWriter(tag string, ring *logRingBuffer) *openvpnLogWriter {
	return &openvpnLogWriter{tag: tag, ring: ring}
}

func (w *openvpnLogWriter) Write(p []byte) (n int, err error) {
	if len(p) == 0 {
		return 0, nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.ring != nil {
		_, _ = w.ring.Write(p)
	}

	data := w.pending + string(p)
	w.pending = ""

	for {
		idx := strings.IndexByte(data, '\n')
		if idx < 0 {
			w.pending = data
			break
		}
		line := strings.TrimRight(data[:idx], "\r")
		data = data[idx+1:]
		if strings.TrimSpace(line) == "" {
			continue
		}

		lower := strings.ToLower(line)
		if strings.Contains(lower, "error") || strings.Contains(lower, "warning") || strings.Contains(lower, "failed") {
			log.WithField("tag", w.tag).Warn(line)
		} else {
			log.WithField("tag", w.tag).Debug(line)
		}
	}

	return len(p), nil
}

func (w *openvpnLogWriter) Flush() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if strings.TrimSpace(w.pending) != "" {
		line := strings.TrimRight(w.pending, "\r\n")
		w.pending = ""
		lower := strings.ToLower(line)
		if strings.Contains(lower, "error") || strings.Contains(lower, "warning") || strings.Contains(lower, "failed") {
			log.WithField("tag", w.tag).Warn(line)
		} else {
			log.WithField("tag", w.tag).Debug(line)
		}
	}
}

func removeTunInterface(iface string) {
	_ = execCommand(fmt.Sprintf("ip link set %s down", iface))
	_ = execCommand(fmt.Sprintf("ip tuntap del mode tun dev %s", iface))
	_ = execCommand(fmt.Sprintf("ip link delete %s", iface))
}

func (o *OpenVPNCore) closePipes() {
	if o.logWriter != nil {
		o.logWriter.Flush()
	}
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
	// OpenVPN re-reads ta.key after dropping privileges to nobody/nogroup;
	// grant the unprivileged user access with minimal exposure.
	makeReadableByUnprivilegedUser(taKeyPath)

	confPath := filepath.Join(o.WorkDir, "server.conf")
	if err := o.writeServerConf(confPath, caFile, serverCertFile, serverKeyFile, taKeyPath); err != nil {
		return fmt.Errorf("write server.conf: %w", err)
	}

	_ = os.Remove(o.socketPath) // stale socket from a previous run

	// Clean up any stale interface left from a previous crash or unclean stop
	removeTunInterface(o.InterfaceName)

	o.cmd = exec.Command("openvpn", "--config", confPath)
	o.logRing = newLogRingBuffer(50)
	writer := newOpenVPNLogWriter(o.Tag, o.logRing)
	o.logWriter = writer
	o.cmd.Stdout = writer
	o.cmd.Stderr = writer

	if err := o.cmd.Start(); err != nil {
		o.closePipes()
		return fmt.Errorf("start openvpn process: %w", err)
	}

	// Setup NAT/TProxy rules
	if err := o.setupNAT(); err != nil {
		log.WithError(err).Warn("openvpn: failed to setup NAT")
	}

	// Wait for the management socket to appear.
	mgmt, err := waitForManagementSocket(o.socketPath, 5*time.Second)
	if err != nil {
		if o.cmd.Process != nil {
			_ = o.cmd.Process.Kill()
			waitErr := o.cmd.Wait()
			o.closePipes()
			recentLogs := o.logRing.Dump()
			log.WithFields(log.Fields{
				"tag":         o.Tag,
				"exit_error":  waitErr,
				"recent_logs": recentLogs,
			}).Error("OpenVPN process failed to initialize management socket")
		} else {
			o.closePipes()
		}
		o.teardownNAT()
		return fmt.Errorf("connect to management socket: %w", err)
	}
	o.mgmt.Store(mgmt)
	o.verifyDCOActive()

	byteCountInterval := o.ByteCountInterval
	if byteCountInterval <= 0 {
		byteCountInterval = 30
	}
	if err := mgmt.enableByteCount(byteCountInterval); err != nil {
		log.WithError(err).Warn("openvpn: failed to enable bytecount reporting")
	}

	o.running.Store(true)
	waitDone := make(chan struct{})
	o.waitDone = waitDone
	go func() {
		defer close(waitDone)
		waitErr := o.cmd.Wait()
		o.closePipes()
		// Atomic CompareAndSwap to claim the shutdown without racing with Stop()
		if o.running.CompareAndSwap(true, false) {
			recentLogs := o.logRing.Dump()
			log.WithFields(log.Fields{
				"tag":         o.Tag,
				"exit_error":  waitErr,
				"recent_logs": recentLogs,
			}).Error("OpenVPN process exited unexpectedly")
			if oldMgmt := o.mgmt.Swap(nil); oldMgmt != nil {
				_ = oldMgmt.Close()
			}
			o.sessions.Range(func(key, _ interface{}) bool {
				o.sessions.Delete(key)
				return true
			})
			if o.OnUnexpectedExit != nil {
				o.OnUnexpectedExit()
			}
		}
	}()
	go o.eventLoop(mgmt)

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

	if oldMgmt := o.mgmt.Swap(nil); oldMgmt != nil {
		_ = oldMgmt.Close()
	}

	if o.cmd != nil && o.cmd.Process != nil && o.waitDone != nil {
		// Send SIGTERM first for graceful process termination
		_ = o.cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-o.waitDone:
		case <-time.After(1 * time.Second):
			// Escalate to SIGKILL if process does not exit within grace period
			_ = o.cmd.Process.Kill()
			<-o.waitDone
		}
		o.waitDone = nil
	}

	_ = os.Remove(o.socketPath)

	removeTunInterface(o.InterfaceName)

	log.WithField("tag", o.Tag).Info("OpenVPN server stopped")
	return nil
}

func (o *OpenVPNCore) IsRunning() bool {
	return o.running.Load()
}

// Restart cleanly stops and relaunches the OpenVPN daemon.
func (o *OpenVPNCore) Restart() error {
	_ = o.Stop()
	return o.Start()
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
	deletedUUIDs := make(map[string]bool, len(users))

	o.users.mu.Lock()
	for _, u := range users {
		delete(o.users.uuidToID, u.Uuid)
		delete(o.users.idToUUID, u.Id)
		deletedUUIDs[u.Uuid] = true
	}
	o.users.mu.Unlock()

	mgmt := o.mgmt.Load()
	o.sessions.Range(func(_, v interface{}) bool {
		sess := v.(*ovpnSession)
		if deletedUUIDs[sess.UUID] && mgmt != nil {
			_ = mgmt.killClient(sess.CID)
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
		if sess.UID > 0 && sess.IP != "" {
			online = append(online, panel.OnlineUser{UID: sess.UID, IP: sess.IP})
		}
		return true
	})
	return online
}

func (o *OpenVPNCore) SetLimiter(l *limiter.Limiter) {
	o.limiterRef = l
}

// eventLoop consumes management-socket events.
func (o *OpenVPNCore) eventLoop(mgmt ovpnResponder) {
	if mgmt == nil {
		return
	}
	var eventsChan <-chan ovpnEvent
	if client, ok := mgmt.(*ovpnMgmtClient); ok && client != nil {
		eventsChan = client.events
	}
	if eventsChan == nil {
		return
	}

	for ev := range eventsChan {
		switch ev.kind {
		case "CLIENT_CONNECT":
			o.handleClientConnect(ev, false, mgmt)
		case "CLIENT_REAUTH":
			o.handleClientConnect(ev, true, mgmt)
		case "CLIENT_DISCONNECT":
			o.sessions.Delete(ev.cid)
		case "BYTECOUNT_CLI":
			o.handleByteCount(ev)
		}
	}
}

func denyClientAsync(cid, kid, reason, tag string, resp ovpnResponder) {
	go func() {
		if resp == nil {
			log.WithFields(log.Fields{
				"tag": tag,
				"cid": cid,
				"kid": kid,
			}).Error("OpenVPN: cannot deny, nil responder")
			return
		}
		_ = resp.denyClient(cid, kid, reason)
	}()
}

func extractOpenVPNClientIP(env map[string]string) string {
	for _, key := range []string{"untrusted_ip", "untrusted_ip6", "trusted_ip", "trusted_ip6"} {
		raw := strings.TrimSpace(env[key])
		if raw == "" {
			continue
		}
		if host, _, err := net.SplitHostPort(raw); err == nil && host != "" {
			raw = host
		}
		raw = strings.TrimPrefix(raw, "[")
		raw = strings.TrimSuffix(raw, "]")
		raw = strings.TrimPrefix(raw, "::ffff:")
		if parsed := net.ParseIP(raw); parsed != nil {
			if v4 := parsed.To4(); v4 != nil {
				return v4.String()
			}
			return parsed.String()
		}
		return raw
	}
	return ""
}

func (o *OpenVPNCore) handleClientConnect(ev ovpnEvent, isReauth bool, resp ovpnResponder) {
	// management-client-auth defers auth to this handler.
	// Users connect either with client certificates (CN = user UUID) or
	// with UUID sent as username. Check username first, then fallback to common_name.
	username := ev.env["username"]
	if username == "" {
		username = ev.env["common_name"]
	}
	ip := extractOpenVPNClientIP(ev.env)

	o.users.mu.RLock()
	uid, ok := o.users.uuidToID[username]
	o.users.mu.RUnlock()

	if !ok {
		log.WithFields(log.Fields{"tag": o.Tag, "username": username, "ip": ip}).
			Warn("OpenVPN auth rejected: unknown user")
		denyClientAsync(ev.cid, ev.kid, "unknown user", o.Tag, resp)
		return
	}

	// On TLS re-auth, if the session already exists with the same UUID, skip
	// device limiter check so active users are not kicked at hourly renegotiation.
	skipLimiter := false
	var lastIn, lastOut int64
	if isReauth {
		if existing, ok := o.sessions.Load(ev.cid); ok {
			sess := existing.(*ovpnSession)
			if sess.UUID == username {
				skipLimiter = true
				lastIn = sess.LastBytesIn
				lastOut = sess.LastBytesOut
			}
		}
	}

	if o.limiterRef != nil && !skipLimiter {
		limiterTag := o.Tag
		if o.LimiterTag != "" {
			limiterTag = o.LimiterTag
		}
		tagUUID := format.UserTag(limiterTag, username)
		_, reject := o.limiterRef.CheckLimit(tagUUID, ip, true)
		if reject {
			log.WithFields(log.Fields{"tag": o.Tag, "limiter_tag": limiterTag, "uid": uid, "ip": ip}).
				Warn("OpenVPN auth rejected: device limit exceeded")
			denyClientAsync(ev.cid, ev.kid, "device limit exceeded", o.Tag, resp)
			return
		}
	}

	o.sessions.Store(ev.cid, &ovpnSession{
		UID:          uid,
		UUID:         username,
		IP:           ip,
		CID:          ev.cid,
		LastBytesIn:  lastIn,
		LastBytesOut: lastOut,
	})

	// Authorize client asynchronously so eventLoop never blocks on send()
	go func(cid, kid, tag string, uid int, ip string, r ovpnResponder) {
		if r == nil {
			o.sessions.Delete(cid)
			log.WithFields(log.Fields{
				"tag": tag,
				"cid": cid,
				"kid": kid,
			}).Error("OpenVPN: cannot authorize, nil responder")
			return
		}
		if err := r.authorizeClient(cid, kid); err != nil {
			o.sessions.Delete(cid)
			log.WithError(err).WithFields(log.Fields{
				"tag": tag,
				"cid": cid,
				"kid": kid,
			}).Error("OpenVPN: failed to send client-auth-nt")
			return
		}
		log.WithFields(log.Fields{"tag": tag, "uid": uid, "ip": ip}).Info("OpenVPN auth accepted")
	}(ev.cid, ev.kid, o.Tag, uid, ip, resp)
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
	poolIP, pool, err := net.ParseCIDR(o.Subnet)
	if err != nil {
		return fmt.Errorf("invalid OpenVPN subnet %q: %w", o.Subnet, err)
	}
	mask := net.IP(pool.Mask).String()
	if mask == "<nil>" {
		return fmt.Errorf("OpenVPN subnet %q is not IPv4", o.Subnet)
	}
	serverNetwork := poolIP.Mask(pool.Mask).String()
	extraUDP := ""
	if o.Proto == "udp" {
		extraUDP = "explicit-exit-notify 1\n"
	}
	conf := fmt.Sprintf(`port %d
proto %s
dev %s
dev-type tun
max-clients 10000

ca %s
cert %s
key %s
dh none
tls-crypt %s

# Client profiles include <cert>/<key> signed by CA (CN = user UUID).
# auth-user-pass-optional allows clients with client certificates
# (and no username/password) to pass through to management-client-auth.
auth-user-pass-optional

# Every device authenticates with the same UUID-as-username, so OpenVPN
# would cap each user to one connection without this. CheckLimit remains
# the sole enforcer of the actual per-user device count.
duplicate-cn

# Hand every connection decision to this process instead of deciding locally.
management %s unix
management-client-auth

topology subnet
server %s %s
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 1.1.1.1"

keepalive 10 60
cipher AES-256-GCM
auth SHA256
%s
user nobody
group nogroup
# Keep key material in memory across SIGUSR1/ping-restart soft restarts
# so the unprivileged nobody user does not fail on re-reading key files.
persist-key

verb 3
`, o.Port, o.Proto, o.InterfaceName, caFile, certFile, keyFile, taKeyPath, o.socketPath, serverNetwork, mask, extraUDP)

	return os.WriteFile(path, []byte(conf), 0600)
}

// verifyDCOActive inspects the created tunnel interface and logs whether DCO
// acceleration is active or whether OpenVPN fell back to standard userspace tun.
func (o *OpenVPNCore) verifyDCOActive() {
	var linkInfo string
	var dcoActive bool
	for start := time.Now(); time.Since(start) < 2*time.Second; time.Sleep(100 * time.Millisecond) {
		output, err := exec.Command("ip", "-d", "link", "show", "dev", o.InterfaceName).CombinedOutput()
		if err == nil {
			linkInfo = strings.TrimSpace(string(output))
			dcoActive = isOpenVPNDCOInterfaceInfo(linkInfo)
			break
		}
	}

	if dcoActive {
		log.WithFields(log.Fields{"tag": o.Tag, "interface": o.InterfaceName, "link_info": linkInfo}).Info("OpenVPN DCO active")
	} else if linkInfo != "" {
		log.WithFields(log.Fields{"tag": o.Tag, "interface": o.InterfaceName, "link_info": linkInfo}).Warn("OpenVPN running in userspace TUN mode (DCO not active)")
	} else {
		log.WithFields(log.Fields{"tag": o.Tag, "interface": o.InterfaceName}).Warn("OpenVPN interface not yet detected via ip link")
	}
}

// iproute2 versions format link kinds differently. The legacy ovpn-dco
// module reports a standalone "ovpn-dco ..." line, while other versions may
// print "kind ovpn" or "kind ovpn-dco". Inspect the first token on each line
// so the interface name itself cannot accidentally satisfy this check.
func isOpenVPNDCOInterfaceInfo(info string) bool {
	for _, line := range strings.Split(info, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		kind := strings.TrimSuffix(fields[0], ":")
		if kind == "kind" {
			if len(fields) > 1 && (fields[1] == "ovpn" || fields[1] == "ovpn-dco") {
				return true
			}
			continue
		}
		if kind == "ovpn" || kind == "ovpn-dco" || kind == "link/ovpn" || kind == "link/ovpn-dco" {
			return true
		}
	}
	return false
}

func (o *OpenVPNCore) SetByteCountInterval(seconds int) {
	o.ByteCountInterval = seconds
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

func (o *OpenVPNCore) SetTProxyConfig(port int, subnet string, bypassUDP bool, dropICMP bool) {
	o.TProxyPort = port
	o.TProxySubnet = subnet
	o.TProxyBypassUDP = bypassUDP
	o.DropICMPUnreachable = dropICMP
}

// makeReadableByUnprivilegedUser makes a secret file readable by the
// unprivileged account the openvpn process drops to ("user nobody" in
// server.conf), with the least exposure possible: chown to nobody keeping
// mode 0600 when possible, world-readable 0644 only as a last resort.
func makeReadableByUnprivilegedUser(path string) {
	if u, err := user.Lookup("nobody"); err == nil {
		uid, errU := strconv.Atoi(u.Uid)
		gid, errG := strconv.Atoi(u.Gid)
		if errU == nil && errG == nil {
			if err := os.Chown(path, uid, gid); err == nil {
				_ = os.Chmod(path, 0600)
				return
			}
		}
	}
	log.WithField("path", path).Warn(
		"could not chown to nobody; falling back to world-readable 0644")
	_ = os.Chmod(path, 0644)
}

func (o *OpenVPNCore) setupNAT() error {
	// Enable IP forwarding
	if err := execCommand("sysctl -w net.ipv4.ip_forward=1"); err != nil {
		log.WithError(err).Warn("Failed to enable IP forwarding")
	}

	subnet := o.Subnet

	defaultIface, err := getDefaultInterface()
	if err != nil {
		log.WithError(err).Warn("Failed to get default interface, defaulting to eth0")
		defaultIface = "eth0"
	}

	// Always add FORWARD ACCEPT rules for the OpenVPN interface
	// Use -I 1 so they take precedence over UFW or firewall DROP rules
	if err := execCommand(fmt.Sprintf("iptables -w 5 -C FORWARD -i %s -j ACCEPT", o.InterfaceName)); err != nil {
		if err := execCommand(fmt.Sprintf("iptables -w 5 -I FORWARD 1 -i %s -j ACCEPT", o.InterfaceName)); err != nil {
			log.WithError(err).Warn("Failed to add FORWARD input rule for OpenVPN")
		}
	}
	if err := execCommand(fmt.Sprintf("iptables -w 5 -C FORWARD -o %s -j ACCEPT", o.InterfaceName)); err != nil {
		if err := execCommand(fmt.Sprintf("iptables -w 5 -I FORWARD 1 -o %s -j ACCEPT", o.InterfaceName)); err != nil {
			log.WithError(err).Warn("Failed to add FORWARD output rule for OpenVPN")
		}
	}
	// Always add INPUT ACCEPT rule for the OpenVPN interface (needed for local DNS like Technitium on local IP)
	// Use -I INPUT 1 so it takes precedence over UFW/default DROP rules
	if err := execCommand(fmt.Sprintf("iptables -w 5 -C INPUT -i %s -j ACCEPT", o.InterfaceName)); err != nil {
		if err := execCommand(fmt.Sprintf("iptables -w 5 -I INPUT 1 -i %s -j ACCEPT", o.InterfaceName)); err != nil {
			log.WithError(err).Warn("Failed to add INPUT rule for OpenVPN")
		}
	}

	// Always add TCPMSS clamping rule for forwarded / outbound traffic to prevent MTU blackholing
	if err := execCommand("iptables -w 5 -t mangle -C POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu"); err != nil {
		_ = execCommand("iptables -w 5 -t mangle -A POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu")
	}

	// Drop ICMP Destination Unreachable if enabled (prevents game disconnects during radio fades)
	// Insert at index 1 AFTER the ACCEPT rules so DROP has higher precedence over ACCEPT
	if o.DropICMPUnreachable {
		if err := execCommand(fmt.Sprintf("iptables -w 5 -C FORWARD -i %s -p icmp --icmp-type destination-unreachable -j DROP", o.InterfaceName)); err != nil {
			_ = execCommand(fmt.Sprintf("iptables -w 5 -I FORWARD 1 -i %s -p icmp --icmp-type destination-unreachable -j DROP", o.InterfaceName))
		}
		if err := execCommand(fmt.Sprintf("iptables -w 5 -C FORWARD -o %s -p icmp --icmp-type destination-unreachable -j DROP", o.InterfaceName)); err != nil {
			_ = execCommand(fmt.Sprintf("iptables -w 5 -I FORWARD 1 -o %s -p icmp --icmp-type destination-unreachable -j DROP", o.InterfaceName))
		}
		if err := execCommand(fmt.Sprintf("iptables -w 5 -C OUTPUT -o %s -p icmp --icmp-type destination-unreachable -j DROP", o.InterfaceName)); err != nil {
			_ = execCommand(fmt.Sprintf("iptables -w 5 -I OUTPUT 1 -o %s -p icmp --icmp-type destination-unreachable -j DROP", o.InterfaceName))
		}
	}

	tproxySubnet := o.TProxySubnet
	if tproxySubnet == "" {
		tproxySubnet = subnet
	}

	if o.TProxyPort > 0 {
		tproxyAvailable := execCommand("iptables -w 5 -t mangle -m TPROXY -h") == nil ||
			execCommand("modprobe xt_TPROXY") == nil

		if !tproxyAvailable {
			log.WithField("interface", o.InterfaceName).Warn(
				"TPROXY module not available, falling back to MASQUERADE for OpenVPN NAT")
			o.TProxyPort = 0
			return o.setupMasquerade(subnet, defaultIface)
		}

		// 1. Global IP rules & route
		ensureTProxyIpRule()

		// 2. Interface-specific mangle chain
		chainName := fmt.Sprintf("XRAY_%s", o.InterfaceName)

		if err := execCommand(fmt.Sprintf("iptables -w 5 -t mangle -N %s", chainName)); err != nil {
			execCommand(fmt.Sprintf("iptables -w 5 -t mangle -F %s", chainName))
		}

		// Return traffic destined to local pool
		execCommand(fmt.Sprintf("iptables -w 5 -t mangle -A %s -d %s -j RETURN", chainName, tproxySubnet))

		// TPROXY capture rules
		if err := execCommand(fmt.Sprintf("iptables -w 5 -t mangle -A %s -p tcp -j TPROXY --on-port %d --tproxy-mark 1", chainName, o.TProxyPort)); err != nil {
			log.WithFields(log.Fields{
				"chain": chainName,
				"port":  o.TProxyPort,
				"err":   err,
			}).Error("Failed to add TPROXY TCP rule — OpenVPN traffic will not be routed through Xray")
		}
		if !o.TProxyBypassUDP {
			if err := execCommand(fmt.Sprintf("iptables -w 5 -t mangle -A %s -p udp -j TPROXY --on-port %d --tproxy-mark 1", chainName, o.TProxyPort)); err != nil {
				log.WithFields(log.Fields{
					"chain": chainName,
					"port":  o.TProxyPort,
					"err":   err,
				}).Error("Failed to add TPROXY UDP rule — OpenVPN traffic will not be routed through Xray")
			}
		} else {
			// Explicitly RETURN so UDP packets bypass mangle TPROXY and fall through to standard kernel MASQUERADE
			_ = execCommand(fmt.Sprintf("iptables -w 5 -t mangle -A %s -p udp -j RETURN", chainName))
		}

		// Apply chain to PREROUTING
		checkCmd := fmt.Sprintf("iptables -w 5 -t mangle -C PREROUTING -i %s -j %s", o.InterfaceName, chainName)
		if err := execCommand(checkCmd); err != nil {
			execCommand(fmt.Sprintf("iptables -w 5 -t mangle -A PREROUTING -i %s -j %s", o.InterfaceName, chainName))
		}

		// Add INPUT rule for TProxy marked packets (required when default INPUT policy is DROP/UFW)
		inputCheck := fmt.Sprintf("iptables -w 5 -C INPUT -i %s -s %s -m mark --mark 1 -j ACCEPT", o.InterfaceName, tproxySubnet)
		if err := execCommand(inputCheck); err != nil {
			inputAdd := fmt.Sprintf("iptables -w 5 -I INPUT 1 -i %s -s %s -m mark --mark 1 -j ACCEPT", o.InterfaceName, tproxySubnet)
			if err := execCommand(inputAdd); err != nil {
				return fmt.Errorf("add OpenVPN TProxy INPUT rule: %w", err)
			}
		}

		// Also add MASQUERADE
		_ = o.setupMasquerade(subnet, defaultIface)
	} else {
		return o.setupMasquerade(subnet, defaultIface)
	}

	return nil
}

func (o *OpenVPNCore) setupMasquerade(subnet, defaultIface string) error {
	checkCmd := fmt.Sprintf("iptables -w 5 -t nat -C POSTROUTING -s %s -o %s -j MASQUERADE", subnet, defaultIface)
	if err := execCommand(checkCmd); err != nil {
		addCmd := fmt.Sprintf("iptables -w 5 -t nat -A POSTROUTING -s %s -o %s -j MASQUERADE", subnet, defaultIface)
		if err := execCommand(addCmd); err != nil {
			return fmt.Errorf("failed to add MASQUERADE rule: %w", err)
		}
	}
	return nil
}

func (o *OpenVPNCore) teardownNAT() {
	subnet := o.Subnet
	tproxySubnet := o.TProxySubnet
	if tproxySubnet == "" {
		tproxySubnet = subnet
	}

	defaultIface, err := getDefaultInterface()
	if err != nil {
		defaultIface = "eth0"
	}

	_ = execCommand(fmt.Sprintf("iptables -w 5 -D INPUT -i %s -j ACCEPT", o.InterfaceName))
	_ = execCommand(fmt.Sprintf("iptables -w 5 -D FORWARD -i %s -j ACCEPT", o.InterfaceName))
	_ = execCommand(fmt.Sprintf("iptables -w 5 -D FORWARD -o %s -j ACCEPT", o.InterfaceName))

	if o.DropICMPUnreachable {
		_ = execCommand(fmt.Sprintf("iptables -w 5 -D FORWARD -i %s -p icmp --icmp-type destination-unreachable -j DROP", o.InterfaceName))
		_ = execCommand(fmt.Sprintf("iptables -w 5 -D FORWARD -o %s -p icmp --icmp-type destination-unreachable -j DROP", o.InterfaceName))
		_ = execCommand(fmt.Sprintf("iptables -w 5 -D OUTPUT -o %s -p icmp --icmp-type destination-unreachable -j DROP", o.InterfaceName))
	}

	_ = execCommand(fmt.Sprintf("iptables -w 5 -t nat -D POSTROUTING -s %s -o %s -j MASQUERADE", subnet, defaultIface))

	if o.TProxyPort > 0 {
		_ = execCommand(fmt.Sprintf("iptables -w 5 -D INPUT -i %s -s %s -m mark --mark 1 -j ACCEPT", o.InterfaceName, tproxySubnet))
		chainName := fmt.Sprintf("XRAY_%s", o.InterfaceName)
		_ = execCommand(fmt.Sprintf("iptables -w 5 -t mangle -D PREROUTING -i %s -j %s", o.InterfaceName, chainName))
		_ = execCommand(fmt.Sprintf("iptables -w 5 -t mangle -F %s", chainName))
		_ = execCommand(fmt.Sprintf("iptables -w 5 -t mangle -X %s", chainName))
	}
}

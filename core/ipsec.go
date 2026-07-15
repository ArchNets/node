package core

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/archnets/node/api/panel"
	log "github.com/sirupsen/logrus"
)

// IPsecConfig holds all configuration for an IPsec core instance.
type IPsecConfig struct {
	Tag              string
	Mode             string // "ikev2" or "l2tp"
	PSK              string // Pre-Shared Key for IPsec
	L2TPSharedSecret string // L2TP shared secret
	AuthMethod       string // "eap-mschapv2" or "psk"
	Domain           string // SNI domain for cert (e.g. "ik1.archlio.com")
	CertMode         string // "none", "file", "http", "self"
	CertFile         string // Inline cert content (for cert_mode=file)
	KeyFile          string // Inline key content (for cert_mode=file)
	DNS              string // DNS servers for VPN clients (e.g. "8.8.8.8,1.1.1.1")
	Subnet           string // IP pool subnet (e.g. "10.10.0.0/16")
	MTU              int    // MTU for L2TP PPP links
}

// IPsecCore manages strongSwan IKEv2 and xl2tpd L2TP servers.
type IPsecCore struct {
	IPsecConfig
	TProxyPort int // Xray TPROXY port for routing traffic
	TProxySubnet   string

	mu    sync.RWMutex
	users map[int]*IPsecUser // key: subscription ID

	// Traffic accounting
	trafficMu      sync.Mutex
	traffic        map[int]*UserTraffic
	lastSasStats   map[string]*sasStats
	statsCollector *ipsecStatsCollector
}

// IPsecUser represents a user's IKEv2/L2TP credentials.
type IPsecUser struct {
	UID      int
	UUID     string
	Username string
	Password string
}

// NewIPsecCore creates a new IPsec core manager.
func NewIPsecCore(cfg IPsecConfig) *IPsecCore {
	if cfg.Mode == "" {
		cfg.Mode = "ikev2"
	}
	cfg.Mode = strings.ToLower(cfg.Mode)
	if cfg.AuthMethod == "" {
		cfg.AuthMethod = "eap-mschapv2"
	}
	return &IPsecCore{
		IPsecConfig:  cfg,
		users:        make(map[int]*IPsecUser),
		traffic:      make(map[int]*UserTraffic),
		lastSasStats: make(map[string]*sasStats),
	}
}

// getSubnet returns the configured subnet or a default based on mode.
func (c *IPsecCore) getSubnet() string {
	if c.Subnet != "" {
		return c.Subnet
	}
	if c.Mode == "l2tp" {
		return "10.11.0.0/16"
	}
	return "10.10.0.0/16"
}

// getDNS returns the configured DNS servers or defaults.
func (c *IPsecCore) getDNS() string {
	if c.DNS != "" {
		return c.DNS
	}
	return "8.8.8.8,1.1.1.1"
}

// getMTU returns the configured MTU or default 1400.
func (c *IPsecCore) getMTU() int {
	if c.MTU > 0 {
		return c.MTU
	}
	return 1400
}

// Start initializes strongSwan and xl2tpd.
func (c *IPsecCore) Start() error {
	// Enable IP forwarding and redirect settings for IPsec/L2TP
	_ = exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1").Run()
	_ = exec.Command("sysctl", "-w", "net.ipv4.conf.all.send_redirects=0").Run()
	_ = exec.Command("sysctl", "-w", "net.ipv4.conf.default.send_redirects=0").Run()
	_ = exec.Command("sysctl", "-w", "net.ipv4.conf.all.accept_redirects=0").Run()
	_ = exec.Command("sysctl", "-w", "net.ipv4.conf.default.accept_redirects=0").Run()

	// Setup NAT
	if err := c.setupNAT(); err != nil {
		log.WithError(err).Warn("Failed to setup NAT for IPsec/L2TP")
	}

	// Write configs
	if err := c.writeConfigs(); err != nil {
		return fmt.Errorf("failed to write ipsec configs: %w", err)
	}

	// Restart strongSwan
	if err := c.reloadStrongSwan(); err != nil {
		return fmt.Errorf("failed to start strongSwan: %w", err)
	}

	// Start xl2tpd if mode is l2tp
	if c.Mode == "l2tp" {
		c.restartXl2tpd()
	}

	// Start stats collector
	c.statsCollector = &ipsecStatsCollector{
		core:     c,
		stopChan: make(chan struct{}),
	}
	c.statsCollector.start()

	log.WithFields(log.Fields{
		"tag":  c.Tag,
		"mode": c.Mode,
	}).Info("IPsec core started")
	return nil
}

// Stop stops strongSwan and xl2tpd.
func (c *IPsecCore) Stop() {
	if c.statsCollector != nil {
		c.statsCollector.stop()
	}
	_ = exec.Command("swanctl", "--terminate", "--ike", c.Tag).Run()

	// Cleanup config files
	os.Remove(fmt.Sprintf("/etc/swanctl/conf.d/%s.conf", c.Tag))
	os.Remove(fmt.Sprintf("/etc/swanctl/conf.d/%s-secrets.conf", c.Tag))

	if c.Mode == "l2tp" {
		c.stopXl2tpd()
		os.Remove(fmt.Sprintf("/etc/xl2tpd/%s.conf", c.Tag))
		os.Remove(fmt.Sprintf("/etc/ppp/options.xl2tpd.%s", c.Tag))
		os.Remove("/etc/ppp/chap-secrets")
		os.Remove(fmt.Sprintf("/etc/ppp/ip-up.d/%s", c.Tag))
		os.Remove(fmt.Sprintf("/etc/ppp/ip-down.d/%s", c.Tag))
		os.Remove(fmt.Sprintf("/run/xl2tpd-%s.pid", c.Tag))
		os.Remove(fmt.Sprintf("/run/xl2tpd-%s.control", c.Tag))
	}

	c.teardownNAT()

	log.WithFields(log.Fields{
		"tag":  c.Tag,
		"mode": c.Mode,
	}).Info("IPsec core stopped")
}

// AddUsers parses ServiceId JSON and adds users.
func (c *IPsecCore) AddUsers(users []panel.UserInfo) {
	c.mu.Lock()
	defer c.mu.Unlock()

	type VPNIdentity struct {
		IKEv2 *struct {
			Username string `json:"username"`
			Password string `json:"password"`
		} `json:"ikev2,omitempty"`
	}

	for _, user := range users {
		if user.ServiceId == "" {
			continue
		}
		var identity VPNIdentity
		if err := json.Unmarshal([]byte(user.ServiceId), &identity); err != nil {
			continue
		}

		// The backend puts creds in "ikev2" key even for l2tp
		if identity.IKEv2 != nil && identity.IKEv2.Username != "" {
			c.users[user.Id] = &IPsecUser{
				UID:      user.Id,
				UUID:     user.Uuid,
				Username: identity.IKEv2.Username,
				Password: identity.IKEv2.Password,
			}
		}
	}

	if err := c.writeConfigs(); err != nil {
		log.WithError(err).Error("Failed to write ipsec configs after adding users")
		return
	}
	if err := c.reloadStrongSwan(); err != nil {
		log.WithError(err).Error("Failed to reload strongSwan after adding users")
	}

	log.WithFields(log.Fields{
		"tag":   c.Tag,
		"count": len(users),
	}).Info("IPsec users added")
}

// DelUsers removes users.
func (c *IPsecCore) DelUsers(users []panel.UserInfo) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, user := range users {
		delete(c.users, user.Id)
	}

	if err := c.writeConfigs(); err != nil {
		log.WithError(err).Error("Failed to write ipsec configs after deleting users")
		return
	}
	if err := c.reloadStrongSwan(); err != nil {
		log.WithError(err).Error("Failed to reload strongSwan after deleting users")
	}

	log.WithFields(log.Fields{
		"tag":   c.Tag,
		"count": len(users),
	}).Info("IPsec users removed")
}

// GetTrafficAndReset returns traffic and resets counters.
func (c *IPsecCore) GetTrafficAndReset() map[int]*UserTraffic {
	c.trafficMu.Lock()
	defer c.trafficMu.Unlock()

	result := c.traffic
	c.traffic = make(map[int]*UserTraffic)
	return result
}

// GetOnlineUsers returns currently connected users via swanctl.
func (c *IPsecCore) GetOnlineUsers() []panel.OnlineUser {
	var online []panel.OnlineUser
	sas := c.parseSasOutput()
	c.mu.RLock()
	defer c.mu.RUnlock()
	seen := make(map[int]bool)
	for _, sa := range sas {
		for _, user := range c.users {
			if sa.Username == user.Username && !seen[user.UID] {
				seen[user.UID] = true
				online = append(online, panel.OnlineUser{
					UID: user.UID,
					IP:  sa.RemoteIP,
				})
			}
		}
	}
	return online
}

// writeConfigs generates appropriate configs based on mode.
func (c *IPsecCore) writeConfigs() error {
	if err := os.MkdirAll("/etc/swanctl/conf.d", 0755); err != nil {
		return err
	}

	// Write swanctl connection config
	conf := ""
	if c.Mode == "l2tp" {
		conf = c.generateL2TPSwanctlConf()
	} else {
		// Ensure server certificate for IKEv2 based on CertMode
		if err := c.setupCertificate(); err != nil {
			log.WithError(err).Warn("Failed to setup IKEv2 certificate")
		}
		conf = c.generateIKEv2SwanctlConf()
	}

	confPath := fmt.Sprintf("/etc/swanctl/conf.d/%s.conf", c.Tag)
	if err := os.WriteFile(confPath, []byte(conf), 0644); err != nil {
		return fmt.Errorf("failed to write %s: %w", confPath, err)
	}

	// Write secrets
	secrets := c.generateSecrets()
	secretsPath := fmt.Sprintf("/etc/swanctl/conf.d/%s-secrets.conf", c.Tag)
	if err := os.WriteFile(secretsPath, []byte(secrets), 0644); err != nil {
		return fmt.Errorf("failed to write %s: %w", secretsPath, err)
	}

	// Write L2TP specific configs
	if c.Mode == "l2tp" {
		for _, dir := range []string{"/etc/xl2tpd", "/etc/ppp", "/etc/ppp/ip-up.d", "/etc/ppp/ip-down.d"} {
			if err := os.MkdirAll(dir, 0755); err != nil {
				return err
			}
		}

		if err := os.WriteFile(fmt.Sprintf("/etc/xl2tpd/%s.conf", c.Tag), []byte(c.generateXl2tpdConf()), 0644); err != nil {
			return err
		}
		if err := os.WriteFile(fmt.Sprintf("/etc/ppp/options.xl2tpd.%s", c.Tag), []byte(c.generatePPPOptions()), 0644); err != nil {
			return err
		}
		if err := os.WriteFile("/etc/ppp/chap-secrets", []byte(c.generateChapSecrets()), 0600); err != nil {
			return err
		}
		// PPP ip-up script: logs which ppp interface belongs to which user
		ipUpScript := fmt.Sprintf(`#!/bin/sh
# Written by ArchNet IPsecCore tag=%s
echo "$PEERNAME $IFNAME" >> /tmp/archnet-ppp-%s.map
`, c.Tag, c.Tag)
		if err := os.WriteFile(fmt.Sprintf("/etc/ppp/ip-up.d/%s", c.Tag), []byte(ipUpScript), 0755); err != nil {
			return err
		}
		// PPP ip-down script: removes mapping
		ipDownScript := fmt.Sprintf(`#!/bin/sh
sed -i "/^$PEERNAME $IFNAME$/d" /tmp/archnet-ppp-%s.map 2>/dev/null
`, c.Tag)
		if err := os.WriteFile(fmt.Sprintf("/etc/ppp/ip-down.d/%s", c.Tag), []byte(ipDownScript), 0755); err != nil {
			return err
		}
	}

	return nil
}

// generateIKEv2SwanctlConf generates IKEv2 swanctl.conf.
func (c *IPsecCore) generateIKEv2SwanctlConf() string {
	// Server (local) auth selection based on CertMode:
	// 1. "http"/"file" + domain → pubkey + eap-mschapv2 (iPhone/iOS compatible)
	// 2. "self" → pubkey with self-signed cert (Android only)
	// 3. "none"/"" or PSK auth → PSK server auth
	localAuth := "auth = psk\n            id = %any"
	remoteAuth := c.AuthMethod

	certName := c.Domain + ".pem"
	switch c.CertMode {
	case "http", "dns":
		// Let's Encrypt / ACME: use trusted cert with domain identity
		certPath := fmt.Sprintf("/etc/swanctl/x509/%s", certName)
		if _, err := os.Stat(certPath); err == nil {
			localAuth = fmt.Sprintf("auth = pubkey\n            certs = %s\n            id = %s", certName, c.Domain)
			remoteAuth = "eap-mschapv2"
			log.WithFields(log.Fields{"tag": c.Tag, "domain": c.Domain}).Info("Using trusted cert for IKEv2")
		}
	case "file":
		// Inline cert from panel
		certPath := fmt.Sprintf("/etc/swanctl/x509/%s", certName)
		if _, err := os.Stat(certPath); err == nil {
			localAuth = fmt.Sprintf("auth = pubkey\n            certs = %s\n            id = %s", certName, c.Domain)
			remoteAuth = "eap-mschapv2"
			log.WithFields(log.Fields{"tag": c.Tag, "domain": c.Domain}).Info("Using file cert for IKEv2")
		}
	case "self":
		// Self-signed cert (Android strongSwan only, not iOS)
		selfCertName := fmt.Sprintf("server-%s.pem", c.Tag)
		certPath := fmt.Sprintf("/etc/swanctl/x509/%s", selfCertName)
		if _, err := os.Stat(certPath); err == nil {
			localAuth = fmt.Sprintf("auth = pubkey\n            certs = %s", selfCertName)
		}
	default:
		// "none" or "" → PSK mode (or EAP with self-signed fallback)
		if strings.HasPrefix(c.AuthMethod, "eap") {
			selfCertName := fmt.Sprintf("server-%s.pem", c.Tag)
			certPath := fmt.Sprintf("/etc/swanctl/x509/%s", selfCertName)
			if _, err := os.Stat(certPath); err == nil {
				localAuth = fmt.Sprintf("auth = pubkey\n            certs = %s", selfCertName)
			}
		}
	}

	r := strings.NewReplacer(
		"{{TAG}}", c.Tag,
		"{{LOCAL_AUTH}}", localAuth,
		"{{REMOTE_AUTH}}", remoteAuth,
		"{{SUBNET}}", c.getSubnet(),
		"{{DNS}}", c.getDNS(),
	)

	return r.Replace(`connections {
    {{TAG}} {
        version = 2
        proposals = aes256gcm16-sha384-ecp256,aes256gcm16-sha256-modp2048,aes128gcm16-sha256-ecp256,aes256-sha256-ecp256,aes256-sha256-modp2048,aes128-sha256-modp2048,aes256-sha1-modp1024,default
        rekey_time = 0s
        pools = pool-{{TAG}}
        fragmentation = force
        dpd_delay = 30s
        send_cert = always
        local {
            {{LOCAL_AUTH}}
        }
        remote {
            auth = {{REMOTE_AUTH}}
            eap_id = %any
        }
        children {
            {{TAG}}-child {
                local_ts = 0.0.0.0/0
                rekey_time = 0s
                dpd_action = clear
                esp_proposals = aes256gcm16,aes128gcm16,aes256-sha256,aes128-sha256,aes256-sha1,aes128-sha1,default
            }
        }
    }
}
pools {
    pool-{{TAG}} {
        addrs = {{SUBNET}}
        dns = {{DNS}}
    }
}
`)
}

// ensureServerCert generates a self-signed certificate for IKEv2 server auth if one doesn't exist.
func (c *IPsecCore) ensureServerCert() error {
	certPath := fmt.Sprintf("/etc/swanctl/x509/server-%s.pem", c.Tag)
	keyPath := fmt.Sprintf("/etc/swanctl/private/server-%s.pem", c.Tag)

	// Skip if cert already exists
	if _, err := os.Stat(certPath); err == nil {
		return nil
	}

	// Ensure directories exist
	for _, dir := range []string{"/etc/swanctl/x509", "/etc/swanctl/private"} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create %s: %w", dir, err)
		}
	}

	// Generate ECDSA P-256 key
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate key: %w", err)
	}

	// Detect server IP from swanctl socket or use a wildcard
	serverIP := "0.0.0.0"
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, addr := range addrs {
			if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() && ipNet.IP.To4() != nil {
				serverIP = ipNet.IP.String()
				break
			}
		}
	}

	// Create self-signed certificate
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: serverIP,
		},
		IPAddresses:           []net.IP{net.ParseIP(serverIP)},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour), // 10 years
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return fmt.Errorf("failed to create certificate: %w", err)
	}

	// Write certificate
	certFile, err := os.Create(certPath)
	if err != nil {
		return fmt.Errorf("failed to create cert file: %w", err)
	}
	defer certFile.Close()
	if err := pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		return err
	}

	// Write private key
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return fmt.Errorf("failed to marshal key: %w", err)
	}
	keyFile, err := os.OpenFile(keyPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create key file: %w", err)
	}
	defer keyFile.Close()
	if err := pem.Encode(keyFile, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}); err != nil {
		return err
	}

	log.WithField("tag", c.Tag).Info("Generated self-signed certificate for IKEv2 server auth")
	return nil
}

// setupCertificate installs certificates for IKEv2 based on CertMode.
func (c *IPsecCore) setupCertificate() error {
	// Ensure strongSwan directories exist
	for _, dir := range []string{"/etc/swanctl/x509", "/etc/swanctl/x509ca", "/etc/swanctl/private"} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create %s: %w", dir, err)
		}
	}

	switch c.CertMode {
	case "http", "dns":
		// Let's Encrypt / ACME cert from standard certbot path
		return c.installLetsEncryptCert()
	case "file":
		// Inline cert content from panel API
		return c.installFileCert()
	case "self":
		// Self-signed certificate
		return c.ensureServerCert()
	default:
		// "none" or "" → try self-signed for EAP fallback, skip for PSK
		if strings.HasPrefix(c.AuthMethod, "eap") {
			return c.ensureServerCert()
		}
		return nil // PSK mode, no cert needed
	}
}

// installLetsEncryptCert copies Let's Encrypt certificates into strongSwan directories.
func (c *IPsecCore) installLetsEncryptCert() error {
	if c.Domain == "" {
		return fmt.Errorf("no domain configured for Let's Encrypt cert")
	}

	leDir := fmt.Sprintf("/etc/letsencrypt/live/%s", c.Domain)
	certSrc := leDir + "/cert.pem"
	chainSrc := leDir + "/chain.pem"
	keySrc := leDir + "/privkey.pem"

	// Verify Let's Encrypt files exist
	for _, f := range []string{certSrc, chainSrc, keySrc} {
		if _, err := os.Stat(f); err != nil {
			return fmt.Errorf("Let's Encrypt file not found: %s", f)
		}
	}

	// Copy cert (not symlink — Let's Encrypt live/ files are already symlinks)
	copies := []struct {
		src, dst string
	}{
		{certSrc, fmt.Sprintf("/etc/swanctl/x509/%s.pem", c.Domain)},
		{chainSrc, fmt.Sprintf("/etc/swanctl/x509ca/%s-chain.pem", c.Domain)},
		{keySrc, fmt.Sprintf("/etc/swanctl/private/%s.pem", c.Domain)},
	}

	for _, cp := range copies {
		data, err := os.ReadFile(cp.src)
		if err != nil {
			return fmt.Errorf("failed to read %s: %w", cp.src, err)
		}
		perm := os.FileMode(0644)
		if strings.Contains(cp.dst, "private") {
			perm = 0600
		}
		if err := os.WriteFile(cp.dst, data, perm); err != nil {
			return fmt.Errorf("failed to write %s: %w", cp.dst, err)
		}
	}

	log.WithFields(log.Fields{"tag": c.Tag, "domain": c.Domain}).Info("Installed Let's Encrypt certificate for IKEv2")
	return nil
}

// installFileCert writes inline certificate content from the panel to strongSwan directories.
func (c *IPsecCore) installFileCert() error {
	if c.Domain == "" {
		return fmt.Errorf("no domain configured for file cert")
	}
	if c.IPsecConfig.CertFile == "" || c.IPsecConfig.KeyFile == "" {
		return fmt.Errorf("cert_mode is 'file' but cert_file or key_file is empty")
	}

	certDst := fmt.Sprintf("/etc/swanctl/x509/%s.pem", c.Domain)
	keyDst := fmt.Sprintf("/etc/swanctl/private/%s.pem", c.Domain)

	if err := os.WriteFile(certDst, []byte(c.IPsecConfig.CertFile), 0644); err != nil {
		return fmt.Errorf("failed to write cert: %w", err)
	}
	if err := os.WriteFile(keyDst, []byte(c.IPsecConfig.KeyFile), 0600); err != nil {
		return fmt.Errorf("failed to write key: %w", err)
	}

	log.WithFields(log.Fields{"tag": c.Tag, "domain": c.Domain}).Info("Installed file certificate for IKEv2")
	return nil
}

// generateL2TPSwanctlConf generates IKEv1 Transport mode swanctl.conf for L2TP.
func (c *IPsecCore) generateL2TPSwanctlConf() string {
	return fmt.Sprintf(`connections {
    %s {
        version = 1
        proposals = aes256-sha1-modp2048,aes128-sha1-modp1024,3des-sha1-modp1024,default
        encap = yes
        local {
            auth = psk
            id = %%any
        }
        remote {
            auth = psk
        }
        children {
            %s-l2tp {
                local_ts = dynamic[udp/1701]
                remote_ts = dynamic[udp/1701]
                mode = transport
                esp_proposals = aes256-sha1,aes128-sha1,3des-sha1,default
                dpd_action = clear
            }
        }
    }
}
`, c.Tag, c.Tag)
}

// generateXl2tpdConf generates xl2tpd.conf (tag-scoped).
func (c *IPsecCore) generateXl2tpdConf() string {
	// Derive IP range from subnet (e.g. 10.11.0.0/16 → local=10.11.0.1, range=10.11.1.2-10.11.254.254)
	subnet := c.getSubnet()
	parts := strings.Split(strings.Split(subnet, "/")[0], ".")
	base := "10.11"
	if len(parts) >= 2 {
		base = parts[0] + "." + parts[1]
	}

	return fmt.Sprintf(`[global]
port = 1701

[lns default]
ip range = %s.1.2-%s.254.254
local ip = %s.0.1
require chap = yes
refuse pap = yes
require authentication = yes
pppoptfile = /etc/ppp/options.xl2tpd.%s
length bit = yes
`, base, base, base, c.Tag)
}

// generatePPPOptions generates PPP options.
func (c *IPsecCore) generatePPPOptions() string {
	// Split DNS string into individual ms-dns lines
	dnsServers := strings.Split(c.getDNS(), ",")
	var dnsLines string
	for _, dns := range dnsServers {
		dns = strings.TrimSpace(dns)
		if dns != "" {
			dnsLines += fmt.Sprintf("ms-dns %s\n", dns)
		}
	}

	mtu := c.getMTU()
	return fmt.Sprintf(`ipcp-accept-local
ipcp-accept-remote
%snoccp
auth
mtu %d
mru %d
nodefaultroute
lock
proxyarp
`, dnsLines, mtu, mtu)
}

// generateChapSecrets generates PPP CHAP secrets.
func (c *IPsecCore) generateChapSecrets() string {
	var sb strings.Builder
	sb.WriteString("# Generated by ArchNet IPsecCore\n")
	for _, user := range c.users {
		sb.WriteString(fmt.Sprintf("\"%s\" * \"%s\" *\n", user.Username, user.Password))
	}
	return sb.String()
}

// generateSecrets generates the strongSwan secrets config.
func (c *IPsecCore) generateSecrets() string {
	var sb strings.Builder
	sb.WriteString("secrets {\n")

	// IKE PSK
	psk := c.PSK
	if c.Mode == "l2tp" && c.L2TPSharedSecret != "" {
		psk = c.L2TPSharedSecret
	}
	sb.WriteString(fmt.Sprintf("    ike-%s {\n", c.Tag))
	sb.WriteString("        id = %any\n")
	sb.WriteString(fmt.Sprintf("        secret = \"%s\"\n", psk))
	sb.WriteString("    }\n")

	// EAP secrets for each user (IKEv2 only)
	if c.Mode == "ikev2" {
		for _, user := range c.users {
			sb.WriteString(fmt.Sprintf("    eap-%s-%d {\n", c.Tag, user.UID))
			sb.WriteString(fmt.Sprintf("        id = \"%s\"\n", user.Username))
			sb.WriteString(fmt.Sprintf("        secret = \"%s\"\n", user.Password))
			sb.WriteString("    }\n")
		}
	}

	sb.WriteString("}\n")
	return sb.String()
}

// reloadStrongSwan ensures charon is running and loads configuration.
func (c *IPsecCore) reloadStrongSwan() error {
	// Check if swanctl binary exists
	if _, err := exec.LookPath("swanctl"); err != nil {
		return fmt.Errorf("strongSwan not installed (swanctl not found). Install: apt install -y strongswan strongswan-swanctl xl2tpd")
	}

	// Ensure strongSwan daemon (charon) is running.
	// Service name varies by distro/package:
	//   - strongswan-starter : classic strongSwan (charon-starter)
	//   - strongswan-swanctl : swanctl-managed (Debian/Ubuntu strongswan-swanctl pkg)
	//   - strongswan         : generic alias on some distros
	//   - ipsec start        : legacy SysV fallback
	serviceNames := []string{"strongswan-starter", "strongswan-swanctl", "strongswan"}
	started := false
	for _, svc := range serviceNames {
		if err := exec.Command("systemctl", "start", svc).Run(); err == nil {
			started = true
			log.WithField("service", svc).Info("strongSwan service started")
			break
		}
	}
	if !started {
		_ = exec.Command("ipsec", "start").Run()
	}

	// Wait for charon VICI socket with retries
	viciSocket := "/var/run/charon.vici"
	for i := 0; i < 10; i++ {
		if _, err := os.Stat(viciSocket); err == nil {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if _, err := os.Stat(viciSocket); err != nil {
		return fmt.Errorf("charon VICI socket not found after 5s. strongSwan daemon failed to start")
	}

	if out, err := exec.Command("swanctl", "--load-all").CombinedOutput(); err != nil {
		return fmt.Errorf("swanctl --load-all failed: %s, output: %s", err, string(out))
	}
	return nil
}

// restartXl2tpd stops any running xl2tpd instance for this tag and starts a new one.
func (c *IPsecCore) restartXl2tpd() {
	c.stopXl2tpd()
	confPath := fmt.Sprintf("/etc/xl2tpd/%s.conf", c.Tag)
	pidFile := fmt.Sprintf("/run/xl2tpd-%s.pid", c.Tag)
	controlFile := fmt.Sprintf("/run/xl2tpd-%s.control", c.Tag)
	cmd := exec.Command("xl2tpd", "-c", confPath, "-p", pidFile, "-C", controlFile)
	if err := cmd.Start(); err != nil {
		log.WithError(err).Error("Failed to start xl2tpd")
	}
}

// stopXl2tpd stops the xl2tpd instance for this tag by reading its PID file.
func (c *IPsecCore) stopXl2tpd() {
	pidFile := fmt.Sprintf("/run/xl2tpd-%s.pid", c.Tag)
	data, err := os.ReadFile(pidFile)
	if err != nil {
		return
	}
	pid := strings.TrimSpace(string(data))
	if pid != "" {
		_ = exec.Command("kill", pid).Run()
		// Wait briefly for process to exit
		time.Sleep(200 * time.Millisecond)
	}
}

// SetTProxyPort sets the local Xray port to route traffic to.
func (c *IPsecCore) SetTProxyConfig(port int, subnet string) {
	c.TProxyPort = port
	c.TProxySubnet = subnet
}

// setupNAT configures TPROXY or MASQUERADE for the VPN subnet
func (c *IPsecCore) setupNAT() error {
	subnet := c.getSubnet()

	tproxySubnet := c.TProxySubnet
	if tproxySubnet == "" { tproxySubnet = c.getSubnet() }

	if c.TProxyPort > 0 {
		// TPROXY mode: route VPN traffic through Xray.
		// TPROXY preserves original destination for both TCP and UDP.
		// Note: REDIRECT can't recover original dest for UDP (SO_ORIGINAL_DST
		// doesn't work for connectionless protocols), so TPROXY is required.
		_ = exec.Command("sh", "-c", "ip rule add fwmark 1 lookup 100").Run()
		_ = exec.Command("sh", "-c", "ip route add local 0.0.0.0/0 dev lo table 100").Run()

		chainName := fmt.Sprintf("XRAY_IPSEC_%s", c.Tag)

		// Create chain in mangle table (ignore error if exists)
		if err := exec.Command("sh", "-c", fmt.Sprintf("iptables -w 5 -t mangle -N %s", chainName)).Run(); err != nil {
			_ = exec.Command("sh", "-c", fmt.Sprintf("iptables -w 5 -t mangle -F %s", chainName)).Run()
		}

		// Skip traffic destined to VPN subnet itself
		_ = exec.Command("sh", "-c", fmt.Sprintf("iptables -w 5 -t mangle -A %s -d %s -j RETURN", chainName, tproxySubnet)).Run()

		// TPROXY capture rules for TCP and UDP
		_ = exec.Command("sh", "-c", fmt.Sprintf("iptables -w 5 -t mangle -A %s -p tcp -j TPROXY --on-port %d --tproxy-mark 1", chainName, c.TProxyPort)).Run()
		_ = exec.Command("sh", "-c", fmt.Sprintf("iptables -w 5 -t mangle -A %s -p udp -j TPROXY --on-port %d --tproxy-mark 1", chainName, c.TProxyPort)).Run()

		// Apply to PREROUTING for packets from VPN subnet
		checkCmd := fmt.Sprintf("iptables -w 5 -t mangle -C PREROUTING -s %s -j %s", subnet, chainName)
		if err := exec.Command("sh", "-c", checkCmd).Run(); err != nil {
			_ = exec.Command("sh", "-c", fmt.Sprintf("iptables -w 5 -t mangle -A PREROUTING -s %s -j %s", subnet, chainName)).Run()
		}

		log.WithFields(log.Fields{"tag": c.Tag, "port": c.TProxyPort}).Info("IPsec TPROXY routing enabled")
	} else {
		// Standard masquerade (direct internet)
		checkCmd := fmt.Sprintf("iptables -w 5 -t nat -C POSTROUTING -s %s -j MASQUERADE", subnet)
		if err := exec.Command("sh", "-c", checkCmd).Run(); err != nil {
			addCmd := fmt.Sprintf("iptables -w 5 -t nat -A POSTROUTING -s %s -j MASQUERADE", subnet)
			if err := exec.Command("sh", "-c", addCmd).Run(); err != nil {
				return err
			}
		}
	}
	return nil
}

// teardownNAT removes NAT/TPROXY rules for the VPN subnet
func (c *IPsecCore) teardownNAT() {
	subnet := c.getSubnet()

	if c.TProxyPort > 0 {
		chainName := fmt.Sprintf("XRAY_IPSEC_%s", c.Tag)
		_ = exec.Command("sh", "-c", fmt.Sprintf("iptables -w 5 -t mangle -D PREROUTING -s %s -j %s", subnet, chainName)).Run()
		_ = exec.Command("sh", "-c", fmt.Sprintf("iptables -w 5 -t mangle -F %s", chainName)).Run()
		_ = exec.Command("sh", "-c", fmt.Sprintf("iptables -w 5 -t mangle -X %s", chainName)).Run()
	} else {
		_ = exec.Command("sh", "-c", fmt.Sprintf("iptables -w 5 -t nat -D POSTROUTING -s %s -j MASQUERADE", subnet)).Run()
	}
}

type sasStats struct {
	InBytes  int64
	OutBytes int64
}

type ipsecStatsCollector struct {
	core     *IPsecCore
	stopChan chan struct{}
	wg       sync.WaitGroup
}

type parsedSA struct {
	Username string
	RemoteIP string
	InBytes  int64
	OutBytes int64
}

var (
	reRemote   = regexp.MustCompile(`remote\s+'([^']+)'\s+@\s+([0-9.]+)`)
	reInBytes  = regexp.MustCompile(`bytes_i(?:n)?=(\d+)`)
	reOutBytes = regexp.MustCompile(`bytes_o(?:ut)?=(\d+)`)
	reBytesAlt = regexp.MustCompile(`(\d+)\s+bytes_i.*?(\d+)\s+bytes_o`)
)

func (c *IPsecCore) parseSasOutput() []parsedSA {
	if c.Mode == "l2tp" {
		return c.parseL2TPOnlineUsers()
	}

	output, err := exec.Command("swanctl", "--list-sas").CombinedOutput()
	if err != nil {
		return nil
	}
	var result []parsedSA
	var current *parsedSA
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if m := reRemote.FindStringSubmatch(line); len(m) == 3 {
			if current != nil {
				result = append(result, *current)
			}
			current = &parsedSA{
				Username: m[1],
				RemoteIP: m[2],
			}
			continue
		}
		if current == nil {
			continue
		}
		if m := reInBytes.FindStringSubmatch(line); len(m) == 2 {
			current.InBytes, _ = strconv.ParseInt(m[1], 10, 64)
		}
		if m := reOutBytes.FindStringSubmatch(line); len(m) == 2 {
			current.OutBytes, _ = strconv.ParseInt(m[1], 10, 64)
		}
		if m := reBytesAlt.FindStringSubmatch(line); len(m) == 3 {
			current.InBytes, _ = strconv.ParseInt(m[1], 10, 64)
			current.OutBytes, _ = strconv.ParseInt(m[2], 10, 64)
		}
	}
	if current != nil {
		result = append(result, *current)
	}
	return result
}

func (c *IPsecCore) collectStats() {
	sas := c.parseSasOutput()
	if len(sas) == 0 {
		return
	}
	c.mu.RLock()
	usernameToUID := make(map[string]int)
	for _, user := range c.users {
		usernameToUID[user.Username] = user.UID
	}
	c.mu.RUnlock()

	c.trafficMu.Lock()
	defer c.trafficMu.Unlock()
	for _, sa := range sas {
		uid, ok := usernameToUID[sa.Username]
		if !ok {
			continue
		}
		last, exists := c.lastSasStats[sa.Username]
		if !exists {
			last = &sasStats{}
			c.lastSasStats[sa.Username] = last
		}
		var dlDelta, ulDelta int64
		if sa.OutBytes >= last.OutBytes {
			dlDelta = sa.OutBytes - last.OutBytes
		} else {
			dlDelta = sa.OutBytes
		}
		if sa.InBytes >= last.InBytes {
			ulDelta = sa.InBytes - last.InBytes
		} else {
			ulDelta = sa.InBytes
		}
		last.InBytes = sa.InBytes
		last.OutBytes = sa.OutBytes
		if dlDelta == 0 && ulDelta == 0 {
			continue
		}
		if c.traffic[uid] == nil {
			c.traffic[uid] = &UserTraffic{}
		}
		c.traffic[uid].Download += dlDelta
		c.traffic[uid].Upload += ulDelta
	}
}

// parseL2TPOnlineUsers reads the PPP user-to-interface map and collects
// traffic from /sys/class/net/pppX/statistics.
func (c *IPsecCore) parseL2TPOnlineUsers() []parsedSA {
	mapFile := fmt.Sprintf("/tmp/archnet-ppp-%s.map", c.Tag)
	data, err := os.ReadFile(mapFile)
	if err != nil {
		return nil
	}

	var result []parsedSA
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	for _, line := range lines {
		parts := strings.Fields(line)
		if len(parts) != 2 {
			continue
		}
		username := parts[0]
		iface := parts[1]

		// Read rx/tx bytes from sysfs
		rxBytes := readSysfsInt64(fmt.Sprintf("/sys/class/net/%s/statistics/rx_bytes", iface))
		txBytes := readSysfsInt64(fmt.Sprintf("/sys/class/net/%s/statistics/tx_bytes", iface))

		result = append(result, parsedSA{
			Username: username,
			RemoteIP: "",
			InBytes:  rxBytes, // rx on server = upload from user
			OutBytes: txBytes, // tx on server = download for user
		})
	}
	return result
}

// readSysfsInt64 reads an integer from a sysfs file.
func readSysfsInt64(path string) int64 {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	v, _ := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	return v
}

func (t *ipsecStatsCollector) start() {
	t.wg.Add(1)
	go t.run()
}

func (t *ipsecStatsCollector) run() {
	defer t.wg.Done()
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-t.stopChan:
			return
		case <-ticker.C:
			t.core.collectStats()
		}
	}
}

func (t *ipsecStatsCollector) stop() {
	close(t.stopChan)
	t.wg.Wait()
}

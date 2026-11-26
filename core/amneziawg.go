//go:build !freebsd

package core

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/archnets/node/api/panel"
	"github.com/archnets/node/limiter"
	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type awgUserspace interface {
	ipcSet(conf string) error
	ipcGet() (string, error)
	up() error
	close()
}

// AmneziaConfig holds obfuscation and mimicry parameters for AmneziaWG 3.1
type AmneziaConfig struct {
	Jc                     int
	Jmin                   int
	Jmax                   int
	S1                     int
	S2                     int
	S3                     int
	S4                     int
	H1                     string
	H2                     string
	H3                     string
	H4                     string
	I1                     string
	I2                     string
	I3                     string
	I4                     string
	I5                     string
	HeaderProtectionKey    string
	ContentPaddingAddition string
	RekeyAfterTime         string
	RekeyTimeout           string
	RejectAfterTime        string
	KeepaliveTimeout       string
	MaxHandshakeAttempts   string
	RandomTrailers         bool
	DisableCookies         bool
}

// AmneziaWGCore manages a AmneziaWG VPN server
type AmneziaWGCore struct {
	Tag           string
	Port          int
	InterfaceName string
	PrivateKey    wgtypes.Key
	PublicKey     wgtypes.Key
	Address       string // e.g., "10.0.0.1/24"
	MTU           int
	DNS           string

	// Amnezia Params
	Jc                     int
	Jmin                   int
	Jmax                   int
	S1                     int
	S2                     int
	S3                     int
	S4                     int
	H1                     string
	H2                     string
	H3                     string
	H4                     string
	I1                     string
	I2                     string
	I3                     string
	I4                     string
	I5                     string
	HeaderProtectionKey    string
	ContentPaddingAddition string
	RekeyAfterTime         string
	RekeyTimeout           string
	RejectAfterTime        string
	KeepaliveTimeout       string
	MaxHandshakeAttempts   string
	RandomTrailers         bool
	DisableCookies         bool

	peers      sync.Map // map[string]*WireGuardPeer (key: UUID)
	keyToPeer  sync.Map // map[string]*WireGuardPeer (key: PublicKey.String())
	users      *WGUserMap
	limiterRef *limiter.Limiter
	running    atomic.Bool

	// Traffic accounting
	trafficMu      sync.RWMutex
	traffic        map[int]*UserTraffic // key: uid
	lastPeerStats  map[string]*peerStats
	statsCollector *amneziaStatsCollectorTask
	userspace      awgUserspace
	TProxyPort          int
	TProxySubnet        string
	TProxyBypassUDP     bool
	DropICMPUnreachable bool
	OnPeerActive        func()
}

// SetTProxyConfig sets the local Xray port to route traffic to, subnet, and routing options
func (w *AmneziaWGCore) SetTProxyConfig(port int, subnet string, bypassUDP bool, dropICMP bool) {
	w.TProxyPort = port
	w.TProxySubnet = subnet
	w.TProxyBypassUDP = bypassUDP
	w.DropICMPUnreachable = dropICMP
}

// Reuse structs from wireguard.go where possible or redefine if private

// NewAmneziaWGCore creates a new AmneziaWG VPN server
func NewAmneziaWGCore(tag string, port int, address string, interfaceName string, mtu int, dns string, privateKeyStr string,
	cfg AmneziaConfig) (*AmneziaWGCore, error) {

	var privateKey wgtypes.Key
	var err error

	if privateKeyStr != "" {
		privateKey, err = wgtypes.ParseKey(privateKeyStr)
		if err != nil {
			return nil, fmt.Errorf("invalid private key: %w", err)
		}
	} else {
		privateKey, err = wgtypes.GeneratePrivateKey()
		if err != nil {
			return nil, fmt.Errorf("failed to generate private key: %w", err)
		}
	}
	publicKey := privateKey.PublicKey()

	if mtu == 0 {
		mtu = 1280
	}

	if interfaceName == "" {
		interfaceName = "awg0"
	}

	core := &AmneziaWGCore{
		Tag:                    tag,
		Port:                   port,
		InterfaceName:          interfaceName,
		PrivateKey:             privateKey,
		PublicKey:              publicKey,
		Address:                address,
		MTU:                    mtu,
		DNS:                    dns,
		Jc:                     cfg.Jc,
		Jmin:                   cfg.Jmin,
		Jmax:                   cfg.Jmax,
		S1:                     cfg.S1,
		S2:                     cfg.S2,
		S3:                     cfg.S3,
		S4:                     cfg.S4,
		H1:                     cfg.H1,
		H2:                     cfg.H2,
		H3:                     cfg.H3,
		H4:                     cfg.H4,
		I1:                     cfg.I1,
		I2:                     cfg.I2,
		I3:                     cfg.I3,
		I4:                     cfg.I4,
		I5:                     cfg.I5,
		HeaderProtectionKey:    cfg.HeaderProtectionKey,
		ContentPaddingAddition: cfg.ContentPaddingAddition,
		RekeyAfterTime:         cfg.RekeyAfterTime,
		RekeyTimeout:           cfg.RekeyTimeout,
		RejectAfterTime:        cfg.RejectAfterTime,
		KeepaliveTimeout:       cfg.KeepaliveTimeout,
		MaxHandshakeAttempts:   cfg.MaxHandshakeAttempts,
		RandomTrailers:         cfg.RandomTrailers,
		DisableCookies:         cfg.DisableCookies,
		users: &WGUserMap{
			uuidToID: make(map[string]int),
			idToUUID: make(map[int]string),
			ipToUID:  make(map[string]int),
		},
		traffic:       make(map[int]*UserTraffic),
		lastPeerStats: make(map[string]*peerStats),
	}

	return core, nil
}

// Start starts the AmneziaWG server
func (w *AmneziaWGCore) Start() error {
	// Create AmneziaWG interface
	if err := w.createInterface(); err != nil {
		return fmt.Errorf("failed to create interface: %w", err)
	}

	// Configure the interface
	if err := w.configureInterface(); err != nil {
		w.deleteInterface() // Cleanup on failure
		return fmt.Errorf("failed to configure interface: %w", err)
	}

	// Setup NAT/Masquerading
	if err := w.setupNAT(); err != nil {
		log.WithError(err).Warn("Failed to setup NAT for AmneziaWG")
	}

	w.running.Store(true)

	// Start stats collector
	w.statsCollector = &amneziaStatsCollectorTask{
		core:     w,
		stopChan: make(chan struct{}),
	}
	w.statsCollector.start()

	log.WithFields(log.Fields{
		"tag":       w.Tag,
		"interface": w.InterfaceName,
		"port":      w.Port,
		"publicKey": w.PublicKey.String(),
	}).Info("AmneziaWG server started")

	return nil
}

// Stop stops the AmneziaWG server
func (w *AmneziaWGCore) Stop() error {
	w.running.Store(false)

	if w.statsCollector != nil {
		w.statsCollector.stop()
	}

	w.teardownNAT()

	if err := w.deleteInterface(); err != nil {
		log.WithError(err).Warn("Failed to delete AmneziaWG interface")
	}

	log.WithField("tag", w.Tag).Info("AmneziaWG server stopped")
	return nil
}

// AddUsers adds users via batched `awg set` commands
func (w *AmneziaWGCore) AddUsers(users []panel.UserInfo) error {
	w.users.mu.Lock()
	defer w.users.mu.Unlock()

	_, poolNet, _ := net.ParseCIDR(getPoolSubnet(w.Address))

	type ServiceIdentity struct {
		WireGuard *struct {
			PublicKey string `json:"public_key"`
		} `json:"wireguard,omitempty"`
	}

	type pendingPeer struct {
		pubKey     string
		assignedIP string
	}
	var batch []pendingPeer

	for _, user := range users {
		if user.ServiceId == "" {
			continue
		}

		pubKeyStr := user.ServiceId
		var identity ServiceIdentity
		if err := json.Unmarshal([]byte(user.ServiceId), &identity); err == nil {
			if identity.WireGuard != nil && identity.WireGuard.PublicKey != "" {
				pubKeyStr = identity.WireGuard.PublicKey
			} else if identity.WireGuard == nil {
				// Valid JSON without WireGuard identity (e.g. IKEv2-only); skip smoothly
				continue
			}
		}

		peerPublicKey, err := wgtypes.ParseKey(pubKeyStr)
		if err != nil {
			log.WithError(err).Warnf("Invalid Public Key for user %d", user.Id)
			continue
		}

		assignedIP := w.assignIP(user.Id)
		if assignedIP == "" {
			continue
		}

		peer := &WireGuardPeer{
			PublicKey: peerPublicKey,
			UID:       user.Id,
			UUID:      user.Uuid,
			IP:        assignedIP,
		}
		w.peers.Store(user.Uuid, peer)
		w.keyToPeer.Store(peerPublicKey.String(), peer)
		w.users.uuidToID[user.Uuid] = user.Id
		w.users.idToUUID[user.Id] = user.Uuid
		w.users.ipToUID[assignedIP] = user.Id
		RegisterTunnelUser(assignedIP, user.Id, user.Uuid, w.Tag)

		batch = append(batch, pendingPeer{
			pubKey:     peerPublicKey.String(),
			assignedIP: assignedIP,
		})
	}

	const batchSize = 150
	var firstErr error
	for start := 0; start < len(batch); start += batchSize {
		end := start + batchSize
		if end > len(batch) {
			end = len(batch)
		}
		chunk := batch[start:end]
		if w.userspace != nil {
			var sb strings.Builder
			for _, p := range chunk {
				pk, err := wgtypes.ParseKey(p.pubKey)
				if err != nil {
					continue
				}
				sb.WriteString("public_key=")
				sb.WriteString(hex.EncodeToString(pk[:]))
				sb.WriteString("\nallowed_ip=")
				sb.WriteString(p.assignedIP)
				sb.WriteString("/32\npersistent_keepalive_interval=25\n")
			}
			if sb.Len() > 0 {
				if err := w.userspace.ipcSet(sb.String()); err != nil {
					log.WithError(err).Errorf("Failed to add AmneziaWG peer batch via userspace UAPI (%d peers)", len(chunk))
					if firstErr == nil {
						firstErr = err
					}
					continue
				}
			}
		} else {
			args := make([]string, 0, 2+len(chunk)*6)
			args = append(args, "set", w.InterfaceName)
			for _, p := range chunk {
				args = append(args, "peer", p.pubKey, "allowed-ips", p.assignedIP+"/32", "persistent-keepalive", "25")
			}
			if err := execCommandDirect("awg", args...); err != nil {
				log.WithError(err).Errorf("Failed to add AmneziaWG peer batch (%d peers)", len(chunk))
				if firstErr == nil {
					firstErr = err
				}
				continue
			}
		}
		if w.running.Load() && poolNet != nil {
			for _, p := range chunk {
				if parsedIP := net.ParseIP(p.assignedIP); parsedIP != nil && !poolNet.Contains(parsedIP) {
					_ = execCommand(fmt.Sprintf("ip route replace %s/32 dev %s", p.assignedIP, w.InterfaceName))
				}
			}
		}
	}

	log.WithFields(log.Fields{
		"tag":   w.Tag,
		"count": len(users),
	}).Info("AmneziaWG users added")
	return firstErr
}

// DelUsers removes users via batched `awg set` commands
func (w *AmneziaWGCore) DelUsers(users []panel.UserInfo) {
	w.users.mu.Lock()
	defer w.users.mu.Unlock()

	type ServiceIdentity struct {
		WireGuard *struct {
			PublicKey string `json:"public_key"`
		} `json:"wireguard,omitempty"`
	}

	var removeKeys []string
	var removedUIDs []int

	for _, user := range users {
		var pubKeyStr string
		if uuid, exists := w.users.idToUUID[user.Id]; exists {
			if peer, ok := w.peers.Load(uuid); ok {
				if wgPeer, ok := peer.(*WireGuardPeer); ok {
					pubKeyStr = wgPeer.PublicKey.String()
					if wgPeer.IP != "" {
						delete(w.users.ipToUID, wgPeer.IP)
						UnregisterTunnelUserIfTag(wgPeer.IP, w.Tag)
					}
					w.keyToPeer.Delete(pubKeyStr)
				}
			}
			w.peers.Delete(uuid)
			delete(w.users.uuidToID, uuid)
			delete(w.users.idToUUID, user.Id)
		}

		if pubKeyStr == "" && user.ServiceId != "" {
			pubKeyStr = user.ServiceId
			var identity ServiceIdentity
			if err := json.Unmarshal([]byte(user.ServiceId), &identity); err == nil && identity.WireGuard != nil {
				pubKeyStr = identity.WireGuard.PublicKey
			}
		}

		if _, err := wgtypes.ParseKey(pubKeyStr); err == nil {
			removeKeys = append(removeKeys, pubKeyStr)
		}
		removedUIDs = append(removedUIDs, user.Id)
	}

	if len(removeKeys) > 0 || len(removedUIDs) > 0 {
		w.trafficMu.Lock()
		for _, k := range removeKeys {
			delete(w.lastPeerStats, k)
		}
		for _, uid := range removedUIDs {
			delete(w.traffic, uid)
		}
		w.trafficMu.Unlock()
	}

	const batchSize = 200
	for start := 0; start < len(removeKeys); start += batchSize {
		end := start + batchSize
		if end > len(removeKeys) {
			end = len(removeKeys)
		}
		chunk := removeKeys[start:end]
		if w.userspace != nil {
			var sb strings.Builder
			for _, k := range chunk {
				pk, err := wgtypes.ParseKey(k)
				if err != nil {
					continue
				}
				sb.WriteString("public_key=")
				sb.WriteString(hex.EncodeToString(pk[:]))
				sb.WriteString("\nremove=true\n")
			}
			if sb.Len() > 0 {
				_ = w.userspace.ipcSet(sb.String())
			}
		} else {
			args := make([]string, 0, 2+len(chunk)*3)
			args = append(args, "set", w.InterfaceName)
			for _, k := range chunk {
				args = append(args, "peer", k, "remove")
			}
			_ = execCommandDirect("awg", args...)
		}
	}

	log.WithFields(log.Fields{
		"tag":   w.Tag,
		"count": len(users),
	}).Info("AmneziaWG users removed")
}

// uapiKeyToHex decodes a base64 WireGuard/AmneziaWG key (or accepts 64-char hex) and returns lowercase hex.
func uapiKeyToHex(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if len(s) == 64 {
		if b, err := hex.DecodeString(s); err == nil && len(b) == 32 {
			return strings.ToLower(s), nil
		}
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(b) != 32 {
		return "", fmt.Errorf("invalid 32-byte key")
	}
	return hex.EncodeToString(b), nil
}

func (w *AmneziaWGCore) buildUAPIDeviceConfig() (string, error) {
	var sb strings.Builder
	sb.WriteString("private_key=")
	sb.WriteString(hex.EncodeToString(w.PrivateKey[:]))
	sb.WriteByte('\n')
	sb.WriteString("listen_port=")
	sb.WriteString(strconv.Itoa(w.Port))
	sb.WriteByte('\n')

	if w.Jc > 0 {
		sb.WriteString("jc=")
		sb.WriteString(strconv.Itoa(w.Jc))
		sb.WriteByte('\n')
	}
	if w.Jmin > 0 {
		sb.WriteString("jmin=")
		sb.WriteString(strconv.Itoa(w.Jmin))
		sb.WriteByte('\n')
	}
	if w.Jmax > 0 {
		sb.WriteString("jmax=")
		sb.WriteString(strconv.Itoa(w.Jmax))
		sb.WriteByte('\n')
	}
	if w.S1 > 0 {
		sb.WriteString("s1=")
		sb.WriteString(strconv.Itoa(w.S1))
		sb.WriteByte('\n')
	}
	if w.S2 > 0 {
		sb.WriteString("s2=")
		sb.WriteString(strconv.Itoa(w.S2))
		sb.WriteByte('\n')
	}
	if w.S3 > 0 {
		sb.WriteString("s3=")
		sb.WriteString(strconv.Itoa(w.S3))
		sb.WriteByte('\n')
	}
	if w.S4 > 0 {
		sb.WriteString("s4=")
		sb.WriteString(strconv.Itoa(w.S4))
		sb.WriteByte('\n')
	}
	if w.H1 != "" {
		sb.WriteString("h1=")
		sb.WriteString(w.H1)
		sb.WriteByte('\n')
	}
	if w.H2 != "" {
		sb.WriteString("h2=")
		sb.WriteString(w.H2)
		sb.WriteByte('\n')
	}
	if w.H3 != "" {
		sb.WriteString("h3=")
		sb.WriteString(w.H3)
		sb.WriteByte('\n')
	}
	if w.H4 != "" {
		sb.WriteString("h4=")
		sb.WriteString(w.H4)
		sb.WriteByte('\n')
	}
	if w.I1 != "" {
		sb.WriteString("i1=")
		sb.WriteString(w.I1)
		sb.WriteByte('\n')
	}
	if w.I2 != "" {
		sb.WriteString("i2=")
		sb.WriteString(w.I2)
		sb.WriteByte('\n')
	}
	if w.I3 != "" {
		sb.WriteString("i3=")
		sb.WriteString(w.I3)
		sb.WriteByte('\n')
	}
	if w.I4 != "" {
		sb.WriteString("i4=")
		sb.WriteString(w.I4)
		sb.WriteByte('\n')
	}
	if w.I5 != "" {
		sb.WriteString("i5=")
		sb.WriteString(w.I5)
		sb.WriteByte('\n')
	}
	if w.HeaderProtectionKey != "" {
		hexHPK, err := uapiKeyToHex(w.HeaderProtectionKey)
		if err != nil {
			return "", fmt.Errorf("invalid header protection key: %w", err)
		}
		sb.WriteString("header_protection_key=")
		sb.WriteString(hexHPK)
		sb.WriteByte('\n')
	}
	if w.ContentPaddingAddition != "" {
		sb.WriteString("content_padding_addition=")
		sb.WriteString(w.ContentPaddingAddition)
		sb.WriteByte('\n')
	}
	if w.RekeyAfterTime != "" {
		sb.WriteString("rekey_after_time=")
		sb.WriteString(w.RekeyAfterTime)
		sb.WriteByte('\n')
	}
	if w.RekeyTimeout != "" {
		sb.WriteString("rekey_timeout=")
		sb.WriteString(w.RekeyTimeout)
		sb.WriteByte('\n')
	}
	if w.RejectAfterTime != "" {
		sb.WriteString("reject_after_time=")
		sb.WriteString(w.RejectAfterTime)
		sb.WriteByte('\n')
	}
	if w.KeepaliveTimeout != "" {
		sb.WriteString("keepalive_timeout=")
		sb.WriteString(w.KeepaliveTimeout)
		sb.WriteByte('\n')
	}
	if w.MaxHandshakeAttempts != "" {
		sb.WriteString("max_handshake_attempts=")
		sb.WriteString(w.MaxHandshakeAttempts)
		sb.WriteByte('\n')
	}
	if w.RandomTrailers {
		sb.WriteString("random_trailers=true\n")
	}
	if w.DisableCookies {
		sb.WriteString("disable_cookies=true\n")
	}
	return sb.String(), nil
}

// configureInterface configures params using awg command or in-process UAPI
func (w *AmneziaWGCore) configureInterface() error {
	if w.userspace != nil {
		uapiConf, err := w.buildUAPIDeviceConfig()
		if err != nil {
			return err
		}
		if err := w.userspace.ipcSet(uapiConf); err != nil {
			return fmt.Errorf("failed to configure userspace amneziawg-go device: %w", err)
		}
		if err := w.userspace.up(); err != nil {
			return fmt.Errorf("failed to bring up userspace amneziawg-go device: %w", err)
		}
	} else {
		// 1. Set basic config (listen-port and private-key)
		cmd := fmt.Sprintf("echo %s | awg set %s listen-port %d private-key /dev/stdin", w.PrivateKey.String(), w.InterfaceName, w.Port)
		if err := execShellCommand(cmd); err != nil {
			return fmt.Errorf("failed to set basic config: %w", err)
		}

		// 2. Prepare HeaderProtectionKey file if configured
		var hpkFile string
		if w.HeaderProtectionKey != "" {
			tmp, err := os.CreateTemp("", fmt.Sprintf("awg_hpk_%s_*", w.InterfaceName))
			if err != nil {
				return fmt.Errorf("failed to create temporary header protection key file: %w", err)
			}
			hpkFile = tmp.Name()
			_ = os.Chmod(hpkFile, 0600)
			if _, err := tmp.WriteString(strings.TrimSpace(w.HeaderProtectionKey) + "\n"); err != nil {
				_ = tmp.Close()
				_ = os.Remove(hpkFile)
				return fmt.Errorf("failed to write header protection key: %w", err)
			}
			_ = tmp.Close()
			defer os.Remove(hpkFile)
		}

		// 3. Set Amnezia 3.1 parameters directly via exec (avoids shell redirection issues with CPS tags)
		var args []string
		args = append(args, w.InterfaceName)

		if w.Jc > 0 {
			args = append(args, "jc", strconv.Itoa(w.Jc))
		}
		if w.Jmin > 0 {
			args = append(args, "jmin", strconv.Itoa(w.Jmin))
		}
		if w.Jmax > 0 {
			args = append(args, "jmax", strconv.Itoa(w.Jmax))
		}
		if w.S1 > 0 {
			args = append(args, "s1", strconv.Itoa(w.S1))
		}
		if w.S2 > 0 {
			args = append(args, "s2", strconv.Itoa(w.S2))
		}
		if w.S3 > 0 {
			args = append(args, "s3", strconv.Itoa(w.S3))
		}
		if w.S4 > 0 {
			args = append(args, "s4", strconv.Itoa(w.S4))
		}
		if w.H1 != "" {
			args = append(args, "h1", w.H1)
		}
		if w.H2 != "" {
			args = append(args, "h2", w.H2)
		}
		if w.H3 != "" {
			args = append(args, "h3", w.H3)
		}
		if w.H4 != "" {
			args = append(args, "h4", w.H4)
		}
		if w.I1 != "" {
			args = append(args, "i1", w.I1)
		}
		if w.I2 != "" {
			args = append(args, "i2", w.I2)
		}
		if w.I3 != "" {
			args = append(args, "i3", w.I3)
		}
		if w.I4 != "" {
			args = append(args, "i4", w.I4)
		}
		if w.I5 != "" {
			args = append(args, "i5", w.I5)
		}
		if hpkFile != "" {
			args = append(args, "header-protection-key", hpkFile)
		}
		if w.ContentPaddingAddition != "" {
			args = append(args, "content-padding-addition", w.ContentPaddingAddition)
		}
		if w.RekeyAfterTime != "" {
			args = append(args, "rekey-after-time", w.RekeyAfterTime)
		}
		if w.RekeyTimeout != "" {
			args = append(args, "rekey-timeout", w.RekeyTimeout)
		}
		if w.RejectAfterTime != "" {
			args = append(args, "reject-after-time", w.RejectAfterTime)
		}
		if w.KeepaliveTimeout != "" {
			args = append(args, "keepalive-timeout", w.KeepaliveTimeout)
		}
		if w.MaxHandshakeAttempts != "" {
			args = append(args, "max-handshake-attempts", w.MaxHandshakeAttempts)
		}
		if w.RandomTrailers {
			args = append(args, "random-trailers", "on")
		}
		if w.DisableCookies {
			args = append(args, "disable-cookies", "on")
		}

		if len(args) > 1 {
			if err := execCommandDirect("awg", append([]string{"set"}, args...)...); err != nil {
				return fmt.Errorf("failed to set amnezia params: %w", err)
			}
		}
	}

	// 4. Set IP
	cmd := fmt.Sprintf("ip addr add %s dev %s", w.Address, w.InterfaceName)
	if err := execCommand(cmd); err != nil {
		return fmt.Errorf("failed to assign IP: %w", err)
	}

	// 5. Up
	cmd = fmt.Sprintf("ip link set %s up", w.InterfaceName)
	if err := execCommand(cmd); err != nil {
		return fmt.Errorf("failed to up interface: %w", err)
	}

	// Ensure the full allocatable pool subnet is routed through this interface
	poolSubnet := getPoolSubnet(w.Address)
	_ = execCommand(fmt.Sprintf("ip route replace %s dev %s", poolSubnet, w.InterfaceName))

	return nil
}

func (w *AmneziaWGCore) createInterface() error {
	_ = execCommand(fmt.Sprintf("ip link delete %s", w.InterfaceName))

	// Prefer kernel module when available and `awg` CLI is present;
	// otherwise seamlessly fall back to the embedded userspace amneziawg-go engine.
	_ = execCommand("modprobe amneziawg")
	cmd := fmt.Sprintf("ip link add %s type amneziawg", w.InterfaceName)
	if err := execCommand(cmd); err == nil {
		if _, lookErr := exec.LookPath("awg"); lookErr == nil {
			w.userspace = nil
		} else {
			log.WithField("interface", w.InterfaceName).
				Warn("AmneziaWG kernel module loaded, but 'awg' CLI not found; falling back to embedded userspace engine")
			_ = execCommand(fmt.Sprintf("ip link delete %s", w.InterfaceName))
			u, uErr := createAWGUserspace(w.InterfaceName, w.MTU)
			if uErr != nil {
				return fmt.Errorf("failed to start embedded amneziawg-go userspace fallback: %w", uErr)
			}
			w.userspace = u
		}
	} else {
		log.WithFields(log.Fields{
			"interface": w.InterfaceName,
			"kernelErr": err.Error(),
		}).Info("AmneziaWG kernel module unavailable, starting embedded userspace amneziawg-go engine")
		u, uErr := createAWGUserspace(w.InterfaceName, w.MTU)
		if uErr != nil {
			return fmt.Errorf("failed to create interface via kernel (%v) and userspace amneziawg-go (%v)", err, uErr)
		}
		w.userspace = u
	}

	if err := execCommand("sysctl -w net.ipv4.ip_forward=1"); err != nil {
		log.WithError(err).Warn("Failed to enable IP forwarding")
	}

	cmd = fmt.Sprintf("ip link set %s mtu %d", w.InterfaceName, w.MTU)
	if err := execCommand(cmd); err != nil {
		_ = w.deleteInterface()
		return fmt.Errorf("failed to set MTU: %w", err)
	}

	return nil
}

func (w *AmneziaWGCore) deleteInterface() error {
	if w.userspace != nil {
		w.userspace.close()
		w.userspace = nil
	}
	cmd := fmt.Sprintf("ip link delete %s", w.InterfaceName)
	return execCommand(cmd)
}

func execShellCommand(cmd string) error {
	command := exec.Command("sh", "-c", cmd)
	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("command failed: %s, output: %s", err, string(output))
	}
	return nil
}

func execCommandDirect(name string, args ...string) error {
	execMu.Lock()
	defer execMu.Unlock()

	command := exec.Command(name, args...)
	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("command failed: %s %v, output: %s", name, args, string(output))
	}
	return nil
}

// Stats collection - need to parse `awg show <iface> dump` output
type amneziaStatsCollectorTask struct {
	core     *AmneziaWGCore
	stopChan chan struct{}
	wg       sync.WaitGroup
}

func (t *amneziaStatsCollectorTask) start() {
	t.wg.Add(1)
	go t.run()
}

func (t *amneziaStatsCollectorTask) stop() {
	close(t.stopChan)
	t.wg.Wait()
}

func (t *amneziaStatsCollectorTask) run() {
	defer t.wg.Done()
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-t.stopChan:
			return
		case <-ticker.C:
			if t.core.running.Load() {
				t.core.collectStats()
			}
		}
	}
}

// uapiGetToDump converts UAPI `IpcGet()` key=value lines into `awg show <iface> dump` tab-separated lines.
func uapiGetToDump(uapiOut string) string {
	type peerBlock struct {
		pubKey    string
		endpoint  string
		allowed   []string
		handshake string
		rx        string
		tx        string
		keepalive string
	}

	var cur *peerBlock
	var sb strings.Builder
	flush := func() {
		if cur == nil || cur.pubKey == "" {
			return
		}
		ep := cur.endpoint
		if ep == "" {
			ep = "(none)"
		}
		allowed := "(none)"
		if len(cur.allowed) > 0 {
			allowed = strings.Join(cur.allowed, ",")
		}
		hs := cur.handshake
		if hs == "" {
			hs = "0"
		}
		rx := cur.rx
		if rx == "" {
			rx = "0"
		}
		tx := cur.tx
		if tx == "" {
			tx = "0"
		}
		ka := cur.keepalive
		if ka == "" {
			ka = "0"
		}
		sb.WriteString(cur.pubKey)
		sb.WriteString("\t(none)\t")
		sb.WriteString(ep)
		sb.WriteByte('\t')
		sb.WriteString(allowed)
		sb.WriteByte('\t')
		sb.WriteString(hs)
		sb.WriteByte('\t')
		sb.WriteString(rx)
		sb.WriteByte('\t')
		sb.WriteString(tx)
		sb.WriteByte('\t')
		sb.WriteString(ka)
		sb.WriteByte('\n')
	}

	for _, line := range strings.Split(uapiOut, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		if k == "public_key" {
			flush()
			cur = &peerBlock{}
			if b, err := hex.DecodeString(v); err == nil && len(b) == 32 {
				if key, err := wgtypes.NewKey(b); err == nil {
					cur.pubKey = key.String()
				}
			}
			continue
		}
		if cur == nil {
			continue
		}
		switch k {
		case "endpoint":
			cur.endpoint = v
		case "allowed_ip":
			cur.allowed = append(cur.allowed, v)
		case "last_handshake_time_sec":
			cur.handshake = v
		case "rx_bytes":
			cur.rx = v
		case "tx_bytes":
			cur.tx = v
		case "persistent_keepalive_interval":
			cur.keepalive = v
		}
	}
	flush()
	return sb.String()
}

func (w *AmneziaWGCore) getDumpOutput() (string, error) {
	if w.userspace != nil {
		raw, err := w.userspace.ipcGet()
		if err != nil {
			return "", err
		}
		return uapiGetToDump(raw), nil
	}
	cmd := exec.Command("awg", "show", w.InterfaceName, "dump")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", err
	}
	return string(output), nil
}

func (w *AmneziaWGCore) collectStats() {
	// Parse `awg show <iface> dump` (or equivalent UAPI output in userspace mode)
	// Output format: publicKey, preSharedKey, endpoint, allowedIPs, latestHandshake, transferRx, transferTx, persistentKeepalive
	output, err := w.getDumpOutput()
	if err != nil {
		return
	}

	lines := strings.Split(output, "\n")
	w.trafficMu.Lock()
	var newlyActive bool

	for _, line := range lines {
		parts := strings.Fields(line)
		if len(parts) < 8 {
			continue
		}

		pubKey := parts[0]
		rxStr := parts[5]
		txStr := parts[6]
		handshakeStr := parts[4] // Unix timestamp

		rx, _ := strconv.ParseInt(rxStr, 10, 64)
		tx, _ := strconv.ParseInt(txStr, 10, 64)
		handshake, _ := strconv.ParseInt(handshakeStr, 10, 64)

		// Find user by public key in O(1) time
		var uid int
		var assignedIP string
		if val, ok := w.keyToPeer.Load(pubKey); ok {
			peer := val.(*WireGuardPeer)
			uid = peer.UID
			assignedIP = peer.IP
		}

		if uid == 0 {
			continue
		}

		rawEndpoint := parts[2]
		clientEndpointIP := ""
		if rawEndpoint != "" && rawEndpoint != "(none)" && assignedIP != "" {
			if host, _, err := net.SplitHostPort(rawEndpoint); err == nil && host != "" {
				clientEndpointIP = strings.TrimPrefix(host, "::ffff:")
				UpdateTunnelUserEndpoint(assignedIP, clientEndpointIP)
			}
		}

		peerKey := pubKey
		lastStats, exists := w.lastPeerStats[peerKey]
		if !exists {
			lastStats = &peerStats{}
			w.lastPeerStats[peerKey] = lastStats
		}

		downloadDelta := rx - lastStats.ReceiveBytes
		uploadDelta := tx - lastStats.TransmitBytes

		if downloadDelta < 0 {
			downloadDelta = rx
		} // Handle restarts
		if uploadDelta < 0 {
			uploadDelta = tx
		}

		if downloadDelta+uploadDelta > 8192 {
			if lastStats.LastDataTime.IsZero() || time.Since(lastStats.LastDataTime) > wgOnlineActiveWindow {
				newlyActive = true
			}
			lastStats.LastDataTime = time.Now()
		}

		lastStats.ReceiveBytes = rx
		lastStats.TransmitBytes = tx

		lastHandshakeTime := time.Unix(handshake, 0)

		if lastHandshakeTime.After(lastStats.LastHandshake) {
			if lastStats.LastHandshake.IsZero() || time.Since(lastStats.LastHandshake) > wgOnlineActiveWindow {
				log.WithFields(log.Fields{
					"uid":       uid,
					"ip":        assignedIP,
					"client_ip": clientEndpointIP,
				}).Info("AmneziaWG peer connected")
			}
			lastStats.LastHandshake = lastHandshakeTime
		}

		if w.traffic[uid] == nil {
			w.traffic[uid] = &UserTraffic{}
		}
		w.traffic[uid].Download += downloadDelta
		w.traffic[uid].Upload += uploadDelta
	}
	w.trafficMu.Unlock()

	if newlyActive && w.OnPeerActive != nil {
		go w.OnPeerActive()
	}
}

// GetTrafficAndReset returns traffic stats and resets counters
func (w *AmneziaWGCore) GetTrafficAndReset() map[int]*UserTraffic {
	w.collectStats()

	w.trafficMu.Lock()
	defer w.trafficMu.Unlock()

	result := w.traffic
	w.traffic = make(map[int]*UserTraffic)
	return result
}

// parseAWGDumpOnlinePeers extracts currently active peers from `awg show <iface> dump`
// requiring both a recent handshake and real payload traffic within wgOnlineActiveWindow.
func parseAWGDumpOnlinePeers(
	output string,
	lastPeerStats map[string]*peerStats,
	keyToPeer *sync.Map,
	now time.Time,
) []panel.OnlineUser {
	var online []panel.OnlineUser
	recentThreshold := now.Add(-wgOnlineActiveWindow)

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		parts := strings.Fields(line)
		if len(parts) < 8 {
			continue
		}

		pubKey := parts[0]
		handshakeStr := parts[4]
		handshake, _ := strconv.ParseInt(handshakeStr, 10, 64)
		lastHandshakeTime := time.Unix(handshake, 0)

		if lastHandshakeTime.Before(recentThreshold) {
			continue
		}

		st, hasStats := lastPeerStats[pubKey]
		if !hasStats || st.LastDataTime.Before(recentThreshold) {
			continue
		}

		rawEndpoint := parts[2]
		clientIP := ""
		if rawEndpoint != "" && rawEndpoint != "(none)" {
			if host, _, err := net.SplitHostPort(rawEndpoint); err == nil && host != "" {
				clientIP = strings.TrimPrefix(host, "::ffff:")
			}
		}
		if clientIP == "" {
			continue
		}

		if val, ok := keyToPeer.Load(pubKey); ok {
			peer := val.(*WireGuardPeer)
			online = append(online, panel.OnlineUser{
				UID: peer.UID,
				IP:  clientIP,
			})
		}
	}
	return online
}

// GetOnlineUsers returns list of currently connected users
func (w *AmneziaWGCore) GetOnlineUsers() []panel.OnlineUser {
	output, err := w.getDumpOutput()
	if err != nil {
		return nil
	}

	w.trafficMu.RLock()
	defer w.trafficMu.RUnlock()

	return parseAWGDumpOnlinePeers(output, w.lastPeerStats, &w.keyToPeer, time.Now())
}

func (w *AmneziaWGCore) SetLimiter(l *limiter.Limiter) {
	w.limiterRef = l
}

func (w *AmneziaWGCore) assignIP(id int) string {
	if id <= 0 {
		return ""
	}
	first := strings.TrimSpace(strings.Split(w.Address, ",")[0])
	baseIP, ipnet, err := net.ParseCIDR(first)
	if err != nil {
		baseIP = net.ParseIP(first)
	}
	if baseIP == nil {
		baseIP = net.ParseIP("10.0.0.1")
	}
	baseIP = baseIP.To4()
	if baseIP == nil {
		return ""
	}

	prefix := 16
	if ipnet != nil && ipnet.Mask != nil {
		if ones, bits := ipnet.Mask.Size(); bits == 32 && ones > 0 {
			prefix = ones
		}
	}

	subId := int64(id)
	// Legacy 10.0.x.x expansion: 10.0.0.0/13 covering 10.0 - 10.7 (260,096 subscribers)
	if baseIP[0] == 10 && baseIP[1] == 0 {
		const hostCount = 8 * 256 * 127
		slot := (subId - 1) % hostCount
		dIndex := slot % 127
		upper := slot / 127
		cOffset := upper % 256
		bOffset := upper / 256
		byteD := int(dIndex*2) + 2
		return fmt.Sprintf("10.%d.%d.%d", bOffset, cOffset, byteD)
	}

	// For /24 or smaller: only byte 3 varies
	if prefix >= 24 {
		slot := (subId - 1) % 127
		byteD := int(slot*2) + 2
		return fmt.Sprintf("%d.%d.%d.%d", baseIP[0], baseIP[1], baseIP[2], byteD)
	}

	// For /16 .. /23: bound bOffset within prefix host space
	bShift := 16 - prefix
	if bShift < 0 {
		bShift = 0
	}
	bBlocks := int64(1 << bShift)
	hostCount := bBlocks * 256 * 127

	slot := (subId - 1) % hostCount
	dIndex := slot % 127
	upper := slot / 127
	cOffset := upper % 256
	bOffset := (upper / 256) % bBlocks
	byteD := int(dIndex*2) + 2

	return fmt.Sprintf("%d.%d.%d.%d", baseIP[0], int(baseIP[1])+int(bOffset), cOffset, byteD)
}

func (w *AmneziaWGCore) setupNAT() error {
	if err := execCommand("sysctl -w net.ipv4.ip_forward=1"); err != nil {
		log.WithError(err).Warn("Failed to enable IP forwarding")
	}

	subnet := getPoolSubnet(w.Address)

	defaultIface, err := getDefaultInterface()
	if err != nil {
		log.WithError(err).Warn("Failed to get default interface, defaulting to eth0")
		defaultIface = "eth0"
	}

	// Always add FORWARD ACCEPT rules for the AWG interface (needed in both paths)
	// Use -I 1 so they are placed before any UFW or firewall DROP rules
	if err := execCommand(fmt.Sprintf("iptables -w 5 -C FORWARD -i %s -j ACCEPT", w.InterfaceName)); err != nil {
		if err := execCommand(fmt.Sprintf("iptables -w 5 -I FORWARD 1 -i %s -j ACCEPT", w.InterfaceName)); err != nil {
			log.WithError(err).Warn("Failed to add FORWARD input rule for AmneziaWG")
		}
	}
	if err := execCommand(fmt.Sprintf("iptables -w 5 -C FORWARD -o %s -j ACCEPT", w.InterfaceName)); err != nil {
		if err := execCommand(fmt.Sprintf("iptables -w 5 -I FORWARD 1 -o %s -j ACCEPT", w.InterfaceName)); err != nil {
			log.WithError(err).Warn("Failed to add FORWARD output rule for AmneziaWG")
		}
	}
	// Always add INPUT ACCEPT rule for the AWG interface (needed for local DNS like Technitium on 10.0.0.1:53)
	// Use -I INPUT 1 so it takes precedence over UFW/default DROP rules
	if err := execCommand(fmt.Sprintf("iptables -w 5 -C INPUT -i %s -j ACCEPT", w.InterfaceName)); err != nil {
		if err := execCommand(fmt.Sprintf("iptables -w 5 -I INPUT 1 -i %s -j ACCEPT", w.InterfaceName)); err != nil {
			log.WithError(err).Warn("Failed to add INPUT rule for AmneziaWG")
		}
	}

	tcpmss := w.MTU - 80
	if tcpmss <= 0 {
		tcpmss = 1240
	}

	// Always add TCPMSS clamping rules to prevent MTU blackholing:
	// 1. In PREROUTING so incoming TCP SYN packets are clamped BEFORE TProxy redirects them to Xray!
	if err := execCommand(fmt.Sprintf("iptables -w 5 -t mangle -C PREROUTING -i %s -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss %d", w.InterfaceName, tcpmss)); err != nil {
		_ = execCommand(fmt.Sprintf("iptables -w 5 -t mangle -I PREROUTING 1 -i %s -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss %d", w.InterfaceName, tcpmss))
	}
	// 2. In FORWARD for kernel forwarded packets in both directions
	if err := execCommand(fmt.Sprintf("iptables -w 5 -t mangle -C FORWARD -i %s -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss %d", w.InterfaceName, tcpmss)); err != nil {
		_ = execCommand(fmt.Sprintf("iptables -w 5 -t mangle -I FORWARD 1 -i %s -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss %d", w.InterfaceName, tcpmss))
	}
	if err := execCommand(fmt.Sprintf("iptables -w 5 -t mangle -C FORWARD -o %s -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss %d", w.InterfaceName, tcpmss)); err != nil {
		_ = execCommand(fmt.Sprintf("iptables -w 5 -t mangle -I FORWARD 1 -o %s -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss %d", w.InterfaceName, tcpmss))
	}

	// Drop ICMP Destination Unreachable if enabled (prevents game disconnects during radio fades)
	// Must be inserted at head of chain (index 1) BEFORE the ACCEPT rules so they take effect
	if w.DropICMPUnreachable {
		// Allow Path MTU Discovery (ICMP fragmentation-needed) so MTU detection doesn't blackhole
		if err := execCommand(fmt.Sprintf("iptables -w 5 -C FORWARD -i %s -p icmp --icmp-type fragmentation-needed -j ACCEPT", w.InterfaceName)); err != nil {
			_ = execCommand(fmt.Sprintf("iptables -w 5 -I FORWARD 1 -i %s -p icmp --icmp-type fragmentation-needed -j ACCEPT", w.InterfaceName))
		}
		if err := execCommand(fmt.Sprintf("iptables -w 5 -C FORWARD -o %s -p icmp --icmp-type fragmentation-needed -j ACCEPT", w.InterfaceName)); err != nil {
			_ = execCommand(fmt.Sprintf("iptables -w 5 -I FORWARD 1 -o %s -p icmp --icmp-type fragmentation-needed -j ACCEPT", w.InterfaceName))
		}

		if err := execCommand(fmt.Sprintf("iptables -w 5 -C FORWARD -i %s -p icmp --icmp-type port-unreachable -j DROP", w.InterfaceName)); err != nil {
			_ = execCommand(fmt.Sprintf("iptables -w 5 -A FORWARD -i %s -p icmp --icmp-type port-unreachable -j DROP", w.InterfaceName))
		}
		if err := execCommand(fmt.Sprintf("iptables -w 5 -C FORWARD -o %s -p icmp --icmp-type port-unreachable -j DROP", w.InterfaceName)); err != nil {
			_ = execCommand(fmt.Sprintf("iptables -w 5 -A FORWARD -o %s -p icmp --icmp-type port-unreachable -j DROP", w.InterfaceName))
		}
		if err := execCommand(fmt.Sprintf("iptables -w 5 -C OUTPUT -o %s -p icmp --icmp-type port-unreachable -j DROP", w.InterfaceName)); err != nil {
			_ = execCommand(fmt.Sprintf("iptables -w 5 -A OUTPUT -o %s -p icmp --icmp-type port-unreachable -j DROP", w.InterfaceName))
		}
	}

	tproxySubnet := w.TProxySubnet
	if tproxySubnet == "" { tproxySubnet = subnet }

	if w.TProxyPort > 0 {
		// Verify TPROXY module availability
		tproxyAvailable := execCommand("iptables -w 5 -t mangle -m TPROXY -h") == nil ||
			execCommand("modprobe xt_TPROXY") == nil

		if !tproxyAvailable {
			log.WithField("interface", w.InterfaceName).Warn(
				"TPROXY module not available, falling back to MASQUERADE for AmneziaWG NAT")
			w.TProxyPort = 0
			return w.setupMasquerade(subnet, defaultIface)
		}

		// Global IP rules & route
		ensureTProxyIpRule()

		chainName := fmt.Sprintf("XRAY_%s", w.InterfaceName)
		if err := execCommand(fmt.Sprintf("iptables -w 5 -t mangle -N %s", chainName)); err != nil {
			execCommand(fmt.Sprintf("iptables -w 5 -t mangle -F %s", chainName))
		}

		execCommand(fmt.Sprintf("iptables -w 5 -t mangle -A %s -d %s -j RETURN", chainName, tproxySubnet))
		if err := execCommand(fmt.Sprintf("iptables -w 5 -t mangle -A %s -p tcp -j TPROXY --on-port %d --tproxy-mark 1", chainName, w.TProxyPort)); err != nil {
			log.WithFields(log.Fields{
				"chain": chainName,
				"port":  w.TProxyPort,
				"err":   err,
			}).Error("Failed to add TPROXY TCP rule — AmneziaWG traffic will not be routed through Xray")
		}
		if !w.TProxyBypassUDP {
			if err := execCommand(fmt.Sprintf("iptables -w 5 -t mangle -A %s -p udp -j TPROXY --on-port %d --tproxy-mark 1", chainName, w.TProxyPort)); err != nil {
				log.WithFields(log.Fields{
					"chain": chainName,
					"port":  w.TProxyPort,
					"err":   err,
				}).Error("Failed to add TPROXY UDP rule — AmneziaWG traffic will not be routed through Xray")
			}
		} else {
			// Explicitly RETURN so UDP packets bypass mangle TPROXY and fall through to standard kernel MASQUERADE
			_ = execCommand(fmt.Sprintf("iptables -w 5 -t mangle -A %s -p udp -j RETURN", chainName))
		}

		checkCmd := fmt.Sprintf("iptables -w 5 -t mangle -C PREROUTING -i %s -j %s", w.InterfaceName, chainName)
		if err := execCommand(checkCmd); err != nil {
		 execCommand(fmt.Sprintf("iptables -w 5 -t mangle -A PREROUTING -i %s -j %s", w.InterfaceName, chainName))
		}

		// Add INPUT rule for TProxy marked packets (required when default INPUT policy is DROP/UFW)
		inputCheck := fmt.Sprintf("iptables -w 5 -C INPUT -i %s -s %s -m mark --mark 1 -j ACCEPT", w.InterfaceName, subnet)
		if err := execCommand(inputCheck); err != nil {
		 inputAdd := fmt.Sprintf("iptables -w 5 -I INPUT 1 -i %s -s %s -m mark --mark 1 -j ACCEPT", w.InterfaceName, subnet)
		 if err := execCommand(inputAdd); err != nil {
		  return fmt.Errorf("add AmneziaWG TProxy INPUT rule: %w", err)
		 }
		}

		// Also add MASQUERADE so Xray outbound traffic can reach external endpoints
		_ = w.setupMasquerade(subnet, defaultIface)
	} else {
		return w.setupMasquerade(subnet, defaultIface)
	}

	return nil
}

// setupMasquerade adds NAT MASQUERADE rules for the AWG subnet
func (w *AmneziaWGCore) setupMasquerade(subnet, defaultIface string) error {
	checkCmd := fmt.Sprintf("iptables -w 5 -t nat -C POSTROUTING -s %s -o %s -j MASQUERADE", subnet, defaultIface)
	if err := execCommand(checkCmd); err != nil {
		addCmd := fmt.Sprintf("iptables -w 5 -t nat -A POSTROUTING -s %s -o %s -j MASQUERADE", subnet, defaultIface)
		if err := execCommand(addCmd); err != nil {
			return fmt.Errorf("failed to add MASQUERADE rule: %w", err)
		}
	}
	return nil
}

func (w *AmneziaWGCore) teardownNAT() {
	subnet := getPoolSubnet(w.Address)
	tproxySubnet := w.TProxySubnet
	if tproxySubnet == "" {
		tproxySubnet = subnet
	}

	defaultIface, err := getDefaultInterface()
	if err != nil {
		defaultIface = "eth0"
	}

	tcpmss := w.MTU - 80
	if tcpmss <= 0 {
		tcpmss = 1240
	}

	_ = execCommand(fmt.Sprintf("iptables -w 5 -t mangle -D PREROUTING -i %s -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss %d", w.InterfaceName, tcpmss))
	_ = execCommand(fmt.Sprintf("iptables -w 5 -t mangle -D FORWARD -i %s -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss %d", w.InterfaceName, tcpmss))
	_ = execCommand(fmt.Sprintf("iptables -w 5 -t mangle -D FORWARD -o %s -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss %d", w.InterfaceName, tcpmss))

	// Always clean up FORWARD and INPUT rules (added in both paths)
	_ = execCommand(fmt.Sprintf("iptables -w 5 -D FORWARD -i %s -j ACCEPT", w.InterfaceName))
	_ = execCommand(fmt.Sprintf("iptables -w 5 -D FORWARD -o %s -j ACCEPT", w.InterfaceName))
	_ = execCommand(fmt.Sprintf("iptables -w 5 -D INPUT -i %s -j ACCEPT", w.InterfaceName))

	if w.DropICMPUnreachable {
		_ = execCommand(fmt.Sprintf("iptables -w 5 -D FORWARD -i %s -p icmp --icmp-type fragmentation-needed -j ACCEPT", w.InterfaceName))
		_ = execCommand(fmt.Sprintf("iptables -w 5 -D FORWARD -o %s -p icmp --icmp-type fragmentation-needed -j ACCEPT", w.InterfaceName))
		_ = execCommand(fmt.Sprintf("iptables -w 5 -D FORWARD -i %s -p icmp --icmp-type port-unreachable -j DROP", w.InterfaceName))
		_ = execCommand(fmt.Sprintf("iptables -w 5 -D FORWARD -o %s -p icmp --icmp-type port-unreachable -j DROP", w.InterfaceName))
		_ = execCommand(fmt.Sprintf("iptables -w 5 -D OUTPUT -o %s -p icmp --icmp-type port-unreachable -j DROP", w.InterfaceName))
	}

	// Always clean up MASQUERADE (added in both paths)
	if subnet != "" {
		_ = execCommand(fmt.Sprintf("iptables -w 5 -t nat -D POSTROUTING -s %s -o %s -j MASQUERADE", subnet, defaultIface))
	}

	if w.TProxyPort > 0 {
		_ = execCommand(fmt.Sprintf("iptables -w 5 -D INPUT -i %s -s %s -m mark --mark 1 -j ACCEPT", w.InterfaceName, subnet))
		_ = execCommand(fmt.Sprintf("iptables -w 5 -D INPUT -i %s -s %s -m mark --mark 1 -j ACCEPT", w.InterfaceName, tproxySubnet))
		chainName := fmt.Sprintf("XRAY_%s", w.InterfaceName)
		_ = execCommand(fmt.Sprintf("iptables -w 5 -t mangle -D PREROUTING -i %s -j %s", w.InterfaceName, chainName))
		_ = execCommand(fmt.Sprintf("iptables -w 5 -t mangle -F %s", chainName))
		_ = execCommand(fmt.Sprintf("iptables -w 5 -t mangle -X %s", chainName))
	}
}

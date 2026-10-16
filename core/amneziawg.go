//go:build !freebsd

package core

import (
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
	users      *WGUserMap
	limiterRef *limiter.Limiter
	running    atomic.Bool

	// Traffic accounting
	trafficMu      sync.RWMutex
	traffic        map[int]*UserTraffic // key: uid
	lastPeerStats  map[string]*peerStats
	statsCollector *amneziaStatsCollectorTask
	TProxyPort          int
	TProxySubnet        string
	TProxyBypassUDP     bool
	DropICMPUnreachable bool
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
		mtu = 1420
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

// AddUsers adds users via `awg set` command
func (w *AmneziaWGCore) AddUsers(users []panel.UserInfo) {
	w.users.mu.Lock()
	defer w.users.mu.Unlock()

	// ... similar user parsing logic as WireGuard ...
	// Since we are using awg command, we likely need to build a large command line or write to a temp file
	// Writing a config file /tmp/awg_peers.conf and using `awg setconf` or `awg addconf` might be safer/easier
	// `awg set <iface> peer <key> allowed-ips <ips>`

	for _, user := range users {
		// ... parsing logic ...
		if user.ServiceId == "" {
			continue
		}
		// ... json parse ...
		pubKeyStr := user.ServiceId // simplified

		// Parse struct from ServiceId if JSON
		type ServiceIdentity struct {
			WireGuard *struct {
				PublicKey string `json:"public_key"`
			} `json:"wireguard,omitempty"`
		}
		var identity ServiceIdentity
		if err := json.Unmarshal([]byte(user.ServiceId), &identity); err == nil && identity.WireGuard != nil {
			pubKeyStr = identity.WireGuard.PublicKey
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

		// Add to internal maps
		peer := &WireGuardPeer{
			PublicKey: peerPublicKey,
			UID:       user.Id,
			UUID:      user.Uuid,
			IP:        assignedIP,
		}
		w.peers.Store(user.Uuid, peer)
		w.users.uuidToID[user.Uuid] = user.Id
		w.users.idToUUID[user.Id] = user.Uuid
		w.users.ipToUID[assignedIP] = user.Id
		RegisterTunnelUser(assignedIP, user.Id, user.Uuid, w.Tag)

		// Execute awg command
		// awg set <iface> peer <key> allowed-ips <ip>/32
		cmd := fmt.Sprintf("awg set %s peer %s allowed-ips %s/32", w.InterfaceName, peerPublicKey.String(), assignedIP)
		if err := execCommand(cmd); err != nil {
			log.WithError(err).Errorf("Failed to add peer %s", user.Uuid)
		}
	}

	log.WithFields(log.Fields{
		"tag":   w.Tag,
		"count": len(users),
	}).Info("AmneziaWG users added")
}

// DelUsers removes users
func (w *AmneziaWGCore) DelUsers(users []panel.UserInfo) {
	w.users.mu.Lock()
	defer w.users.mu.Unlock()

	for _, user := range users {
		var pubKeyStr string
		// Try to find the peer public key from our maps if possible, or parse from user
		// But usually we need the public key to remove the peer

		// Best effort: parse from user struct again
		pubKeyStr = user.ServiceId
		// ... (json parse logic) ...
		type ServiceIdentity struct {
			WireGuard *struct {
				PublicKey string `json:"public_key"`
			} `json:"wireguard,omitempty"`
		}
		var identity ServiceIdentity
		if err := json.Unmarshal([]byte(user.ServiceId), &identity); err == nil && identity.WireGuard != nil {
			pubKeyStr = identity.WireGuard.PublicKey
		}

		if uuid, exists := w.users.idToUUID[user.Id]; exists {
			if peer, ok := w.peers.Load(uuid); ok {
				if wgPeer, ok := peer.(*WireGuardPeer); ok && wgPeer.IP != "" {
					delete(w.users.ipToUID, wgPeer.IP)
					UnregisterTunnelUser(wgPeer.IP)
				}
			}
			w.peers.Delete(uuid)
			delete(w.users.uuidToID, uuid)
			delete(w.users.idToUUID, user.Id)
		}

		// Execute awg command
		// awg set <iface> peer <key> remove
		cmd := fmt.Sprintf("awg set %s peer %s remove", w.InterfaceName, pubKeyStr)
		// Ignore error as peer might not exist
		_ = execCommand(cmd)
	}

	log.WithFields(log.Fields{
		"tag":   w.Tag,
		"count": len(users),
	}).Info("AmneziaWG users removed")
}

// configureInterface configures params using awg command
func (w *AmneziaWGCore) configureInterface() error {
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

	// 3. Set IP
	cmd = fmt.Sprintf("ip addr add %s dev %s", w.Address, w.InterfaceName)
	if err := execCommand(cmd); err != nil {
		return fmt.Errorf("failed to assign IP: %w", err)
	}

	// 4. Up
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

	// Check if amneziawg module is loaded?
	// Just try to create
	cmd := fmt.Sprintf("ip link add %s type amneziawg", w.InterfaceName)
	if err := execCommand(cmd); err != nil {
		return fmt.Errorf("failed to create interface (is amneziawg module installed?): %w", err)
	}

	if err := execCommand("sysctl -w net.ipv4.ip_forward=1"); err != nil {
		log.WithError(err).Warn("Failed to enable IP forwarding")
	}

	cmd = fmt.Sprintf("ip link set %s mtu %d", w.InterfaceName, w.MTU)
	if err := execCommand(cmd); err != nil {
		return fmt.Errorf("failed to set MTU: %w", err)
	}

	return nil
}

func (w *AmneziaWGCore) deleteInterface() error {
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

func (w *AmneziaWGCore) collectStats() {
	// Parse `awg show <iface> dump`
	// Output format: publicKey, preSharedKey, endpoint, allowedIPs, latestHandshake, transferRx, transferTx, persistentKeepalive
	cmd := exec.Command("awg", "show", w.InterfaceName, "dump")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return
	}

	lines := strings.Split(string(output), "\n")
	w.trafficMu.Lock()
	defer w.trafficMu.Unlock()

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

		// Find user by public key
		var uid int
		var assignedIP string
		w.peers.Range(func(key, value interface{}) bool {
			peer := value.(*WireGuardPeer)
			if peer.PublicKey.String() == pubKey {
				uid = peer.UID
				assignedIP = peer.IP
				return false
			}
			return true
		})

		if uid == 0 {
			continue
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
			downloadDelta = 0
		} // Handle restarts
		if uploadDelta < 0 {
			uploadDelta = 0
		}

		lastStats.ReceiveBytes = rx
		lastStats.TransmitBytes = tx

		lastHandshakeTime := time.Unix(handshake, 0)

		if lastHandshakeTime.After(lastStats.LastHandshake) {
			if lastStats.LastHandshake.IsZero() || time.Since(lastStats.LastHandshake) > 3*time.Minute {
				log.WithFields(log.Fields{
					"uid": uid,
					"ip":  assignedIP,
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
}

// GetTrafficAndReset returns traffic stats and resets counters
func (w *AmneziaWGCore) GetTrafficAndReset() map[int]*UserTraffic {
	w.trafficMu.Lock()
	defer w.trafficMu.Unlock()

	result := w.traffic
	w.traffic = make(map[int]*UserTraffic)
	return result
}

// GetOnlineUsers returns list of currently connected users
func (w *AmneziaWGCore) GetOnlineUsers() []panel.OnlineUser {
	// Parse `awg show <iface> dump` again to find active peers
	cmd := exec.Command("awg", "show", w.InterfaceName, "dump")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil
	}

	var online []panel.OnlineUser
	recentThreshold := time.Now().Add(-3 * time.Minute)

	lines := strings.Split(string(output), "\n")
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

		// Find user
		w.peers.Range(func(key, value interface{}) bool {
			peer := value.(*WireGuardPeer)
			if peer.PublicKey.String() == pubKey {
				online = append(online, panel.OnlineUser{
					UID: peer.UID,
					IP:  peer.IP,
				})
				return false
			}
			return true
		})
	}
	return online
}

func (w *AmneziaWGCore) SetLimiter(l *limiter.Limiter) {
	w.limiterRef = l
}

func (w *AmneziaWGCore) assignIP(id int) string {
	if id <= 0 {
		return ""
	}
	baseIP, _, err := net.ParseCIDR(w.Address)
	if err != nil {
		baseIP = net.ParseIP("10.0.0.1")
	}
	baseIP = baseIP.To4()
	if baseIP == nil {
		return ""
	}
	index := int64(id) - 1
	hostsPerSubnet := int64(127)
	dIndex := index % hostsPerSubnet
	upperIndex := index / hostsPerSubnet
	cOffset := upperIndex % 256
	bOffset := (upperIndex / 256) % 256
	byteD := (dIndex * 2) + 2
	valC := int(baseIP[2]) + int(cOffset)
	extraB := valC / 256
	byteC := valC % 256
	valB := int(baseIP[1]) + int(bOffset) + extraB
	byteB := valB % 256
	return fmt.Sprintf("%d.%d.%d.%d", baseIP[0], byteB, byteC, byteD)
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

	// Always add TCPMSS clamping rule for forwarded / outbound traffic to prevent MTU blackholing
	if err := execCommand("iptables -w 5 -t mangle -C POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu"); err != nil {
		_ = execCommand("iptables -w 5 -t mangle -A POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu")
	}

	// Drop ICMP Destination Unreachable if enabled (prevents game disconnects during radio fades)
	// Must be inserted at head of chain (index 1) BEFORE the ACCEPT rules so they take effect
	if w.DropICMPUnreachable {
		if err := execCommand(fmt.Sprintf("iptables -w 5 -C FORWARD -i %s -p icmp --icmp-type destination-unreachable -j DROP", w.InterfaceName)); err != nil {
			_ = execCommand(fmt.Sprintf("iptables -w 5 -I FORWARD 1 -i %s -p icmp --icmp-type destination-unreachable -j DROP", w.InterfaceName))
		}
		if err := execCommand(fmt.Sprintf("iptables -w 5 -C FORWARD -o %s -p icmp --icmp-type destination-unreachable -j DROP", w.InterfaceName)); err != nil {
			_ = execCommand(fmt.Sprintf("iptables -w 5 -I FORWARD 1 -o %s -p icmp --icmp-type destination-unreachable -j DROP", w.InterfaceName))
		}
		if err := execCommand(fmt.Sprintf("iptables -w 5 -C OUTPUT -o %s -p icmp --icmp-type destination-unreachable -j DROP", w.InterfaceName)); err != nil {
			_ = execCommand(fmt.Sprintf("iptables -w 5 -I OUTPUT 1 -o %s -p icmp --icmp-type destination-unreachable -j DROP", w.InterfaceName))
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

	defaultIface, err := getDefaultInterface()
	if err != nil {
		defaultIface = "eth0"
	}

	// Always clean up FORWARD and INPUT rules (added in both paths)
	_ = execCommand(fmt.Sprintf("iptables -w 5 -D FORWARD -i %s -j ACCEPT", w.InterfaceName))
	_ = execCommand(fmt.Sprintf("iptables -w 5 -D FORWARD -o %s -j ACCEPT", w.InterfaceName))
	_ = execCommand(fmt.Sprintf("iptables -w 5 -D INPUT -i %s -j ACCEPT", w.InterfaceName))
	_ = execCommand("iptables -w 5 -t mangle -D POSTROUTING -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu")

	if w.DropICMPUnreachable {
		_ = execCommand(fmt.Sprintf("iptables -w 5 -D FORWARD -i %s -p icmp --icmp-type destination-unreachable -j DROP", w.InterfaceName))
		_ = execCommand(fmt.Sprintf("iptables -w 5 -D FORWARD -o %s -p icmp --icmp-type destination-unreachable -j DROP", w.InterfaceName))
		_ = execCommand(fmt.Sprintf("iptables -w 5 -D OUTPUT -o %s -p icmp --icmp-type destination-unreachable -j DROP", w.InterfaceName))
	}

	// Always clean up MASQUERADE (added in both paths)
	if subnet != "" {
		_ = execCommand(fmt.Sprintf("iptables -w 5 -t nat -D POSTROUTING -s %s -o %s -j MASQUERADE", subnet, defaultIface))
	}

	if w.TProxyPort > 0 {
		chainName := fmt.Sprintf("XRAY_%s", w.InterfaceName)
		_ = execCommand(fmt.Sprintf("iptables -w 5 -t mangle -D PREROUTING -i %s -j %s", w.InterfaceName, chainName))
		_ = execCommand(fmt.Sprintf("iptables -w 5 -t mangle -F %s", chainName))
		_ = execCommand(fmt.Sprintf("iptables -w 5 -t mangle -X %s", chainName))
	}
}

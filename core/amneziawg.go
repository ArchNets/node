//go:build !freebsd

package core

import (
	"encoding/json"
	"fmt"
	"net"
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
	Jc   int
	Jmin int
	Jmax int
	S1   int
	S2   int
	H1   int
	H2   int
	H3   int
	H4   int

	peers      sync.Map // map[string]*WireGuardPeer (key: UUID)
	users      *WGUserMap
	limiterRef *limiter.Limiter
	running    atomic.Bool

	// Traffic accounting
	trafficMu      sync.RWMutex
	traffic        map[int]*UserTraffic // key: uid
	lastPeerStats  map[string]*peerStats
	statsCollector *amneziaStatsCollectorTask
}

// Reuse structs from wireguard.go where possible or redefine if private

// NewAmneziaWGCore creates a new AmneziaWG VPN server
func NewAmneziaWGCore(tag string, port int, address string, interfaceName string, mtu int, dns string, privateKeyStr string,
	jc, jmin, jmax, s1, s2, h1, h2, h3, h4 int) (*AmneziaWGCore, error) {

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
		Tag:           tag,
		Port:          port,
		InterfaceName: interfaceName,
		PrivateKey:    privateKey,
		PublicKey:     publicKey,
		Address:       address,
		MTU:           mtu,
		DNS:           dns,
		Jc:            jc,
		Jmin:          jmin,
		Jmax:          jmax,
		S1:            s1,
		S2:            s2,
		H1:            h1,
		H2:            h2,
		H3:            h3,
		H4:            h4,
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
			w.peers.Delete(uuid)
			delete(w.users.uuidToID, uuid)
			delete(w.users.idToUUID, user.Id)
			// Remove from ipToUID map...
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
	// 1. Set simple params first
	// awg set <iface> listen-port <port> private-key <file>
	// We need to write private key to temp file or pipe it?
	// Piping: echo <key> | awg set <iface> private-key /dev/stdin

	cmd := fmt.Sprintf("echo %s | awg set %s listen-port %d private-key /dev/stdin", w.PrivateKey.String(), w.InterfaceName, w.Port)
	// We need to execute utilizing shell for pipe
	if err := execShellCommand(cmd); err != nil {
		return fmt.Errorf("failed to set basic config: %w", err)
	}

	// 2. Set Amnezia params
	// awg set <iface> jc <jc> jmin <jmin> jmax <jmax> s1 <s1> s2 <s2> h1 <h1> h2 <h2> h3 <h3> h4 <h4>
	amneziaCmd := fmt.Sprintf("awg set %s jc %d jmin %d jmax %d s1 %d s2 %d h1 %d h2 %d h3 %d h4 %d",
		w.InterfaceName, w.Jc, w.Jmin, w.Jmax, w.S1, w.S2, w.H1, w.H2, w.H3, w.H4)

	if err := execCommand(amneziaCmd); err != nil {
		return fmt.Errorf("failed to set amnezia params: %w", err)
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

// ... include setupNAT, teardownNAT, getDefaultInterface, assignIP from wireguard.go ...
// ... include execCommand ...

func execShellCommand(cmd string) error {
	command := exec.Command("sh", "-c", cmd)
	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("command failed: %s, output: %s", err, string(output))
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

// Helper methods copied from wireguard.go

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
	defaultIface, err := getDefaultInterface()
	if err != nil {
		defaultIface = "eth0"
	}
	_, ipnet, err := net.ParseCIDR(w.Address)
	if err != nil {
		return fmt.Errorf("invalid address for NAT: %w", err)
	}
	subnet := ipnet.String()

	if err := execCommand(fmt.Sprintf("iptables -C FORWARD -i %s -j ACCEPT", w.InterfaceName)); err != nil {
		_ = execCommand(fmt.Sprintf("iptables -A FORWARD -i %s -j ACCEPT", w.InterfaceName))
	}
	if err := execCommand(fmt.Sprintf("iptables -C FORWARD -o %s -j ACCEPT", w.InterfaceName)); err != nil {
		_ = execCommand(fmt.Sprintf("iptables -A FORWARD -o %s -j ACCEPT", w.InterfaceName))
	}

	checkCmd := fmt.Sprintf("iptables -t nat -C POSTROUTING -s %s -o %s -j MASQUERADE", subnet, defaultIface)
	if err := execCommand(checkCmd); err != nil {
		_ = execCommand(fmt.Sprintf("iptables -t nat -A POSTROUTING -s %s -o %s -j MASQUERADE", subnet, defaultIface))
	}
	return nil
}

func (w *AmneziaWGCore) teardownNAT() {
	defaultIface, err := getDefaultInterface()
	if err != nil {
		defaultIface = "eth0"
	}
	_, ipnet, _ := net.ParseCIDR(w.Address)
	var subnet string
	if ipnet != nil {
		subnet = ipnet.String()
	}
	if subnet != "" {
		_ = execCommand(fmt.Sprintf("iptables -t nat -D POSTROUTING -s %s -o %s -j MASQUERADE", subnet, defaultIface))
	}
	_ = execCommand(fmt.Sprintf("iptables -D FORWARD -i %s -j ACCEPT", w.InterfaceName))
	_ = execCommand(fmt.Sprintf("iptables -D FORWARD -o %s -j ACCEPT", w.InterfaceName))
}

// ...
// Copy helper methods: assignIP, setupNAT, teardownNAT

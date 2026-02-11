//go:build !freebsd

package core

import (
	"encoding/json"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/archnets/node/api/panel"
	"github.com/archnets/node/limiter"
	log "github.com/sirupsen/logrus"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// WireGuardCore manages a WireGuard VPN server
type WireGuardCore struct {
	Tag           string
	Port          int
	InterfaceName string
	PrivateKey    wgtypes.Key
	PublicKey     wgtypes.Key
	Address       string // e.g., "10.0.0.1/24"
	MTU           int
	DNS           string

	wgClient   *wgctrl.Client
	peers      sync.Map // map[string]*WireGuardPeer (key: UUID)
	users      *WGUserMap
	limiterRef *limiter.Limiter
	running    atomic.Bool

	// Traffic accounting
	trafficMu      sync.RWMutex
	traffic        map[int]*UserTraffic // key: uid
	lastPeerStats  map[string]*peerStats
	statsCollector *statsCollectorTask
}

// WireGuardPeer represents a connected peer (user)
type WireGuardPeer struct {
	PublicKey  wgtypes.Key
	AllowedIPs []net.IPNet
	UID        int
	UUID       string
	IP         string // Assigned internal IP
}

// WGUserMap stores user UUID to ID mapping
type WGUserMap struct {
	mu       sync.RWMutex
	uuidToID map[string]int // UUID -> user ID
	idToUUID map[int]string // user ID -> UUID
	ipToUID  map[string]int // assigned IP -> user ID
}

// peerStats stores the last known stats for a peer
type peerStats struct {
	ReceiveBytes  int64
	TransmitBytes int64
	LastHandshake time.Time
}

// statsCollectorTask periodically collects stats from WireGuard
type statsCollectorTask struct {
	core     *WireGuardCore
	stopChan chan struct{}
	wg       sync.WaitGroup
}

// NewWireGuardCore creates a new WireGuard VPN server
func NewWireGuardCore(tag string, port int, address string, interfaceName string, mtu int, dns string, privateKeyStr string) (*WireGuardCore, error) {
	var privateKey wgtypes.Key
	var err error

	if privateKeyStr != "" {
		// Use provided private key
		privateKey, err = wgtypes.ParseKey(privateKeyStr)
		if err != nil {
			return nil, fmt.Errorf("invalid private key: %w", err)
		}
	} else {
		// Generate server key pair if not provided
		privateKey, err = wgtypes.GeneratePrivateKey()
		if err != nil {
			return nil, fmt.Errorf("failed to generate private key: %w", err)
		}
	}
	publicKey := privateKey.PublicKey()

	// Initialize WireGuard client
	wgClient, err := wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("failed to create wgctrl client: %w", err)
	}

	if mtu == 0 {
		mtu = 1420 // Default WireGuard MTU
	}

	if interfaceName == "" {
		interfaceName = "wg0"
	}

	core := &WireGuardCore{
		Tag:           tag,
		Port:          port,
		InterfaceName: interfaceName,
		PrivateKey:    privateKey,
		PublicKey:     publicKey,
		Address:       address,
		MTU:           mtu,
		DNS:           dns,
		wgClient:      wgClient,
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

// Start starts the WireGuard server
func (w *WireGuardCore) Start() error {
	// Create WireGuard interface
	if err := w.createInterface(); err != nil {
		return fmt.Errorf("failed to create interface: %w", err)
	}

	// Configure the interface
	if err := w.configureInterface(); err != nil {
		w.deleteInterface() // Cleanup on failure
		return fmt.Errorf("failed to configure interface: %w", err)
	}

	w.running.Store(true)

	// Start stats collector
	w.statsCollector = &statsCollectorTask{
		core:     w,
		stopChan: make(chan struct{}),
	}
	w.statsCollector.start()

	log.WithFields(log.Fields{
		"tag":       w.Tag,
		"interface": w.InterfaceName,
		"port":      w.Port,
		"publicKey": w.PublicKey.String(),
	}).Info("WireGuard server started")

	return nil
}

// Stop stops the WireGuard server
func (w *WireGuardCore) Stop() error {
	w.running.Store(false)

	// Stop stats collector
	if w.statsCollector != nil {
		w.statsCollector.stop()
	}

	// Delete the interface
	if err := w.deleteInterface(); err != nil {
		log.WithError(err).Warn("Failed to delete WireGuard interface")
	}

	if w.wgClient != nil {
		w.wgClient.Close()
	}

	log.WithField("tag", w.Tag).Info("WireGuard server stopped")
	return nil
}

// AddUsers adds users as peers to the WireGuard interface
func (w *WireGuardCore) AddUsers(users []panel.UserInfo) {
	w.users.mu.Lock()
	defer w.users.mu.Unlock()

	// Structure for parsing the JSON service_id
	type ServiceIdentity struct {
		WireGuard *struct {
			PublicKey string `json:"public_key"`
		} `json:"wireguard,omitempty"`
	}

	for _, user := range users {
		if user.ServiceId == "" {
			continue
		}

		// Parse the JSON service_id
		var identity ServiceIdentity
		if err := json.Unmarshal([]byte(user.ServiceId), &identity); err != nil {
			// Fallback: Try treating it as a raw key string (legacy support/backward compatibility)
			// log.Debugf("Failed to parse ServiceId as JSON for user %d, trying generic string", user.Id)
			// This part is optional but helpful during migration. For strict mode, we can omit.
		}

		var pubKeyStr string
		// Check for WireGuard identity
		if identity.WireGuard != nil && identity.WireGuard.PublicKey != "" {
			pubKeyStr = identity.WireGuard.PublicKey
		} else {
			// If JSON parse failed or no WG key, try raw string (if users put raw base64 in the DB field)
			pubKeyStr = user.ServiceId
		}

		peerPublicKey, err := wgtypes.ParseKey(pubKeyStr)
		if err != nil {
			// Only invalid if it's meant to be a key.
			// If ServiceId is valid JSON for OpenVPN but no WG, we just skip smoothly.
			if identity.WireGuard != nil {
				log.WithError(err).Warnf("Invalid WireGuard Public Key for user %d", user.Id)
			}
			continue
		}

		// Note: peerPrivateKey is NOT needed logically anymore on the server side if we trust the public key.
		// However, wgtypes.PeerConfig expects a PublicKey.
		// The logic below uses peerPublicKey correctly.

		// Use Id (SubscriptionId) for unique IP generation
		assignedIP := w.assignIP(user.Id)

		// Parse allowed IPs for this peer
		_, ipnet, err := net.ParseCIDR(assignedIP + "/32")
		if err != nil {
			log.WithError(err).Errorf("Failed to parse IP for user %d", user.Id)
			continue
		}

		peer := &WireGuardPeer{
			PublicKey:  peerPublicKey,
			AllowedIPs: []net.IPNet{*ipnet},
			UID:        user.Id,
			UUID:       user.Uuid,
			IP:         assignedIP,
		}

		w.peers.Store(user.Uuid, peer)
		w.users.uuidToID[user.Uuid] = user.Id
		w.users.idToUUID[user.Id] = user.Uuid
		w.users.ipToUID[assignedIP] = user.Id
	}

	// Update WireGuard configuration with new peers
	if err := w.updatePeers(); err != nil {
		log.WithError(err).Error("Failed to update WireGuard peers")
	}

	log.WithFields(log.Fields{
		"tag":   w.Tag,
		"count": len(users),
	}).Info("WireGuard users added")
}

// DelUsers removes users from the WireGuard interface
func (w *WireGuardCore) DelUsers(users []panel.UserInfo) {
	w.users.mu.Lock()
	defer w.users.mu.Unlock()

	for _, user := range users {
		// Get assigned IP for cleanup
		assignedIP := ""
		if uuid, exists := w.users.idToUUID[user.Id]; exists {
			if peer, ok := w.peers.Load(uuid); ok {
				assignedIP = peer.(*WireGuardPeer).IP
			}
		}

		// Remove from maps
		w.peers.Delete(user.Uuid)
		delete(w.users.uuidToID, user.Uuid)
		delete(w.users.idToUUID, user.Id)
		if assignedIP != "" {
			delete(w.users.ipToUID, assignedIP)
		}
	}

	// Update WireGuard configuration
	if err := w.updatePeers(); err != nil {
		log.WithError(err).Error("Failed to update WireGuard peers after deletion")
	}

	log.WithFields(log.Fields{
		"tag":   w.Tag,
		"count": len(users),
	}).Info("WireGuard users removed")
}

// GetTrafficAndReset returns traffic stats and resets counters
func (w *WireGuardCore) GetTrafficAndReset() map[int]*UserTraffic {
	w.trafficMu.Lock()
	defer w.trafficMu.Unlock()

	result := w.traffic
	w.traffic = make(map[int]*UserTraffic)
	return result
}

// GetOnlineUsers returns list of currently connected users
func (w *WireGuardCore) GetOnlineUsers() []panel.OnlineUser {
	var online []panel.OnlineUser

	device, err := w.wgClient.Device(w.InterfaceName)
	if err != nil {
		log.WithError(err).Error("Failed to get WireGuard device info")
		return online
	}

	// A peer is considered online if it had a recent handshake
	recentThreshold := time.Now().Add(-3 * time.Minute)

	for _, peer := range device.Peers {
		if peer.LastHandshakeTime.Before(recentThreshold) {
			continue // Not recently active
		}

		// Find user by public key
		w.peers.Range(func(key, value interface{}) bool {
			wgPeer := value.(*WireGuardPeer)
			if wgPeer.PublicKey == peer.PublicKey {
				online = append(online, panel.OnlineUser{
					UID: wgPeer.UID,
					IP:  wgPeer.IP,
				})
				return false // Stop searching
			}
			return true
		})
	}

	return online
}

// SetLimiter sets the limiter reference for device/speed limiting
func (w *WireGuardCore) SetLimiter(l *limiter.Limiter) {
	w.limiterRef = l
}

// createInterface creates the WireGuard network interface
func (w *WireGuardCore) createInterface() error {
	// Clean up any existing interface with the same name
	// We ignore the error here because the interface might not exist
	_ = execCommand(fmt.Sprintf("ip link delete %s", w.InterfaceName))

	// Use ip link command to create interface
	// Note: This requires root privileges
	cmd := fmt.Sprintf("ip link add %s type wireguard", w.InterfaceName)
	if err := execCommand(cmd); err != nil {
		return fmt.Errorf("failed to create interface: %w", err)
	}

	// Enable IP forwarding
	if err := execCommand("sysctl -w net.ipv4.ip_forward=1"); err != nil {
		log.WithError(err).Warn("Failed to enable IP forwarding")
	}

	// Set interface MTU
	cmd = fmt.Sprintf("ip link set %s mtu %d", w.InterfaceName, w.MTU)
	if err := execCommand(cmd); err != nil {
		return fmt.Errorf("failed to set MTU: %w", err)
	}

	return nil
}

// configureInterface configures the WireGuard interface
func (w *WireGuardCore) configureInterface() error {
	// Configure WireGuard using wgctrl
	config := wgtypes.Config{
		PrivateKey: &w.PrivateKey,
		ListenPort: &w.Port,
	}

	if err := w.wgClient.ConfigureDevice(w.InterfaceName, config); err != nil {
		return fmt.Errorf("failed to configure WireGuard device: %w", err)
	}

	// Assign IP address to interface
	cmd := fmt.Sprintf("ip addr add %s dev %s", w.Address, w.InterfaceName)
	if err := execCommand(cmd); err != nil {
		return fmt.Errorf("failed to assign IP address: %w", err)
	}

	// Bring interface up
	cmd = fmt.Sprintf("ip link set %s up", w.InterfaceName)
	if err := execCommand(cmd); err != nil {
		return fmt.Errorf("failed to bring interface up: %w", err)
	}

	return nil
}

// deleteInterface removes the WireGuard interface
func (w *WireGuardCore) deleteInterface() error {
	cmd := fmt.Sprintf("ip link delete %s", w.InterfaceName)
	return execCommand(cmd)
}

// updatePeers updates the peer configuration on the WireGuard interface
func (w *WireGuardCore) updatePeers() error {
	var peerConfigs []wgtypes.PeerConfig

	w.peers.Range(func(key, value interface{}) bool {
		peer := value.(*WireGuardPeer)
		peerConfigs = append(peerConfigs, wgtypes.PeerConfig{
			PublicKey:  peer.PublicKey,
			AllowedIPs: peer.AllowedIPs,
		})
		return true
	})

	config := wgtypes.Config{
		Peers: peerConfigs,
		// ReplacePeers removes all existing peers and adds these
		ReplacePeers: true,
	}

	if err := w.wgClient.ConfigureDevice(w.InterfaceName, config); err != nil {
		return fmt.Errorf("failed to update peers: %w", err)
	}

	return nil
}

// assignIP assigns an IP address to a user based on their ID (SubscriptionId)
// Matches Backend logic: 10.{byteB}.{byteC}.{byteD}
// Constraints: Even IPs only (2, 4, ..., 254), giving 127 usable hosts per /24 block.
func (w *WireGuardCore) assignIP(id int) string {
	if id <= 0 {
		return ""
	}

	// Parse the base IP from the configuration
	baseIP, _, err := net.ParseCIDR(w.Address)
	if err != nil {
		// Fallback to safe default if address is invalid (should be caught earlier)
		baseIP = net.ParseIP("10.0.0.1")
	}
	baseIP = baseIP.To4()
	if baseIP == nil {
		return ""
	}

	// Algorithm matches Backend's calculateWireGuardIP
	// 0-based index
	index := int64(id) - 1

	// Constants
	hostsPerSubnet := int64(127) // 2 to 254, even numbers only

	// Calculate offset indices
	dIndex := index % hostsPerSubnet
	upperIndex := index / hostsPerSubnet

	cOffset := upperIndex % 256
	bOffset := (upperIndex / 256) % 256

	// Calculate octet values relative to base IP
	// We add the offset to the base IP components

	// Byte D (4th octet): 2, 4, ..., 254
	// This logic reset the last octet, ignoring the base IP's last octet
	// This is intentional to ensure even numbering relative to x.x.x.0
	byteD := (dIndex * 2) + 2

	// Byte C (3rd octet): Base[2] + offset
	valC := int(baseIP[2]) + int(cOffset)
	extraB := valC / 256
	byteC := valC % 256

	// Byte B (2nd octet): Base[1] + offset + overflow from C
	valB := int(baseIP[1]) + int(bOffset) + extraB
	// We do not handle overflow from B to A here as /8 is the max reasonable size
	byteB := valB % 256

	return fmt.Sprintf("%d.%d.%d.%d", baseIP[0], byteB, byteC, byteD)
}

// collectStats collects traffic statistics from WireGuard
func (w *WireGuardCore) collectStats() {
	device, err := w.wgClient.Device(w.InterfaceName)
	if err != nil {
		log.WithError(err).Error("Failed to get WireGuard device stats")
		return
	}

	w.trafficMu.Lock()
	defer w.trafficMu.Unlock()

	for _, peer := range device.Peers {
		// Find the user ID for this peer
		var uid int
		var assignedIP string
		w.peers.Range(func(key, value interface{}) bool {
			wgPeer := value.(*WireGuardPeer)
			if wgPeer.PublicKey == peer.PublicKey {
				uid = wgPeer.UID
				assignedIP = wgPeer.IP
				return false
			}
			return true
		})

		if uid == 0 {
			continue // Unknown peer
		}

		// Calculate delta from last stats
		peerKey := peer.PublicKey.String()
		lastStats, exists := w.lastPeerStats[peerKey]
		if !exists {
			lastStats = &peerStats{}
			w.lastPeerStats[peerKey] = lastStats
		}

		downloadDelta := peer.ReceiveBytes - lastStats.ReceiveBytes
		uploadDelta := peer.TransmitBytes - lastStats.TransmitBytes

		// Update last stats
		lastStats.ReceiveBytes = peer.ReceiveBytes
		lastStats.TransmitBytes = peer.TransmitBytes

		// Check if peer just connected (handshake time changed)
		if !peer.LastHandshakeTime.Equal(lastStats.LastHandshake) {
			// If previous handshake was zero or very old, this is a new active session
			if lastStats.LastHandshake.IsZero() || time.Since(lastStats.LastHandshake) > 3*time.Minute {
				log.WithFields(log.Fields{
					"uid": uid,
					"ip":  assignedIP,
				}).Info("WireGuard peer connected")
			}
		}
		lastStats.LastHandshake = peer.LastHandshakeTime

		// Add to traffic counter
		if w.traffic[uid] == nil {
			w.traffic[uid] = &UserTraffic{}
		}
		w.traffic[uid].Download += downloadDelta
		w.traffic[uid].Upload += uploadDelta
	}
}

// statsCollectorTask methods

func (t *statsCollectorTask) start() {
	t.wg.Add(1)
	go t.run()
}

func (t *statsCollectorTask) run() {
	defer t.wg.Done()

	ticker := time.NewTicker(10 * time.Second) // Collect stats every 10 seconds
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

func (t *statsCollectorTask) stop() {
	close(t.stopChan)
	t.wg.Wait()
}

// execCommand executes a shell command (helper for ip commands)
func execCommand(cmd string) error {
	parts := strings.Fields(cmd)
	if len(parts) == 0 {
		return fmt.Errorf("empty command")
	}

	command := exec.Command(parts[0], parts[1:]...)
	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("command failed: %s, output: %s", err, string(output))
	}

	log.WithFields(log.Fields{
		"cmd":    cmd,
		"output": string(output),
	}).Debug("Command executed successfully")

	return nil
}

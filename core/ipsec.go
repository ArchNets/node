package core

import (
	"encoding/json"
	"fmt"
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

// IPsecCore manages strongSwan IKEv2 and xl2tpd L2TP servers.
type IPsecCore struct {
	Tag string
	PSK string // Pre-Shared Key from Protocol config

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
func NewIPsecCore(tag, psk string) *IPsecCore {
	return &IPsecCore{
		Tag:          tag,
		PSK:          psk,
		users:        make(map[int]*IPsecUser),
		traffic:      make(map[int]*UserTraffic),
		lastSasStats: make(map[string]*sasStats),
	}
}

// Start initializes strongSwan and xl2tpd.
func (c *IPsecCore) Start() error {
	// Enable IP forwarding
	_ = exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1").Run()

	// Write initial configs
	if err := c.writeConfigs(); err != nil {
		return fmt.Errorf("failed to write ipsec configs: %w", err)
	}

	// Restart strongSwan
	if err := c.reloadStrongSwan(); err != nil {
		return fmt.Errorf("failed to start strongSwan: %w", err)
	}

	// Start stats collector
	c.statsCollector = &ipsecStatsCollector{
		core:     c,
		stopChan: make(chan struct{}),
	}
	c.statsCollector.start()

	log.WithField("tag", c.Tag).Info("IPsec core started")
	return nil
}

// Stop stops strongSwan.
func (c *IPsecCore) Stop() {
	if c.statsCollector != nil {
		c.statsCollector.stop()
	}
	_ = exec.Command("swanctl", "--terminate", "--ike", c.Tag).Run()
	log.WithField("tag", c.Tag).Info("IPsec core stopped")
}

// AddUsers parses ServiceId JSON and adds IKEv2 users.
func (c *IPsecCore) AddUsers(users []panel.UserInfo) {
	c.mu.Lock()
	defer c.mu.Unlock()

	type IKEv2Identity struct {
		IKEv2 *struct {
			Username string `json:"username"`
			Password string `json:"password"`
		} `json:"ikev2,omitempty"`
	}

	for _, user := range users {
		if user.ServiceId == "" {
			continue
		}
		var identity IKEv2Identity
		if err := json.Unmarshal([]byte(user.ServiceId), &identity); err != nil {
			continue
		}
		if identity.IKEv2 == nil || identity.IKEv2.Username == "" {
			continue
		}
		c.users[user.Id] = &IPsecUser{
			UID:      user.Id,
			UUID:     user.Uuid,
			Username: identity.IKEv2.Username,
			Password: identity.IKEv2.Password,
		}
	}

	// Regenerate configs with new users
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

// GetOnlineUsers returns currently connected IKEv2 users via swanctl.
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

// writeConfigs generates swanctl.conf and secrets.
func (c *IPsecCore) writeConfigs() error {
	// Write swanctl connection config
	conf := c.generateSwanctlConf()
	if err := os.MkdirAll("/etc/swanctl/conf.d", 0755); err != nil {
		return err
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

	return nil
}

// generateSwanctlConf generates the swanctl.conf content.
func (c *IPsecCore) generateSwanctlConf() string {
	return fmt.Sprintf(`connections {
    %s {
        version = 2
        proposals = aes256-sha256-modp2048,aes128-sha256-modp2048,default
        rekey_time = 0s
        pools = pool-%s
        fragmentation = yes
        dpd_delay = 30s
        local {
            auth = psk
            id = %%any
        }
        remote {
            auth = eap-mschapv2
            eap_id = %%any
        }
        children {
            %s-child {
                local_ts = 0.0.0.0/0
                rekey_time = 0s
                dpd_action = clear
                esp_proposals = aes256-sha256,aes128-sha256,default
            }
        }
    }
}
pools {
    pool-%s {
        addrs = 10.10.0.0/16
        dns = 8.8.8.8,1.1.1.1
    }
}
`, c.Tag, c.Tag, c.Tag, c.Tag)
}

// generateSecrets generates the secrets config.
func (c *IPsecCore) generateSecrets() string {
	var sb strings.Builder
	sb.WriteString("secrets {\n")

	// IKE PSK
	sb.WriteString(fmt.Sprintf("    ike-%s {\n", c.Tag))
	sb.WriteString(fmt.Sprintf("        secret = \"%s\"\n", c.PSK))
	sb.WriteString("    }\n")

	// EAP secrets for each user
	for _, user := range c.users {
		sb.WriteString(fmt.Sprintf("    eap-%s-%d {\n", c.Tag, user.UID))
		sb.WriteString(fmt.Sprintf("        id = \"%s\"\n", user.Username))
		sb.WriteString(fmt.Sprintf("        secret = \"%s\"\n", user.Password))
		sb.WriteString("    }\n")
	}

	sb.WriteString("}\n")
	return sb.String()
}

// reloadStrongSwan reloads strongSwan configuration.
func (c *IPsecCore) reloadStrongSwan() error {
	// Load credentials
	if out, err := exec.Command("swanctl", "--load-all").CombinedOutput(); err != nil {
		return fmt.Errorf("swanctl --load-all failed: %s, output: %s", err, string(out))
	}
	return nil
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

// parsedSA represents one parsed IKE SA from swanctl --list-sas
type parsedSA struct {
	Username string
	RemoteIP string
	InBytes  int64
	OutBytes int64
}

var (
	// swanctl --list-sas output patterns:
	//   remote 'user_a1b2c3d4' @ 203.0.113.5[4500]
	//   bytes_in=12345 bytes_out=67890
	reRemote   = regexp.MustCompile(`remote\s+'([^']+)'\s+@\s+([0-9.]+)`)
	reInBytes  = regexp.MustCompile(`bytes_i(?:n)?=(\d+)`)
	reOutBytes = regexp.MustCompile(`bytes_o(?:ut)?=(\d+)`)
	// Alternative format from swanctl --list-sas (non-raw):
	//   192.168.1.100...10.10.0.1  12345 bytes_i ... 67890 bytes_o
	reBytesAlt = regexp.MustCompile(`(\d+)\s+bytes_i.*?(\d+)\s+bytes_o`)
)

// parseSasOutput runs swanctl --list-sas and parses the output
func (c *IPsecCore) parseSasOutput() []parsedSA {
	output, err := exec.Command("swanctl", "--list-sas").CombinedOutput()
	if err != nil {
		return nil
	}
	var result []parsedSA
	var current *parsedSA
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		// Match remote identity line: remote 'user_xxx' @ 1.2.3.4
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
		// Try raw format: bytes_in=N bytes_out=N
		if m := reInBytes.FindStringSubmatch(line); len(m) == 2 {
			current.InBytes, _ = strconv.ParseInt(m[1], 10, 64)
		}
		if m := reOutBytes.FindStringSubmatch(line); len(m) == 2 {
			current.OutBytes, _ = strconv.ParseInt(m[1], 10, 64)
		}
		// Try alternative format: N bytes_i ... N bytes_o
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

// collectStats collects traffic from strongSwan and computes deltas
func (c *IPsecCore) collectStats() {
	sas := c.parseSasOutput()
	if len(sas) == 0 {
		return
	}
	c.mu.RLock()
	// Build username -> UID map
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
		// Compute delta (handle counter reset if SA was rekeyed)
		var dlDelta, ulDelta int64
		if sa.OutBytes >= last.OutBytes {
			dlDelta = sa.OutBytes - last.OutBytes // out from server = download for user
		} else {
			dlDelta = sa.OutBytes // counter reset
		}
		if sa.InBytes >= last.InBytes {
			ulDelta = sa.InBytes - last.InBytes // in to server = upload from user
		} else {
			ulDelta = sa.InBytes // counter reset
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

// ipsecStatsCollector methods
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

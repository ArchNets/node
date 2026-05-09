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
	Tag              string
	Mode             string // "ikev2" or "l2tp"
	PSK              string // Pre-Shared Key from Protocol config
	L2TPSharedSecret string // L2TP shared secret (for L2TP IPSec PSK)
	AuthMethod       string // "eap-mschapv2" or "psk"

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
func NewIPsecCore(tag, mode, psk, l2tpSecret, authMethod string) *IPsecCore {
	if mode == "" {
		mode = "ikev2"
	}
	if authMethod == "" {
		authMethod = "eap-mschapv2"
	}
	return &IPsecCore{
		Tag:              tag,
		Mode:             strings.ToLower(mode),
		PSK:              psk,
		L2TPSharedSecret: l2tpSecret,
		AuthMethod:       authMethod,
		users:            make(map[int]*IPsecUser),
		traffic:          make(map[int]*UserTraffic),
		lastSasStats:     make(map[string]*sasStats),
	}
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
		os.Remove(fmt.Sprintf("/etc/ppp/chap-secrets.%s", c.Tag))
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
	if c.Mode == "l2tp" {
		c.restartXl2tpd()
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
	if c.Mode == "l2tp" {
		c.restartXl2tpd()
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
		if err := os.WriteFile(fmt.Sprintf("/etc/ppp/chap-secrets.%s", c.Tag), []byte(c.generateChapSecrets()), 0600); err != nil {
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
            auth = %s
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
`, c.Tag, c.Tag, c.AuthMethod, c.Tag, c.Tag)
}

// generateL2TPSwanctlConf generates IKEv1 Transport mode swanctl.conf for L2TP.
func (c *IPsecCore) generateL2TPSwanctlConf() string {
	return fmt.Sprintf(`connections {
    %s {
        version = 1
        proposals = aes256-sha1-modp2048,aes128-sha1-modp1024,default
        local {
            auth = psk
            id = %%any
        }
        remote {
            auth = psk
        }
        children {
            %s-l2tp {
                local_ts = dynamic[udp]
                remote_ts = dynamic[1701/udp]
                mode = transport
                esp_proposals = aes256-sha1,aes128-sha1,default
            }
        }
    }
}
`, c.Tag, c.Tag)
}

// generateXl2tpdConf generates xl2tpd.conf (tag-scoped).
func (c *IPsecCore) generateXl2tpdConf() string {
	return fmt.Sprintf(`[global]
port = 1701

[lns default]
ip range = 10.11.1.2-10.11.254.254
local ip = 10.11.0.1
require chap = yes
refuse pap = yes
require authentication = yes
pppoptfile = /etc/ppp/options.xl2tpd.%s
chap-secrets = /etc/ppp/chap-secrets.%s
length bit = yes
`, c.Tag, c.Tag)
}

// generatePPPOptions generates PPP options.
func (c *IPsecCore) generatePPPOptions() string {
	return `ipcp-accept-local
ipcp-accept-remote
ms-dns 8.8.8.8
ms-dns 1.1.1.1
noccp
auth
mtu 1400
mru 1400
nodefaultroute
lock
proxyarp
`
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

// reloadStrongSwan reloads strongSwan configuration.
func (c *IPsecCore) reloadStrongSwan() error {
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

// setupNAT configures MASQUERADE for the VPN subnet
func (c *IPsecCore) setupNAT() error {
	subnet := "10.10.0.0/16"
	if c.Mode == "l2tp" {
		subnet = "10.11.0.0/16"
	}

	// Basic masquerade rule (assuming eth0 as default iface for simplicity, or just let iptables auto-detect output iface)
	checkCmd := fmt.Sprintf("iptables -t nat -C POSTROUTING -s %s -j MASQUERADE", subnet)
	if err := exec.Command("sh", "-c", checkCmd).Run(); err != nil {
		addCmd := fmt.Sprintf("iptables -t nat -A POSTROUTING -s %s -j MASQUERADE", subnet)
		if err := exec.Command("sh", "-c", addCmd).Run(); err != nil {
			return err
		}
	}
	return nil
}

// teardownNAT removes MASQUERADE for the VPN subnet
func (c *IPsecCore) teardownNAT() {
	subnet := "10.10.0.0/16"
	if c.Mode == "l2tp" {
		subnet = "10.11.0.0/16"
	}
	_ = exec.Command("sh", "-c", fmt.Sprintf("iptables -t nat -D POSTROUTING -s %s -j MASQUERADE", subnet)).Run()
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

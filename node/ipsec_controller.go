package node

import (
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/archnets/node/api/panel"
	"github.com/archnets/node/common/serverstatus"
	"github.com/archnets/node/common/task"
	vCore "github.com/archnets/node/core"
	"github.com/archnets/node/limiter"
	log "github.com/sirupsen/logrus"
	coreConf "github.com/xtls/xray-core/infra/conf"
)

// IPsecController manages IKEv2/L2TP protocol nodes.
type IPsecController struct {
	tag       string // internal tag for iptables/limiter (e.g. "ipsec-28-443")
	xrayTag   string // Xray inbound tag matching panel routing rules (e.g. "ikev2:28")
	info      *panel.NodeInfo
	apiClient *panel.ClientV1
	ipsecCore *vCore.IPsecCore
	limiter   *limiter.Limiter
	xrayCore  *vCore.XrayCore

	userList                []panel.UserInfo
	userListMonitorPeriodic *task.Task
	userReportPeriodic      *task.Task
	isPrimaryReporter       bool
}

// NewIPsecController creates a new IPsec controller.
func NewIPsecController(core *vCore.XrayCore, apiClient *panel.ClientV1, info *panel.NodeInfo, isPrimaryReporter bool) *IPsecController {
	// xrayTag matches the panel routing rule format: "type:nodeId" (e.g. "ikev2:28", "l2tp:28")
	xrayTag := info.Protocol.Type + ":" + strconv.Itoa(info.Id)
	return &IPsecController{
		tag:               generateIPsecTag(info),
		xrayTag:           xrayTag,
		info:              info,
		apiClient:         apiClient,
		isPrimaryReporter: isPrimaryReporter,
		xrayCore:          core,
	}
}

func generateIPsecTag(info *panel.NodeInfo) string {
	return "ipsec-" + strconv.Itoa(info.Id) + "-" + strconv.Itoa(info.Protocol.Port)
}

// Start starts the IPsec controller.
func (c *IPsecController) Start() error {
	// Get initial user list
	users, err := c.apiClient.GetUserList()
	if err != nil {
		log.WithError(err).Warn("Failed to fetch initial user list, starting with empty list")
		users = []panel.UserInfo{}
	}
	c.userList = users

	// Get alive list for device limiting
	aliveList, err := c.apiClient.GetUserAlive()
	if err != nil {
		log.WithError(err).Warn("Failed to get alive list")
		aliveList = make(map[int]int)
	}

	// Create limiter
	c.limiter = limiter.AddLimiter(c.info.Type, c.tag, users, aliveList)

	// Build IPsec config from panel protocol config
	cfg := vCore.IPsecConfig{
		Tag:        c.tag,
		Mode:       "ikev2",
		PSK:        "archnet-default-psk",
		AuthMethod: "eap-mschapv2",
	}

	if c.info.Type == "l2tp" {
		cfg.Mode = "l2tp"
	}

	if c.info.Protocol != nil {
		if c.info.Protocol.IPsecPSK != "" {
			cfg.PSK = c.info.Protocol.IPsecPSK
		}
		if c.info.Protocol.L2TPSharedSecret != "" {
			cfg.L2TPSharedSecret = c.info.Protocol.L2TPSharedSecret
		}
		if c.info.Protocol.IPsecAuthMethod != "" {
			cfg.AuthMethod = c.info.Protocol.IPsecAuthMethod
		}
		// Cert configuration from panel
		cfg.Domain = c.info.Protocol.SNI
		cfg.CertMode = c.info.Protocol.CertMode
		cfg.CertFile = c.info.Protocol.CertFile
		cfg.KeyFile = c.info.Protocol.KeyFile
		// Configurable IPsec params
		cfg.DNS = c.info.Protocol.IPsecDNS
		cfg.Subnet = c.info.Protocol.IPsecSubnet
		cfg.MTU = c.info.Protocol.IPsecMTU
	}

	// Create and start IPsec core
	c.ipsecCore = vCore.NewIPsecCore(cfg)

	// Inject Xray TPROXY inbound for routing traffic through Xray outbounds
	// NOTE: previously `12000/13000/14000 + c.info.Id` per mode — same
	// per-node-only collision bug as WireGuard/AmneziaWG; see
	// node/tproxy_alloc.go. Mode no longer needs to select a port band since
	// the allocator guarantees uniqueness regardless of mode.
	tproxyPort := nextTProxyPort()

	// Use xrayTag (e.g. "ikev2:28") to match panel routing rules, NOT internal tag
	inboundJSON := fmt.Sprintf(`{
		"tag": "%s",
		"port": %d,
		"protocol": "dokodemo-door",
		"settings": {
			"network": "tcp,udp",
			"followRedirect": true
		},
		"sniffing": {
			"enabled": true,
			"destOverride": ["http", "tls", "quic"]
		},
		"streamSettings": {
			"sockopt": {
				"tproxy": "tproxy"
			}
		}
	}`, c.xrayTag, tproxyPort)

	var inConf coreConf.InboundDetourConfig
	if err := json.Unmarshal([]byte(inboundJSON), &inConf); err != nil {
		return fmt.Errorf("failed to parse tproxy inbound for %s: %v", c.xrayTag, err)
	}
	inboundConfig, err2 := inConf.Build()
	if err2 != nil {
		return fmt.Errorf("failed to build tproxy inbound for %s: %v", c.xrayTag, err2)
	}
	if err := c.xrayCore.AddInbound(inboundConfig); err != nil {
		return fmt.Errorf("failed to add tproxy inbound for %s: %v", c.xrayTag, err)
	}
	c.ipsecCore.SetTProxyPort(tproxyPort)

	if err := c.ipsecCore.Start(); err != nil {
		return fmt.Errorf("failed to start IPsec core: %w", err)
	}

	// Add initial users
	c.ipsecCore.AddUsers(users)

	// Start background tasks
	c.startTasks()

	log.WithFields(log.Fields{
		"tag":       c.tag,
		"port":      c.info.Protocol.Port,
		"userCount": len(users),
	}).Info("IPsec controller started")

	return nil
}

// Close stops the IPsec controller.
func (c *IPsecController) Close() error {
	if c.userListMonitorPeriodic != nil {
		c.userListMonitorPeriodic.Close()
	}
	if c.userReportPeriodic != nil {
		c.userReportPeriodic.Close()
	}
	// Remove Xray TPROXY inbound (uses xrayTag, not internal tag)
	if err := c.xrayCore.RemoveInbound(c.xrayTag); err != nil {
		log.WithError(err).WithField("tag", c.xrayTag).Warn("Failed to remove Xray inbound")
	}
	if c.ipsecCore != nil {
		c.ipsecCore.Stop()
	}
	limiter.DeleteLimiter(c.tag)
	log.WithField("tag", c.tag).Info("IPsec controller closed")
	return nil
}

func (c *IPsecController) startTasks() {
	// User list monitor
	c.userListMonitorPeriodic = &task.Task{
		Interval: time.Duration(c.info.PullInterval) * time.Second,
		Execute:  c.userListMonitor,
	}
	_ = c.userListMonitorPeriodic.Start(false)

	// Traffic report
	c.userReportPeriodic = &task.Task{
		Interval: time.Duration(c.info.PushInterval) * time.Second,
		Execute:  c.reportTask,
	}
	_ = c.userReportPeriodic.Start(false)
}

func (c *IPsecController) userListMonitor() error {
	newUsers, err := c.apiClient.GetUserList()
	if err != nil {
		log.WithFields(log.Fields{"tag": c.tag, "err": err}).Error("IPsec: Get user list failed")
		return nil
	}
	newAlive, err := c.apiClient.GetUserAlive()
	if err != nil {
		log.WithFields(log.Fields{"tag": c.tag, "err": err}).Error("IPsec: Get alive list failed")
		return nil
	}
	if newAlive != nil {
		c.limiter.AliveList = newAlive
	}
	if newUsers == nil {
		return nil // 304 Not Modified
	}

	deleted, added := compareIPsecUserList(c.userList, newUsers)
	if len(deleted) > 0 {
		c.ipsecCore.DelUsers(deleted)
		c.limiter.UpdateUser(c.tag, nil, deleted)
	}
	if len(added) > 0 {
		c.ipsecCore.AddUsers(added)
		c.limiter.UpdateUser(c.tag, added, nil)
	}
	c.userList = newUsers

	if len(added)+len(deleted) != 0 {
		log.WithField("node", c.tag).
			Infof("IPsec: Deleted %d users, added %d users", len(deleted), len(added))
	}
	return nil
}

func (c *IPsecController) reportTask() error {
	// Get traffic
	trafficMap := c.ipsecCore.GetTrafficAndReset()
	var userTraffic []panel.UserTraffic
	for uid, traffic := range trafficMap {
		total := traffic.Upload + traffic.Download
		if total >= int64(c.info.TrafficReportThreshold) {
			userTraffic = append(userTraffic, panel.UserTraffic{
				UID:      uid,
				Upload:   traffic.Upload,
				Download: traffic.Download,
			})
		}
	}
	if len(userTraffic) > 0 {
		if err := c.apiClient.ReportUserTraffic(&userTraffic); err != nil {
			log.WithFields(log.Fields{"tag": c.tag, "err": err}).Info("IPsec: Report user traffic failed")
		} else {
			log.WithField("node", c.tag).Infof("IPsec: Reported traffic for %d users", len(userTraffic))
		}
	}

	// Report online users
	onlineUsers := c.ipsecCore.GetOnlineUsers()
	if c.isPrimaryReporter {
		if err := c.apiClient.ReportNodeOnlineUsers(&onlineUsers); err != nil {
			log.WithFields(log.Fields{"tag": c.tag, "err": err}).Info("IPsec: Report online users failed")
		}
		CPU, Mem, Disk, Uptime, err := serverstatus.GetSystemInfo()
		if err != nil {
			log.Print(err)
		}
		_ = c.apiClient.ReportNodeStatus(&panel.NodeStatus{
			CPU:    CPU,
			Mem:    Mem,
			Disk:   Disk,
			Uptime: Uptime,
		})
	}

	return nil
}

func compareIPsecUserList(old, new []panel.UserInfo) (deleted, added []panel.UserInfo) {
	oldMap := make(map[string]int)
	for i, user := range old {
		key := user.Uuid + strconv.Itoa(user.SpeedLimit) + user.ServiceId
		oldMap[key] = i
	}
	for _, user := range new {
		key := user.Uuid + strconv.Itoa(user.SpeedLimit) + user.ServiceId
		if _, exists := oldMap[key]; !exists {
			added = append(added, user)
		} else {
			delete(oldMap, key)
		}
	}
	for _, index := range oldMap {
		deleted = append(deleted, old[index])
	}
	return deleted, added
}

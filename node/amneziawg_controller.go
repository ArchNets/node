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

// AmneziaWGController manages AmneziaWG protocol nodes
type AmneziaWGController struct {
	tag       string
	info      *panel.NodeInfo
	apiClient *panel.ClientV1
	wgCore    *vCore.AmneziaWGCore
	limiter   *limiter.Limiter

	userList                []panel.UserInfo
	userListMonitorPeriodic *task.Task
	userReportPeriodic      *task.Task
	isPrimaryReporter       bool
	xrayCore                *vCore.XrayCore
}

// NewAmneziaWGController creates a new AmneziaWG controller
func NewAmneziaWGController(core *vCore.XrayCore, apiClient *panel.ClientV1, info *panel.NodeInfo, isPrimaryReporter bool) *AmneziaWGController {
	return &AmneziaWGController{
		tag:               generateAmneziaWGTag(info),
		info:              info,
		apiClient:         apiClient,
		isPrimaryReporter: isPrimaryReporter,
		xrayCore:          core,
	}
}

func generateAmneziaWGTag(info *panel.NodeInfo) string {
	return "awg-" + strconv.Itoa(info.Id) + "-" + strconv.Itoa(info.Protocol.Port)
}

// Start starts the AmneziaWG controller
func (c *AmneziaWGController) Start() error {
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

	// Create limiter for this protocol
	c.limiter = limiter.AddLimiter(c.info.Type, c.tag, users, aliveList)

	// Get AmneziaWG configuration from protocol
	address := "10.0.0.1/24" // Default
	if c.info.Protocol != nil && c.info.Protocol.WireguardAddress != "" {
		address = c.info.Protocol.WireguardAddress
	}

	interfaceName := "awg0" // Default
	if c.info.Protocol != nil && c.info.Protocol.WireguardInterface != "" {
		interfaceName = c.info.Protocol.WireguardInterface
		// If user didn't change default 'wg0' to 'awg0', maybe force it or warn?
		// But let's assume if type AmneziaWG is selected, admin sets interface name correctly or we default.
	}

	mtu := 1420 // Default
	if c.info.Protocol != nil && c.info.Protocol.WireguardMTU > 0 {
		mtu = c.info.Protocol.WireguardMTU
	}

	dns := "1.1.1.1,8.8.8.8" // Default
	if c.info.Protocol != nil && c.info.Protocol.WireguardDNS != "" {
		dns = c.info.Protocol.WireguardDNS
	}

	// Amnezia Params
	var jc, jmin, jmax, s1, s2, s3, s4 int
	var h1, h2, h3, h4 string
	if c.info.Protocol != nil {
		jc = c.info.Protocol.AmneziaJc
		jmin = c.info.Protocol.AmneziaJmin
		jmax = c.info.Protocol.AmneziaJmax
		s1 = c.info.Protocol.AmneziaS1
		s2 = c.info.Protocol.AmneziaS2
		s3 = c.info.Protocol.AmneziaS3
		s4 = c.info.Protocol.AmneziaS4
		h1 = c.info.Protocol.AmneziaH1.String()
		h2 = c.info.Protocol.AmneziaH2.String()
		h3 = c.info.Protocol.AmneziaH3.String()
		h4 = c.info.Protocol.AmneziaH4.String()
	}

	// Create and start AmneziaWG server
	wgCore, err := vCore.NewAmneziaWGCore(c.tag, c.info.Protocol.Port, address, interfaceName, mtu, dns, c.info.Protocol.WireguardPrivateKey,
		jc, jmin, jmax, s1, s2, s3, s4, h1, h2, h3, h4)
	if err != nil {
		return err
	}
	c.wgCore = wgCore
	c.wgCore.SetLimiter(c.limiter)
	// Inject Xray TPROXY Inbound
	tproxyPort := 10800 + c.info.Id
	inboundJSON := fmt.Sprintf(`{
		"tag": "%s",
		"port": %d,
		"protocol": "dokodemo-door",
		"settings": {
			"network": "tcp,udp",
			"followRedirect": true
		},
		"streamSettings": {
			"sockopt": {
				"tproxy": "tproxy"
			}
		}
	}`, c.tag, tproxyPort)

	var inConf coreConf.InboundDetourConfig
	if err := json.Unmarshal([]byte(inboundJSON), &inConf); err != nil {
		return fmt.Errorf("failed to parse tproxy inbound for %s: %v", c.tag, err)
	}
	inboundConfig, err := inConf.Build()
	if err != nil {
		return fmt.Errorf("failed to build tproxy inbound for %s: %v", c.tag, err)
	}
	if err := c.xrayCore.AddInbound(inboundConfig); err != nil {
		return fmt.Errorf("failed to add tproxy inbound for %s: %v", c.tag, err)
	}
	c.wgCore.SetTProxyPort(tproxyPort)

	// Start server
	if err := c.wgCore.Start(); err != nil {
		return err
	}

	// Add initial users - MUST come after Start() so the interface exists!
	c.wgCore.AddUsers(users)

	// Start background tasks
	c.startTasks()

	log.WithFields(log.Fields{
		"tag":       c.tag,
		"port":      c.info.Protocol.Port,
		"interface": interfaceName,
		"userCount": len(users),
	}).Info("AmneziaWG controller started")

	return nil
}

// Close stops the AmneziaWG controller
func (c *AmneziaWGController) Close() error {
	if c.userListMonitorPeriodic != nil {
		c.userListMonitorPeriodic.Close()
	}
	if c.userReportPeriodic != nil {
		c.userReportPeriodic.Close()
	}

	// Remove Xray Inbound
	if err := c.xrayCore.RemoveInbound(c.tag); err != nil {
		log.WithError(err).WithField("tag", c.tag).Warn("Failed to remove Xray inbound")
	}

	if c.wgCore != nil {
		c.wgCore.Stop()
	}

	limiter.DeleteLimiter(c.tag)

	log.WithField("tag", c.tag).Info("AmneziaWG controller closed")
	return nil
}

func (c *AmneziaWGController) startTasks() {
	// User list monitor task
	c.userListMonitorPeriodic = &task.Task{
		Interval: time.Duration(c.info.PullInterval) * time.Second,
		Execute:  c.userListMonitor,
	}
	_ = c.userListMonitorPeriodic.Start(false)
	log.WithField("node", c.tag).Info("AmneziaWG user list monitor task started")

	// Traffic report task
	c.userReportPeriodic = &task.Task{
		Interval: time.Duration(c.info.PushInterval) * time.Second,
		Execute:  c.reportTask,
	}
	_ = c.userReportPeriodic.Start(false)
	log.WithField("node", c.tag).Info("AmneziaWG traffic report task started")
}

func (c *AmneziaWGController) userListMonitor() error {
	// Get updated user list
	newUsers, err := c.apiClient.GetUserList()
	if err != nil {
		log.WithFields(log.Fields{
			"tag": c.tag,
			"err": err,
		}).Error("AmneziaWG: Get user list failed")
		return nil
	}

	// Get alive list
	newAlive, err := c.apiClient.GetUserAlive()
	if err != nil {
		log.WithFields(log.Fields{
			"tag": c.tag,
			"err": err,
		}).Error("AmneziaWG: Get alive list failed")
		return nil
	}

	// Update alive list
	if newAlive != nil {
		c.limiter.AliveList = newAlive
	}

	// Check for changes (nil means 304 Not Modified)
	if newUsers == nil {
		return nil
	}

	deleted, added := compareWGUserList(c.userList, newUsers)

	if len(deleted) > 0 {
		c.wgCore.DelUsers(deleted)
		c.limiter.UpdateUser(c.tag, nil, deleted)
	}

	if len(added) > 0 {
		c.wgCore.AddUsers(added)
		c.limiter.UpdateUser(c.tag, added, nil)
	}

	c.userList = newUsers

	if len(added)+len(deleted) != 0 {
		log.WithField("node", c.tag).
			Infof("AmneziaWG: Deleted %d users, added %d users", len(deleted), len(added))
	}

	return nil
}

func (c *AmneziaWGController) reportTask() error {
	reportMin := 0
	if c.info.TrafficReportThreshold > 0 {
		reportMin = c.info.TrafficReportThreshold
	}

	// Get traffic from AmneziaWG core
	trafficMap := c.wgCore.GetTrafficAndReset()

	// Convert to API format
	var userTraffic []panel.UserTraffic
	for uid, traffic := range trafficMap {
		total := traffic.Upload + traffic.Download
		if total >= int64(reportMin) {
			userTraffic = append(userTraffic, panel.UserTraffic{
				UID:      uid,
				Upload:   traffic.Upload,
				Download: traffic.Download,
			})
		}
	}

	// Report traffic
	if len(userTraffic) > 0 {
		err := c.apiClient.ReportUserTraffic(&userTraffic)
		if err != nil {
			log.WithFields(log.Fields{
				"tag": c.tag,
				"err": err,
			}).Info("AmneziaWG: Report user traffic failed")
		} else {
			log.WithField("node", c.tag).Infof("AmneziaWG: Reported traffic for %d users", len(userTraffic))
		}
	}

	// Get online users from AmneziaWG core
	onlineUsers := c.wgCore.GetOnlineUsers()

	// Filter out users with no actual traffic if needed, but getOnlineUsers usually based on handshake
	// However, mimicking wireguard controller logic:
	var result []panel.OnlineUser
	trafficUIDs := make(map[int]bool)
	for _, t := range userTraffic {
		if t.Upload+t.Download > 0 {
			trafficUIDs[t.UID] = true
		}
	}
	for _, online := range onlineUsers {
		if trafficUIDs[online.UID] {
			result = append(result, online)
		}
	}
	// Note: You might want to relax this filtering if handshakes are enough evidence of being online

	if c.isPrimaryReporter {
		// Report online users
		if err := c.apiClient.ReportNodeOnlineUsers(&result); err != nil {
			log.WithFields(log.Fields{
				"tag": c.tag,
				"err": err,
			}).Info("AmneziaWG: Report online users failed")
		} else {
			log.WithField("node", c.tag).Infof("AmneziaWG: Total %d online users, %d reported", len(onlineUsers), len(result))
		}

		// Report node status
		CPU, Mem, Disk, Uptime, err := serverstatus.GetSystemInfo()
		if err != nil {
			log.Print(err)
		}
		err = c.apiClient.ReportNodeStatus(&panel.NodeStatus{
			CPU:    CPU,
			Mem:    Mem,
			Disk:   Disk,
			Uptime: Uptime,
		})
		if err != nil {
			log.Print(err)
		}
	}

	return nil
}

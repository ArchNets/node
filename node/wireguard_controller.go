package node

import (
	"strconv"
	"time"

	"github.com/archnets/node/api/panel"
	"github.com/archnets/node/common/serverstatus"
	"github.com/archnets/node/common/task"
	vCore "github.com/archnets/node/core"
	"github.com/archnets/node/limiter"
	log "github.com/sirupsen/logrus"
)

// WireGuardController manages WireGuard protocol nodes
type WireGuardController struct {
	tag       string
	info      *panel.NodeInfo
	apiClient *panel.ClientV1
	wgCore    *vCore.WireGuardCore
	limiter   *limiter.Limiter

	userList                []panel.UserInfo
	userListMonitorPeriodic *task.Task
	userReportPeriodic      *task.Task
	isPrimaryReporter       bool
}

// NewWireGuardController creates a new WireGuard controller
func NewWireGuardController(apiClient *panel.ClientV1, info *panel.NodeInfo, isPrimaryReporter bool) *WireGuardController {
	return &WireGuardController{
		tag:               generateWireGuardTag(info),
		info:              info,
		apiClient:         apiClient,
		isPrimaryReporter: isPrimaryReporter,
	}
}

func generateWireGuardTag(info *panel.NodeInfo) string {
	return "wg-" + strconv.Itoa(info.Id) + "-" + strconv.Itoa(info.Protocol.Port)
}

// Start starts the WireGuard controller
func (c *WireGuardController) Start() error {
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
	c.limiter = limiter.AddLimiter(c.tag, users, aliveList)

	// Get WireGuard configuration from protocol
	address := "10.0.0.1/24" // Default
	if c.info.Protocol != nil && c.info.Protocol.WireguardAddress != "" {
		address = c.info.Protocol.WireguardAddress
	}

	interfaceName := "wg0" // Default
	if c.info.Protocol != nil && c.info.Protocol.WireguardInterface != "" {
		interfaceName = c.info.Protocol.WireguardInterface
	}

	mtu := 1420 // Default
	if c.info.Protocol != nil && c.info.Protocol.WireguardMTU > 0 {
		mtu = c.info.Protocol.WireguardMTU
	}

	dns := "1.1.1.1,8.8.8.8" // Default
	if c.info.Protocol != nil && c.info.Protocol.WireguardDNS != "" {
		dns = c.info.Protocol.WireguardDNS
	}

	// Create and start WireGuard server
	wgCore, err := vCore.NewWireGuardCore(c.tag, c.info.Protocol.Port, address, interfaceName, mtu, dns, c.info.Protocol.WireguardPrivateKey)
	if err != nil {
		return err
	}
	c.wgCore = wgCore
	c.wgCore.SetLimiter(c.limiter)

	// Start WireGuard server
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
	}).Info("WireGuard controller started")

	return nil
}

// Close stops the WireGuard controller
func (c *WireGuardController) Close() error {
	if c.userListMonitorPeriodic != nil {
		c.userListMonitorPeriodic.Close()
	}
	if c.userReportPeriodic != nil {
		c.userReportPeriodic.Close()
	}

	if c.wgCore != nil {
		c.wgCore.Stop()
	}

	limiter.DeleteLimiter(c.tag)

	log.WithField("tag", c.tag).Info("WireGuard controller closed")
	return nil
}

func (c *WireGuardController) startTasks() {
	// User list monitor task
	c.userListMonitorPeriodic = &task.Task{
		Interval: time.Duration(c.info.PullInterval) * time.Second,
		Execute:  c.userListMonitor,
	}
	_ = c.userListMonitorPeriodic.Start(false)
	log.WithField("node", c.tag).Info("WireGuard user list monitor task started")

	// Traffic report task
	c.userReportPeriodic = &task.Task{
		Interval: time.Duration(c.info.PushInterval) * time.Second,
		Execute:  c.reportTask,
	}
	_ = c.userReportPeriodic.Start(false)
	log.WithField("node", c.tag).Info("WireGuard traffic report task started")
}

func (c *WireGuardController) userListMonitor() error {
	// Get updated user list
	newUsers, err := c.apiClient.GetUserList()
	if err != nil {
		log.WithFields(log.Fields{
			"tag": c.tag,
			"err": err,
		}).Error("WireGuard: Get user list failed")
		return nil
	}

	// Get alive list
	newAlive, err := c.apiClient.GetUserAlive()
	if err != nil {
		log.WithFields(log.Fields{
			"tag": c.tag,
			"err": err,
		}).Error("WireGuard: Get alive list failed")
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
			Infof("WireGuard: Deleted %d users, added %d users", len(deleted), len(added))
	}

	return nil
}

func (c *WireGuardController) reportTask() error {
	reportMin := 0
	if c.info.TrafficReportThreshold > 0 {
		reportMin = c.info.TrafficReportThreshold
	}

	// Get traffic from WireGuard core
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
			}).Info("WireGuard: Report user traffic failed")
		} else {
			log.WithField("node", c.tag).Infof("WireGuard: Reported traffic for %d users", len(userTraffic))
		}
	}

	// Get online users from WireGuard core
	onlineUsers := c.wgCore.GetOnlineUsers()

	// Filter out users with no actual traffic
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

	if c.isPrimaryReporter {
		// Report online users
		if err := c.apiClient.ReportNodeOnlineUsers(&result); err != nil {
			log.WithFields(log.Fields{
				"tag": c.tag,
				"err": err,
			}).Info("WireGuard: Report online users failed")
		} else {
			log.WithField("node", c.tag).Infof("WireGuard: Total %d online users, %d reported", len(onlineUsers), len(result))
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

func compareWGUserList(old, new []panel.UserInfo) (deleted, added []panel.UserInfo) {
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

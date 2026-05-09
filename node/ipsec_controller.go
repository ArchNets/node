package node

import (
	"fmt"
	"strconv"
	"time"

	"github.com/archnets/node/api/panel"
	"github.com/archnets/node/common/serverstatus"
	"github.com/archnets/node/common/task"
	vCore "github.com/archnets/node/core"
	"github.com/archnets/node/limiter"
	log "github.com/sirupsen/logrus"
)

// IPsecController manages IKEv2/L2TP protocol nodes.
type IPsecController struct {
	tag       string
	info      *panel.NodeInfo
	apiClient *panel.ClientV1
	ipsecCore *vCore.IPsecCore
	limiter   *limiter.Limiter

	userList                []panel.UserInfo
	userListMonitorPeriodic *task.Task
	userReportPeriodic      *task.Task
	isPrimaryReporter       bool
}

// NewIPsecController creates a new IPsec controller.
func NewIPsecController(apiClient *panel.ClientV1, info *panel.NodeInfo, isPrimaryReporter bool) *IPsecController {
	return &IPsecController{
		tag:               generateIPsecTag(info),
		info:              info,
		apiClient:         apiClient,
		isPrimaryReporter: isPrimaryReporter,
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

	// Get PSK and Auth from protocol config
	psk := "archnet-default-psk"
	authMethod := "eap-mschapv2"
	l2tpSecret := ""
	mode := "ikev2"

	if c.info.Type == "l2tp" {
		mode = "l2tp"
	}

	if c.info.Protocol != nil {
		if c.info.Protocol.IPsecPSK != "" {
			psk = c.info.Protocol.IPsecPSK
		}
		if c.info.Protocol.L2TPSharedSecret != "" {
			l2tpSecret = c.info.Protocol.L2TPSharedSecret
		}
		if c.info.Protocol.IPsecAuthMethod != "" {
			authMethod = c.info.Protocol.IPsecAuthMethod
		}
	}

	// Create and start IPsec core
	c.ipsecCore = vCore.NewIPsecCore(c.tag, mode, psk, l2tpSecret, authMethod)
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

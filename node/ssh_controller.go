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

// SSHController manages SSH protocol nodes
type SSHController struct {
	tag       string
	info      *panel.NodeInfo
	apiClient *panel.ClientV1
	sshCore   *vCore.SSHCore
	limiter   *limiter.Limiter

	userList                []panel.UserInfo
	userListMonitorPeriodic *task.Task
	userReportPeriodic      *task.Task
	isPrimaryReporter       bool
}

// NewSSHController creates a new SSH controller
func NewSSHController(apiClient *panel.ClientV1, info *panel.NodeInfo, isPrimaryReporter bool) *SSHController {
	return &SSHController{
		tag:               generateSSHTag(info),
		info:              info,
		apiClient:         apiClient,
		isPrimaryReporter: isPrimaryReporter,
	}
}

func generateSSHTag(info *panel.NodeInfo) string {
	return "ssh-" + strconv.Itoa(info.Id) + "-" + strconv.Itoa(info.Protocol.Port)
}

// Start starts the SSH controller
func (c *SSHController) Start() error {
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

	// Determine host key path
	hostKeyPath := ""
	udpgwAddr := ""
	if c.info.Protocol != nil {
		hostKeyPath = c.info.Protocol.SSHHostKeyPath
		udpgwAddr = c.info.Protocol.SSHUdpgwAddr
	}

	// Create and start SSH server
	sshCore, err := vCore.NewSSHCore(c.tag, c.info.Protocol.Port, hostKeyPath, udpgwAddr)
	if err != nil {
		return err
	}
	c.sshCore = sshCore
	c.sshCore.SetLimiter(c.limiter)

	// Add initial users
	c.sshCore.AddUsers(users)

	// Start SSH server
	if err := c.sshCore.Start(); err != nil {
		return err
	}

	// Start background tasks
	c.startTasks()

	log.WithFields(log.Fields{
		"tag":       c.tag,
		"port":      c.info.Protocol.Port,
		"userCount": len(users),
	}).Info("SSH controller started")

	return nil
}

// Close stops the SSH controller
func (c *SSHController) Close() error {
	if c.userListMonitorPeriodic != nil {
		c.userListMonitorPeriodic.Close()
	}
	if c.userReportPeriodic != nil {
		c.userReportPeriodic.Close()
	}

	if c.sshCore != nil {
		c.sshCore.Stop()
	}

	limiter.DeleteLimiter(c.tag)

	log.WithField("tag", c.tag).Info("SSH controller closed")
	return nil
}

func (c *SSHController) startTasks() {
	// User list monitor task
	c.userListMonitorPeriodic = &task.Task{
		Interval: time.Duration(c.info.PullInterval) * time.Second,
		Execute:  c.userListMonitor,
	}
	_ = c.userListMonitorPeriodic.Start(false)
	log.WithField("node", c.tag).Info("SSH user list monitor task started")

	// Traffic report task
	c.userReportPeriodic = &task.Task{
		Interval: time.Duration(c.info.PushInterval) * time.Second,
		Execute:  c.reportTask,
	}
	_ = c.userReportPeriodic.Start(false)
	log.WithField("node", c.tag).Info("SSH traffic report task started")
}

func (c *SSHController) userListMonitor() error {
	// Get updated user list
	newUsers, err := c.apiClient.GetUserList()
	if err != nil {
		log.WithFields(log.Fields{
			"tag": c.tag,
			"err": err,
		}).Error("SSH: Get user list failed")
		return nil
	}

	// Get alive list
	newAlive, err := c.apiClient.GetUserAlive()
	if err != nil {
		log.WithFields(log.Fields{
			"tag": c.tag,
			"err": err,
		}).Error("SSH: Get alive list failed")
		return nil
	}

	// Update alive list
	if newAlive != nil {
		c.limiter.SetAliveList(newAlive)
	}

	// Check for changes (nil means 304 Not Modified)
	if newUsers == nil {
		return nil
	}

	deleted, added := diffUserList(c.userList, newUsers)

	if len(deleted) > 0 {
		c.sshCore.DelUsers(deleted)
		c.limiter.UpdateUser(c.tag, nil, deleted)
	}

	if len(added) > 0 {
		c.sshCore.AddUsers(added)
		c.limiter.UpdateUser(c.tag, added, nil)
	}

	c.userList = newUsers

	if len(added)+len(deleted) != 0 {
		log.WithField("node", c.tag).
			Infof("SSH: Deleted %d users, added %d users", len(deleted), len(added))
	}

	return nil
}

func (c *SSHController) reportTask() error {
	reportMin := 0
	if c.info.TrafficReportThreshold > 0 {
		reportMin = c.info.TrafficReportThreshold
	}

	// Get traffic from SSH core
	trafficMap := c.sshCore.GetTrafficAndReset()

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
			}).Info("SSH: Report user traffic failed")
		} else {
			log.WithField("node", c.tag).Infof("SSH: Reported traffic for %d users", len(userTraffic))
		}
	}

	// Get online users from SSH core
	onlineUsers := c.sshCore.GetOnlineUsers()

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
			}).Info("SSH: Report online users failed")
		} else {
			log.WithField("node", c.tag).Infof("SSH: Total %d online users, %d reported", len(onlineUsers), len(result))
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

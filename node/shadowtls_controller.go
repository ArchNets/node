package node

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/archnets/node/api/panel"
	"github.com/archnets/node/common/serverstatus"
	"github.com/archnets/node/common/task"
	vCore "github.com/archnets/node/core"
	"github.com/archnets/node/limiter"
	log "github.com/sirupsen/logrus"
)

// ShadowTLSController manages ShadowTLS protocol nodes
type ShadowTLSController struct {
	tag           string
	info          *panel.NodeInfo
	apiClient     *panel.ClientV1
	shadowtlsCore *vCore.ShadowTLSCore
	limiter       *limiter.Limiter

	userList                []panel.UserInfo
	userListMonitorPeriodic *task.Task
	userReportPeriodic      *task.Task
}

// NewShadowTLSController creates a new ShadowTLS controller
func NewShadowTLSController(apiClient *panel.ClientV1, info *panel.NodeInfo) *ShadowTLSController {
	return &ShadowTLSController{
		tag:       generateShadowTLSTag(info),
		info:      info,
		apiClient: apiClient,
	}
}

func generateShadowTLSTag(info *panel.NodeInfo) string {
	return "shadowtls-" + strconv.Itoa(info.Id) + "-" + strconv.Itoa(info.Protocol.Port)
}

// Start starts the ShadowTLS controller
func (c *ShadowTLSController) Start() error {
	// Get initial user list
	users, err := c.apiClient.GetUserList()
	if err != nil {
		return err
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

	// Get ShadowTLS-specific config - all fields required
	if c.info.Protocol == nil {
		return fmt.Errorf("ShadowTLS: protocol config is nil")
	}

	version := c.info.Protocol.ShadowTLSVersion
	if version < 1 || version > 3 {
		return fmt.Errorf("ShadowTLS: version must be 1, 2, or 3, got %d", version)
	}

	handshakeServer := strings.TrimSpace(c.info.Protocol.ShadowTLSHandshake)
	if handshakeServer == "" {
		return fmt.Errorf("ShadowTLS: handshake server is required (e.g., www.google.com:443)")
	}

	strictMode := c.info.Protocol.ShadowTLSStrictMode
	shadowsocksPort := c.info.Protocol.ShadowsocksPort

	// Validate shadowsocks port is set
	if shadowsocksPort <= 0 {
		return fmt.Errorf("ShadowTLS: shadowsocks_port is required (the local Shadowsocks port to forward to)")
	}

	// Create and start ShadowTLS server
	shadowtlsCore, err := vCore.NewShadowTLSCore(c.tag, c.info.Protocol.Port, version, handshakeServer, strictMode, shadowsocksPort)
	if err != nil {
		return err
	}

	c.shadowtlsCore = shadowtlsCore
	c.shadowtlsCore.SetLimiter(c.limiter)

	// Add initial users
	c.shadowtlsCore.AddUsers(users)

	// Start ShadowTLS server
	if err := c.shadowtlsCore.Start(); err != nil {
		return err
	}

	// Start background tasks
	c.startTasks()

	log.WithFields(log.Fields{
		"tag":       c.tag,
		"port":      c.info.Protocol.Port,
		"version":   version,
		"handshake": handshakeServer,
		"userCount": len(users),
	}).Info("ShadowTLS controller started")

	return nil
}

// Close stops the ShadowTLS controller
func (c *ShadowTLSController) Close() error {
	if c.userListMonitorPeriodic != nil {
		c.userListMonitorPeriodic.Close()
	}
	if c.userReportPeriodic != nil {
		c.userReportPeriodic.Close()
	}

	if c.shadowtlsCore != nil {
		c.shadowtlsCore.Stop()
	}

	limiter.DeleteLimiter(c.tag)

	log.WithField("tag", c.tag).Info("ShadowTLS controller closed")
	return nil
}

func (c *ShadowTLSController) startTasks() {
	// User list monitor task
	c.userListMonitorPeriodic = &task.Task{
		Interval: time.Duration(c.info.PullInterval) * time.Second,
		Execute:  c.userListMonitor,
	}
	_ = c.userListMonitorPeriodic.Start(false)
	log.WithField("node", c.tag).Info("ShadowTLS user list monitor task started")

	// Traffic report task
	c.userReportPeriodic = &task.Task{
		Interval: time.Duration(c.info.PushInterval) * time.Second,
		Execute:  c.reportTask,
	}
	_ = c.userReportPeriodic.Start(false)
	log.WithField("node", c.tag).Info("ShadowTLS traffic report task started")
}

func (c *ShadowTLSController) userListMonitor() error {
	// Get updated user list
	newUsers, err := c.apiClient.GetUserList()
	if err != nil {
		log.WithFields(log.Fields{
			"tag": c.tag,
			"err": err,
		}).Error("ShadowTLS: Get user list failed")
		return nil
	}

	// Get alive list
	newAlive, err := c.apiClient.GetUserAlive()
	if err != nil {
		log.WithFields(log.Fields{
			"tag": c.tag,
			"err": err,
		}).Error("ShadowTLS: Get alive list failed")
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

	deleted, added := compareShadowTLSUserList(c.userList, newUsers)

	if len(deleted) > 0 {
		c.shadowtlsCore.DelUsers(deleted)
		c.limiter.UpdateUser(c.tag, nil, deleted)
	}

	if len(added) > 0 {
		c.shadowtlsCore.AddUsers(added)
		c.limiter.UpdateUser(c.tag, added, nil)
	}

	c.userList = newUsers

	if len(added)+len(deleted) != 0 {
		log.WithField("node", c.tag).
			Infof("ShadowTLS: Deleted %d users, added %d users", len(deleted), len(added))
	}

	return nil
}

func (c *ShadowTLSController) reportTask() error {
	reportMin := 0
	if c.info.TrafficReportThreshold > 0 {
		reportMin = c.info.TrafficReportThreshold
	}

	// Get traffic from ShadowTLS core
	trafficMap := c.shadowtlsCore.GetTrafficAndReset()

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
			}).Info("ShadowTLS: Report user traffic failed")
		} else {
			log.WithField("node", c.tag).Infof("ShadowTLS: Reported traffic for %d users", len(userTraffic))
		}
	}

	// Get online users from ShadowTLS core
	onlineUsers := c.shadowtlsCore.GetOnlineUsers()

	// Report online users
	if err := c.apiClient.ReportNodeOnlineUsers(&onlineUsers); err != nil {
		log.WithFields(log.Fields{
			"tag": c.tag,
			"err": err,
		}).Info("ShadowTLS: Report online users failed")
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

	return nil
}

func compareShadowTLSUserList(old, new []panel.UserInfo) (deleted, added []panel.UserInfo) {
	oldMap := make(map[string]int)
	for i, user := range old {
		key := user.Uuid + strconv.Itoa(user.SpeedLimit)
		oldMap[key] = i
	}

	for _, user := range new {
		key := user.Uuid + strconv.Itoa(user.SpeedLimit)
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

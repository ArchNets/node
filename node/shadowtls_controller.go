package node

import (
	"fmt"
	"net"
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
	protocolIndex           int
	perProtocolUserList     bool
	isPrimaryReporter       bool
}

// NewShadowTLSController creates a new ShadowTLS controller
func NewShadowTLSController(apiClient *panel.ClientV1, info *panel.NodeInfo, protocolIndex int, perProtocolUserList bool, isPrimaryReporter bool) *ShadowTLSController {
	return &ShadowTLSController{
		tag:                 generateShadowTLSTag(info),
		info:                info,
		apiClient:           apiClient,
		protocolIndex:       protocolIndex,
		perProtocolUserList: perProtocolUserList,
		isPrimaryReporter:   isPrimaryReporter,
	}
}

func generateShadowTLSTag(info *panel.NodeInfo) string {
	return "shadowtls-" + strconv.Itoa(info.Id) + "-" + strconv.Itoa(info.Protocol.Port)
}

// What changed: Updated version validation to strictly allow only versions 2 and 3 with an explicit error, and added a startup reachability self-check warning for local Shadowsocks port.
// Why: Sing-shadowtls only supports versions 2 and 3, and checking Shadowsocks port reachability at startup alerts admins early if the local inbound is down.
func (c *ShadowTLSController) Start() error {
	// Get initial user list
	var protoName string
	if c.perProtocolUserList {
		protoName = c.getIndexedProtocolName()
	} else {
		protoName = c.info.Type
	}
	users, err := c.apiClient.GetUserList(protoName)
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
	c.limiter = limiter.AddLimiter(c.info.Type, c.tag, users, aliveList)

	// Get ShadowTLS-specific config - all fields required
	if c.info.Protocol == nil {
		return fmt.Errorf("ShadowTLS: protocol config is nil")
	}

	version := c.info.Protocol.ShadowTLSVersion
	if version < 2 || version > 3 {
		return fmt.Errorf("ShadowTLS: only versions 2 and 3 are supported, got %d", version)
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

	// Startup self-check: verify local Shadowsocks inbound reachability
	ssAddr := fmt.Sprintf("127.0.0.1:%d", shadowsocksPort)
	if conn, err := net.DialTimeout("tcp", ssAddr, 3*time.Second); err != nil {
		log.WithFields(log.Fields{
			"tag":    c.tag,
			"ssPort": shadowsocksPort,
			"err":    err,
		}).Warnf("ShadowTLS: local Shadowsocks inbound is not reachable on port %d; ShadowTLS will not work until it is running", shadowsocksPort)
	} else {
		conn.Close()
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
	var protoName string
	if c.perProtocolUserList {
		protoName = c.getIndexedProtocolName()
	} else {
		protoName = c.info.Type
	}
	newUsers, err := c.apiClient.GetUserList(protoName)
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
		c.limiter.SetAliveList(newAlive)
	}

	// Check for changes (nil means 304 Not Modified)
	if newUsers == nil {
		return nil
	}

	deleted, added := diffUserList(c.userList, newUsers)

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
		err := c.apiClient.ReportUserTraffic(c.getIndexedProtocolName(), &userTraffic)
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
	protocolName := c.getIndexedProtocolName()
	if err := c.apiClient.ReportNodeOnlineUsers(protocolName, &onlineUsers); err != nil {
		log.WithFields(log.Fields{
			"tag": c.tag,
			"err": err,
		}).Info("ShadowTLS: Report online users failed")
	}

	if c.isPrimaryReporter {
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

func (c *ShadowTLSController) getIndexedProtocolName() string {
	return getIndexedProtocolName(c.info.Type, c.protocolIndex)
}

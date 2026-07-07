package node

import (
	"fmt"
	"path/filepath"
	"strconv"
	"time"

	"github.com/archnets/node/api/panel"
	certutil "github.com/archnets/node/common/cert"
	"github.com/archnets/node/common/serverstatus"
	"github.com/archnets/node/common/task"
	vCore "github.com/archnets/node/core"
	"github.com/archnets/node/limiter"
	log "github.com/sirupsen/logrus"
)

// OpenVPNController manages OpenVPN protocol nodes.
type OpenVPNController struct {
	tag         string
	info        *panel.NodeInfo
	apiClient   *panel.ClientV1
	openvpnCore *vCore.OpenVPNCore
	limiter     *limiter.Limiter
	xrayCore    *vCore.XrayCore

	userList                []panel.UserInfo
	userListMonitorPeriodic *task.Task
	userReportPeriodic      *task.Task
	isPrimaryReporter       bool
}

func NewOpenVPNController(xrayCore *vCore.XrayCore, apiClient *panel.ClientV1, info *panel.NodeInfo, isPrimaryReporter bool) *OpenVPNController {
	return &OpenVPNController{
		tag:               generateOpenVPNTag(info),
		info:              info,
		apiClient:         apiClient,
		xrayCore:          xrayCore,
		isPrimaryReporter: isPrimaryReporter,
	}
}

func generateOpenVPNTag(info *panel.NodeInfo) string {
	return "openvpn-" + strconv.Itoa(info.Id) + "-" + strconv.Itoa(info.Protocol.Port)
}

// Start starts the OpenVPN controller.
func (c *OpenVPNController) Start() error {
	users, err := c.apiClient.GetUserList()
	if err != nil {
		log.WithError(err).Warn("Failed to fetch initial user list, starting with empty list")
		users = []panel.UserInfo{}
	}
	c.userList = users

	aliveList, err := c.apiClient.GetUserAlive()
	if err != nil {
		log.WithError(err).Warn("Failed to get alive list")
		aliveList = make(map[int]int)
	}

	c.limiter = limiter.AddLimiter(c.info.Type, c.tag, users, aliveList)

	var certFile, keyFile string
	if c.info.Protocol.CertMode != "" && c.info.Protocol.CertMode != "none" {
		ctrl := &Controller{info: c.info, tag: c.tag}
		if err := ctrl.requestCert(); err != nil {
			return fmt.Errorf("cert setup failed: %w", err)
		}
		certFile, keyFile = certutil.GetCertPaths(c.info.Protocol.SNI, c.info.Type, c.info.Id)
	}

	proto := c.info.Protocol.OpenVPNProto
	if proto == "" {
		proto = "udp"
	}

	// TODO: Re-enable TPROXY once Xray routing for OpenVPN traffic is debugged.
	// For now, skip TPROXY and let setupNAT use MASQUERADE (direct NAT) instead.
	// The TProxyPort stays at 0, so setupNAT takes the MASQUERADE-only path.
	//
	// tproxyPort := nextTProxyPort()
	// ... (Xray dokodemo-door inbound on tproxyPort) ...
	// c.openvpnCore.SetTProxyPort(tproxyPort)

	workDir := filepath.Join("/etc/archnets/openvpn", c.tag)

	openvpnCore, err := vCore.NewOpenVPNCore(
		c.tag,
		c.info.Protocol.Port,
		proto,
		workDir,
		certFile,
		keyFile,
		c.info.Protocol.OpenVPNTlsCrypt,
	)
	if err != nil {
		return err
	}
	c.openvpnCore = openvpnCore
	// TProxyPort left at 0 — setupNAT will use MASQUERADE only
	c.openvpnCore.SetLimiter(c.limiter)
	c.openvpnCore.AddUsers(users)

	if err := c.openvpnCore.Start(); err != nil {
		return err
	}

	c.startTasks()

	log.WithFields(log.Fields{
		"tag":       c.tag,
		"port":      c.info.Protocol.Port,
		"userCount": len(users),
	}).Info("OpenVPN controller started")

	return nil
}

// Close stops the OpenVPN controller.
func (c *OpenVPNController) Close() error {
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

	if c.openvpnCore != nil {
		c.openvpnCore.Stop()
	}
	limiter.DeleteLimiter(c.tag)

	log.WithField("tag", c.tag).Info("OpenVPN controller closed")
	return nil
}

func (c *OpenVPNController) startTasks() {
	c.userListMonitorPeriodic = &task.Task{
		Interval: time.Duration(c.info.PullInterval) * time.Second,
		Execute:  c.userListMonitor,
	}
	_ = c.userListMonitorPeriodic.Start(false)

	c.userReportPeriodic = &task.Task{
		Interval: time.Duration(c.info.PushInterval) * time.Second,
		Execute:  c.reportTask,
	}
	_ = c.userReportPeriodic.Start(false)
}

func (c *OpenVPNController) userListMonitor() error {
	newUsers, err := c.apiClient.GetUserList()
	if err != nil {
		log.WithFields(log.Fields{"tag": c.tag, "err": err}).Error("OpenVPN: Get user list failed")
		return nil
	}

	newAlive, err := c.apiClient.GetUserAlive()
	if err != nil {
		log.WithFields(log.Fields{"tag": c.tag, "err": err}).Error("OpenVPN: Get alive list failed")
		return nil
	}
	if newAlive != nil {
		c.limiter.AliveList = newAlive
	}

	if newUsers == nil {
		return nil // 304 Not Modified
	}

	deleted, added := compareOpenVPNUserList(c.userList, newUsers)

	if len(deleted) > 0 {
		c.openvpnCore.DelUsers(deleted)
		c.limiter.UpdateUser(c.tag, nil, deleted)
	}
	if len(added) > 0 {
		c.openvpnCore.AddUsers(added)
		c.limiter.UpdateUser(c.tag, added, nil)
	}

	c.userList = newUsers

	if len(added)+len(deleted) != 0 {
		log.WithField("node", c.tag).Infof("OpenVPN: Deleted %d users, added %d users", len(deleted), len(added))
	}
	return nil
}

func (c *OpenVPNController) reportTask() error {
	reportMin := 0
	if c.info.TrafficReportThreshold > 0 {
		reportMin = c.info.TrafficReportThreshold
	}

	trafficMap := c.openvpnCore.GetTrafficAndReset()

	var userTraffic []panel.UserTraffic
	for uid, traffic := range trafficMap {
		total := traffic.Upload + traffic.Download
		if total >= int64(reportMin) {
			userTraffic = append(userTraffic, panel.UserTraffic{UID: uid, Upload: traffic.Upload, Download: traffic.Download})
		}
	}

	if len(userTraffic) > 0 {
		if err := c.apiClient.ReportUserTraffic(&userTraffic); err != nil {
			log.WithFields(log.Fields{"tag": c.tag, "err": err}).Info("OpenVPN: Report user traffic failed")
		} else {
			log.WithField("node", c.tag).Infof("OpenVPN: Reported traffic for %d users", len(userTraffic))
		}
	}

	onlineUsers := c.openvpnCore.GetOnlineUsers()

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
		if err := c.apiClient.ReportNodeOnlineUsers(&result); err != nil {
			log.WithFields(log.Fields{"tag": c.tag, "err": err}).Info("OpenVPN: Report online users failed")
		} else {
			log.WithField("node", c.tag).Infof("OpenVPN: Total %d online users, %d reported", len(onlineUsers), len(result))
		}

		CPU, Mem, Disk, Uptime, err := serverstatus.GetSystemInfo()
		if err != nil {
			log.Print(err)
		}
		if err := c.apiClient.ReportNodeStatus(&panel.NodeStatus{CPU: CPU, Mem: Mem, Disk: Disk, Uptime: Uptime}); err != nil {
			log.Print(err)
		}
	}

	return nil
}

func compareOpenVPNUserList(old, new []panel.UserInfo) (deleted, added []panel.UserInfo) {
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

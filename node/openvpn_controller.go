package node

import (
	"fmt"
	"net"
	"path/filepath"
	"strconv"
	"strings"
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
	tag          string
	xrayTag      string // Xray inbound tag matching panel routing rules (e.g. "openvpn:28")
	info         *panel.NodeInfo
	apiClient    *panel.ClientV1
	openvpnCores []*vCore.OpenVPNCore
	limiter      *limiter.Limiter
	xrayCore     *vCore.XrayCore

	userList                []panel.UserInfo
	userListMonitorPeriodic *task.Task
	userReportPeriodic      *task.Task
	protocolIndex           int
	isPrimaryReporter       bool
	tproxyEnabled           bool
}

func NewOpenVPNController(xrayCore *vCore.XrayCore, apiClient *panel.ClientV1, info *panel.NodeInfo, protocolIndex int, isPrimaryReporter bool) *OpenVPNController {
	return &OpenVPNController{
		tag:               generateOpenVPNTag(info),
		xrayTag:           generateOpenVPNXrayTag(info),
		info:              info,
		apiClient:         apiClient,
		xrayCore:          xrayCore,
		protocolIndex:     protocolIndex,
		isPrimaryReporter: isPrimaryReporter,
	}
}

func generateOpenVPNTag(info *panel.NodeInfo) string {
	return "openvpn-" + strconv.Itoa(info.Id) + "-" + strconv.Itoa(info.Protocol.Port)
}

// generateOpenVPNXrayTag builds the panel-facing Xray inbound tag. Panel
// routing rules reference inbounds as "type:nodeId" (e.g. "openvpn:28") —
// the same convention the IPsec controller uses — NOT the internal tag.
// Registering the dokodemo-door inbound under the internal tag
// ("openvpn-<id>-<port>") was the original TPROXY bug: no panel routing rule
// matched it, so every client packet fell through to Xray's default outbound
// and the tunnel appeared dead.
func generateOpenVPNXrayTag(info *panel.NodeInfo) string {
	protoType := "openvpn"
	if info.Protocol != nil && info.Protocol.Type != "" {
		protoType = info.Protocol.Type
	}
	return protoType + ":" + strconv.Itoa(info.Id)
}

// Start starts the OpenVPN controller.
func (c *OpenVPNController) Start() error {
	protoName := c.getIndexedProtocolName()
	users, err := c.apiClient.GetUserList(protoName)
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

	proto := strings.ToLower(strings.TrimSpace(c.info.Protocol.OpenVPNProto))
	if proto == "" {
		proto = "both"
	}

	baseSubnet := "10.9.0.0/24"
	if c.info.Protocol.OpenVPNSubnet != "" {
		baseSubnet = c.info.Protocol.OpenVPNSubnet
	}

	type instanceConfig struct {
		proto  string
		port   int
		subnet string
	}
	var instances []instanceConfig
	udpSubnet, tcpSubnet := deriveSubnets(baseSubnet)
	tcpPort := c.info.Protocol.OpenVPNTCPPort
	if tcpPort <= 0 {
		tcpPort = c.info.Protocol.Port
	}

	switch proto {
	case "udp":
		instances = append(instances, instanceConfig{proto: "udp", port: c.info.Protocol.Port, subnet: baseSubnet})
	case "tcp":
		instances = append(instances, instanceConfig{proto: "tcp", port: tcpPort, subnet: baseSubnet})
	case "both":
		fallthrough
	default:
		instances = append(instances,
			instanceConfig{proto: "udp", port: c.info.Protocol.Port, subnet: udpSubnet},
			instanceConfig{proto: "tcp", port: tcpPort, subnet: tcpSubnet},
		)
	}

	// Route OpenVPN client traffic through Xray's routing engine via TPROXY if enabled.
	var tproxyPort int
	if c.info.Protocol.EnableTProxy {
		var err error
		tproxyPort, err = addTProxyInbound(c.xrayCore, c.xrayTag, c.info.Protocol.TProxyPort)
		if err != nil {
			log.WithError(err).WithField("tag", c.xrayTag).Error(
				"TPROXY setup failed — OpenVPN will use MASQUERADE only")
		} else {
			c.tproxyEnabled = true
			log.WithFields(log.Fields{"tag": c.xrayTag, "tproxyPort": tproxyPort}).Info("OpenVPN TPROXY inbound registered")
		}
	}

	for _, inst := range instances {
		instTag := fmt.Sprintf("%s-%s", c.tag, inst.proto)
		workDir := filepath.Join("/etc/archnets/openvpn", instTag)

		openvpnCore, err := vCore.NewOpenVPNCore(
			instTag,
			inst.port,
			inst.proto,
			inst.subnet,
			workDir,
			certFile,
			keyFile,
			c.info.Protocol.OpenVPNTlsCrypt,
		)
		if err != nil {
			c.cleanupCores()
			return err
		}

		openvpnCore.DropICMPUnreachable = c.info.Protocol.DropICMPUnreachable

		if c.tproxyEnabled {
			openvpnCore.SetTProxyConfig(
				tproxyPort,
				c.info.Protocol.TProxySubnet,
				c.info.Protocol.TProxyBypassUDP,
				c.info.Protocol.DropICMPUnreachable,
			)
		}

		openvpnCore.SetLimiter(c.limiter)
		openvpnCore.AddUsers(users)

		if err := openvpnCore.Start(); err != nil {
			c.cleanupCores()
			return err
		}
		c.openvpnCores = append(c.openvpnCores, openvpnCore)
	}

	c.startTasks()

	log.WithFields(log.Fields{
		"tag":       c.tag,
		"proto":     proto,
		"instances": len(instances),
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

	// Remove Xray TPROXY inbound (registered under xrayTag, not internal tag)
	if c.tproxyEnabled {
		if err := c.xrayCore.RemoveInbound(c.xrayTag); err != nil {
			log.WithError(err).WithField("tag", c.xrayTag).Warn("Failed to remove Xray inbound")
		}
	}

	c.cleanupCores()
	limiter.DeleteLimiter(c.tag)

	log.WithField("tag", c.tag).Info("OpenVPN controller closed")
	return nil
}

func (c *OpenVPNController) cleanupCores() {
	for _, core := range c.openvpnCores {
		if core != nil {
			core.Stop()
		}
	}
	c.openvpnCores = nil
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
	protoName := c.getIndexedProtocolName()
	newUsers, err := c.apiClient.GetUserList(protoName)
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
		c.limiter.SetAliveList(newAlive)
	}

	if newUsers == nil {
		return nil // 304 Not Modified
	}

	deleted, added := diffUserList(c.userList, newUsers)

	if len(deleted) > 0 {
		for _, core := range c.openvpnCores {
			core.DelUsers(deleted)
		}
		c.limiter.UpdateUser(c.tag, nil, deleted)
	}
	if len(added) > 0 {
		for _, core := range c.openvpnCores {
			core.AddUsers(added)
		}
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

	trafficMap := make(map[int]*vCore.UserTraffic)
	for _, core := range c.openvpnCores {
		for uid, t := range core.GetTrafficAndReset() {
			if existing, ok := trafficMap[uid]; ok {
				existing.Upload += t.Upload
				existing.Download += t.Download
			} else {
				trafficMap[uid] = &vCore.UserTraffic{
					Upload:   t.Upload,
					Download: t.Download,
				}
			}
		}
	}

	var userTraffic []panel.UserTraffic
	for uid, traffic := range trafficMap {
		total := traffic.Upload + traffic.Download
		if total >= int64(reportMin) {
			userTraffic = append(userTraffic, panel.UserTraffic{UID: uid, Upload: traffic.Upload, Download: traffic.Download})
		}
	}

	if len(userTraffic) > 0 {
		if err := c.apiClient.ReportUserTraffic(c.getIndexedProtocolName(), &userTraffic); err != nil {
			log.WithFields(log.Fields{"tag": c.tag, "err": err}).Info("OpenVPN: Report user traffic failed")
		} else {
			log.WithField("node", c.tag).Infof("OpenVPN: Reported traffic for %d users", len(userTraffic))
		}
	}

	var onlineUsers []panel.OnlineUser
	seenOnline := make(map[int]bool)
	for _, core := range c.openvpnCores {
		for _, ou := range core.GetOnlineUsers() {
			if !seenOnline[ou.UID] {
				seenOnline[ou.UID] = true
				onlineUsers = append(onlineUsers, ou)
			}
		}
	}

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

	// Report online users
	protocolName := c.getIndexedProtocolName()
	if err := c.apiClient.ReportNodeOnlineUsers(protocolName, &result); err != nil {
		log.WithFields(log.Fields{"tag": c.tag, "err": err}).Info("OpenVPN: Report online users failed")
	} else {
		log.WithField("node", c.tag).Infof("OpenVPN: Total %d online users, %d reported", len(onlineUsers), len(result))
	}

	if c.isPrimaryReporter {
		CPU, Mem, Disk, Uptime, err := serverstatus.GetSystemInfo()
		if err != nil {
			log.Print(err)
		}
		if err := c.apiClient.ReportNodeStatus(&panel.NodeStatus{CPU: CPU, Mem: Mem, Disk: Disk, Uptime: Uptime, PingMs: c.apiClient.GetLastApiLatency()}); err != nil {
			log.Print(err)
		}
	}

	return nil
}

func (c *OpenVPNController) getIndexedProtocolName() string {
	return getIndexedProtocolName(c.info.Type, c.protocolIndex)
}

func deriveSubnets(baseSubnet string) (udpSubnet, tcpSubnet string) {
	if baseSubnet == "" {
		baseSubnet = "10.9.0.0/24"
	}
	ip, pool, err := net.ParseCIDR(baseSubnet)
	if err != nil || ip.To4() == nil {
		return "10.9.1.0/24", "10.9.2.0/24"
	}
	ipv4 := ip.To4()
	udpSubnet = pool.String()
	third := int(ipv4[2]) + 1
	if third > 254 {
		third = int(ipv4[2]) - 1
	}
	tcpSubnet = fmt.Sprintf("%d.%d.%d.0/24", ipv4[0], ipv4[1], third)
	return udpSubnet, tcpSubnet
}

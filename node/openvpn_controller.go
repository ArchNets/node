package node

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/archnets/node/api/panel"
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

	closed            atomic.Bool
	reconcileMu       sync.Mutex
	reconcileFailures map[string]int
	recoveryActive    map[string]bool
	reportMu          sync.Mutex
	pendingTraffic    []panel.UserTraffic
	pendingBatchID    string
	pendingProtocol   string
}

type openVPNTrafficBatch struct {
	ID       string              `json:"id"`
	Protocol string              `json:"protocol"`
	Traffic  []panel.UserTraffic `json:"traffic"`
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
		reconcileFailures: make(map[string]int),
		recoveryActive:    make(map[string]bool),
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
	if err := c.loadPendingTraffic(); err != nil {
		log.WithError(err).WithField("tag", c.tag).Warn("OpenVPN: failed to load pending traffic batch journal; discarding corrupt file")
		_ = c.removePendingTraffic()
	}

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
		var err error
		certFile, keyFile, err = EnsureNodeCertificate(c.info, c.tag)
		if err != nil {
			return fmt.Errorf("cert setup failed: %w", err)
		}
	} else {
		return fmt.Errorf("openvpn requires CA certificate and key; cert_mode cannot be empty or 'none'")
	}

	proto := strings.ToLower(strings.TrimSpace(c.info.Protocol.OpenVPNProto))
	if proto == "" {
		proto = "udp"
	}

	baseSubnet := "10.9.0.0/16"
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
		instances = append(instances,
			instanceConfig{proto: "udp", port: c.info.Protocol.Port, subnet: udpSubnet},
			instanceConfig{proto: "tcp", port: tcpPort, subnet: tcpSubnet},
		)
	default:
		instances = append(instances, instanceConfig{proto: "udp", port: c.info.Protocol.Port, subnet: baseSubnet})
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

		openvpnCore.LimiterTag = c.tag
		openvpnCore.DropICMPUnreachable = c.info.Protocol.DropICMPUnreachable
		openvpnCore.TunMTU = c.info.Protocol.OpenVPNTunMTU
		openvpnCore.TCPMSS = c.info.Protocol.OpenVPNTCPMSS
		openvpnCore.Sndbuf = c.info.Protocol.OpenVPNSndbuf
		openvpnCore.Rcvbuf = c.info.Protocol.OpenVPNRcvbuf
		openvpnCore.TxQueueLen = c.info.Protocol.OpenVPNTxQueueLen
		byteCountInterval := c.info.PushInterval
		if byteCountInterval < 30 {
			byteCountInterval = 30
		} else if byteCountInterval > 60 {
			byteCountInterval = 60
		}
		openvpnCore.SetByteCountInterval(byteCountInterval)
		core := openvpnCore
		core.OnUnexpectedExit = func() {
			c.scheduleUnexpectedRestart(core)
		}

		if c.tproxyEnabled {
			tproxySubnet := inst.subnet
			if c.info.Protocol.TProxySubnet != "" && proto != "both" {
				tproxySubnet = c.info.Protocol.TProxySubnet
			}
			openvpnCore.SetTProxyConfig(
				tproxyPort,
				tproxySubnet,
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

func (c *OpenVPNController) scheduleUnexpectedRestart(core *vCore.OpenVPNCore) {
	c.reconcileMu.Lock()
	if c.closed.Load() || c.recoveryActive[core.Tag] {
		c.reconcileMu.Unlock()
		return
	}
	if c.recoveryActive == nil {
		c.recoveryActive = make(map[string]bool)
	}
	c.recoveryActive[core.Tag] = true
	c.reconcileMu.Unlock()
	go c.restartAfterUnexpectedExit(core)
}

func (c *OpenVPNController) restartAfterUnexpectedExit(core *vCore.OpenVPNCore) {
	defer func() {
		c.reconcileMu.Lock()
		delete(c.recoveryActive, core.Tag)
		c.reconcileMu.Unlock()
	}()

	delay := time.Second
	for {
		if c.closed.Load() {
			return
		}

		c.reconcileMu.Lock()
		if c.closed.Load() || core.IsRunning() {
			c.reconcileMu.Unlock()
			return
		}
		err := core.Restart()
		if err == nil {
			c.reconcileFailures[core.Tag] = 0
			c.reconcileMu.Unlock()
			log.WithField("tag", core.Tag).Info("OpenVPN core recovered after unexpected exit")
			return
		}

		c.reconcileFailures[core.Tag]++
		failures := c.reconcileFailures[core.Tag]
		c.reconcileMu.Unlock()
		log.WithError(err).WithFields(log.Fields{
			"tag":      core.Tag,
			"retry_in": delay.String(),
			"failures": failures,
		}).Error("OpenVPN recovery attempt failed")
		time.Sleep(delay)
		if delay < time.Minute {
			delay *= 2
			if delay > time.Minute {
				delay = time.Minute
			}
		}
	}
}

// Close stops the OpenVPN controller.
func (c *OpenVPNController) Close() error {
	c.closed.Store(true)

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
	c.reconcileMu.Lock()
	defer c.reconcileMu.Unlock()

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

func (c *OpenVPNController) reconcileCores() {
	if c.closed.Load() {
		return
	}

	c.reconcileMu.Lock()
	defer c.reconcileMu.Unlock()

	for _, core := range c.openvpnCores {
		if core == nil {
			continue
		}
		if c.recoveryActive[core.Tag] {
			continue
		}
		if core.IsRunning() {
			if c.reconcileFailures[core.Tag] > 0 {
				c.reconcileFailures[core.Tag] = 0
			}
			continue
		}

		if c.closed.Load() {
			return
		}

		c.reconcileFailures[core.Tag]++
		failures := c.reconcileFailures[core.Tag]

		// Throttled logging: log on 1st failure and every 10th failure
		if failures == 1 || failures%10 == 0 {
			log.WithFields(log.Fields{
				"tag":      core.Tag,
				"failures": failures,
			}).Warn("OpenVPN core died, reconciling (restarting)...")
		}

		if err := core.Restart(); err != nil {
			if failures == 1 || failures%10 == 0 {
				log.WithError(err).WithFields(log.Fields{
					"tag":      core.Tag,
					"failures": failures,
				}).Error("Failed to restart dead OpenVPN core")
			}
		} else {
			log.WithField("tag", core.Tag).Info("Successfully restarted dead OpenVPN core")
			c.reconcileFailures[core.Tag] = 0
		}
	}
}

func (c *OpenVPNController) userListMonitor() error {
	if c.closed.Load() {
		return nil
	}

	c.reconcileCores()

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
	genDel, genAdd, limDel, limAdd := splitTunnelUserDiff(deleted, added)

	if len(genDel) > 0 {
		for _, core := range c.openvpnCores {
			core.DelUsers(genDel)
		}
		c.limiter.UpdateUser(c.tag, nil, genDel)
	}
	if len(genAdd) > 0 {
		for _, core := range c.openvpnCores {
			core.AddUsers(genAdd)
		}
		c.limiter.UpdateUser(c.tag, genAdd, nil)
	}
	if len(limDel) > 0 || len(limAdd) > 0 {
		c.limiter.UpdateUser(c.tag, limAdd, limDel)
	}

	c.userList = newUsers

	if len(added)+len(deleted) != 0 {
		log.WithField("node", c.tag).Infof("OpenVPN: Deleted %d users, added %d users", len(deleted), len(added))
	}
	return nil
}

func (c *OpenVPNController) reportTask() error {
	if c.closed.Load() {
		return nil
	}
	c.reportMu.Lock()
	defer c.reportMu.Unlock()

	reportMin := 0
	if c.info.TrafficReportThreshold > 0 {
		reportMin = c.info.TrafficReportThreshold
	}

	// Do not drain more counters while a batch is waiting for acknowledgement.
	// Keeping the same batch ID across retries lets the backend deduplicate an
	// accepted request whose response was lost.
	if len(c.pendingTraffic) == 0 {
		var batchID [16]byte
		if _, err := rand.Read(batchID[:]); err != nil {
			log.WithError(err).WithField("tag", c.tag).Error("OpenVPN: failed to generate traffic batch ID")
			return nil
		}
		trafficMap := make(map[int]*vCore.UserTraffic)
		for _, core := range c.openvpnCores {
			for uid, t := range core.GetTrafficAndReset() {
				if existing, ok := trafficMap[uid]; ok {
					existing.Upload += t.Upload
					existing.Download += t.Download
				} else {
					trafficMap[uid] = &vCore.UserTraffic{Upload: t.Upload, Download: t.Download}
				}
			}
		}

		for uid, traffic := range trafficMap {
			if traffic.Upload+traffic.Download >= int64(reportMin) {
				c.pendingTraffic = append(c.pendingTraffic, panel.UserTraffic{
					UID: uid, Upload: traffic.Upload, Download: traffic.Download,
				})
			}
		}
		if len(c.pendingTraffic) > 0 {
			c.pendingBatchID = hex.EncodeToString(batchID[:])
			c.pendingProtocol = c.getIndexedProtocolName()
		}
	}

	if len(c.pendingTraffic) > 0 {
		if err := c.persistPendingTraffic(); err != nil {
			log.WithError(err).WithField("tag", c.tag).Warn("OpenVPN: failed to persist pending traffic batch before send")
		}
		if err := c.apiClient.ReportUserTrafficBatch(c.pendingProtocol, c.pendingBatchID, &c.pendingTraffic); err != nil {
			log.WithFields(log.Fields{"tag": c.tag, "batch_id": c.pendingBatchID, "err": err}).Warn("OpenVPN: traffic batch retained for retry")
		} else {
			log.WithField("node", c.tag).Infof("OpenVPN: Reported traffic batch for %d users", len(c.pendingTraffic))
			if err := c.removePendingTraffic(); err != nil {
				log.WithFields(log.Fields{"tag": c.tag, "batch_id": c.pendingBatchID, "err": err}).Warn("OpenVPN: acknowledged batch journal could not be removed; it will be retried idempotently")
			} else {
				c.pendingTraffic = nil
				c.pendingBatchID = ""
				c.pendingProtocol = ""
			}
		}
	}

	var onlineUsers []panel.OnlineUser
	seenOnline := make(map[string]bool)
	for _, core := range c.openvpnCores {
		for _, ou := range core.GetOnlineUsers() {
			key := strconv.Itoa(ou.UID) + "\x00" + ou.IP
			if !seenOnline[key] {
				seenOnline[key] = true
				onlineUsers = append(onlineUsers, ou)
			}
		}
	}

	// Report online users
	protocolName := c.getIndexedProtocolName()
	if err := c.apiClient.ReportNodeOnlineUsers(protocolName, &onlineUsers); err != nil {
		log.WithFields(log.Fields{"tag": c.tag, "err": err}).Info("OpenVPN: Report online users failed")
	} else {
		log.WithField("node", c.tag).Infof("OpenVPN: Reported %d online sessions", len(onlineUsers))
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

func (c *OpenVPNController) trafficBatchPath() string {
	return filepath.Join("/etc/archnets/openvpn", c.tag+".traffic-pending.json")
}

func (c *OpenVPNController) loadPendingTraffic() error {
	data, err := os.ReadFile(c.trafficBatchPath())
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var batch openVPNTrafficBatch
	if err := json.Unmarshal(data, &batch); err != nil {
		return err
	}
	if batch.ID == "" || batch.Protocol == "" || len(batch.Traffic) == 0 {
		return fmt.Errorf("pending batch journal is missing its ID, protocol, or traffic entries")
	}
	c.pendingBatchID = batch.ID
	c.pendingProtocol = batch.Protocol
	c.pendingTraffic = batch.Traffic
	return nil
}

func (c *OpenVPNController) persistPendingTraffic() error {
	path := c.trafficBatchPath()
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".traffic-pending-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0600); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := json.NewEncoder(tmp).Encode(openVPNTrafficBatch{
		ID: c.pendingBatchID, Protocol: c.pendingProtocol, Traffic: c.pendingTraffic,
	}); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	return syncDirectory(dir)
}

func (c *OpenVPNController) removePendingTraffic() error {
	path := c.trafficBatchPath()
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return syncDirectory(filepath.Dir(path))
}

func syncDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func (c *OpenVPNController) getIndexedProtocolName() string {
	return getIndexedProtocolName(c.info.Type, c.protocolIndex)
}

func deriveSubnets(baseSubnet string) (udpSubnet, tcpSubnet string) {
	if baseSubnet == "" {
		baseSubnet = "10.9.0.0/16"
	}
	ip, pool, err := net.ParseCIDR(baseSubnet)
	if err != nil || ip.To4() == nil {
		return "10.9.0.0/17", "10.9.128.0/17"
	}
	ipv4 := ip.To4()
	ones, _ := pool.Mask.Size()
	if ones <= 16 {
		udpSubnet = fmt.Sprintf("%d.%d.0.0/17", ipv4[0], ipv4[1])
		tcpSubnet = fmt.Sprintf("%d.%d.128.0/17", ipv4[0], ipv4[1])
		return udpSubnet, tcpSubnet
	}
	// For /24 or smaller, use non-overlapping /24 blocks
	udpSubnet = pool.String()
	third := int(ipv4[2]) + 1
	if third > 254 {
		third = int(ipv4[2]) - 1
	}
	tcpSubnet = fmt.Sprintf("%d.%d.%d.0/24", ipv4[0], ipv4[1], third)
	return udpSubnet, tcpSubnet
}

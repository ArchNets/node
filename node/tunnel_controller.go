package node

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"sync"

	"github.com/archnets/node/api/panel"
	"github.com/archnets/node/common/installer"
	"github.com/archnets/node/common/task"
	"github.com/archnets/node/conf"
	log "github.com/sirupsen/logrus"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	xraystats "github.com/xtls/xray-core/features/stats"
	coreConf "github.com/xtls/xray-core/infra/conf"
	confserial "github.com/xtls/xray-core/infra/conf/serial"
	_ "github.com/xtls/xray-core/main/distro/all"
)

const (
	TunnelDir       = "/etc/archnets/tunnel"
	GostBinary      = "/usr/local/bin/gost"
	NodepassBinary  = "/usr/local/bin/nodepass"
	CoreConfigFile  = "core.json"
	TunnelConfigFmt = "tunnel_%d.json"
)

var (
	PaqetBinary     = "/usr/local/bin/paqet"
	WaterwallBinary = "/etc/archnets/tunnel/Waterwall"
)

const (
	ConfigPollSeconds = 60
	StatusPushSeconds = 30
	ControllerLogFile = "controller.log"
	WaterwallLogFile  = "waterwall.log"
	ForwarderLogFile  = "forwarder.log"
)

// trafficSnapshot stores the last-seen RX/TX bytes for a TUN device
type trafficSnapshot struct {
	rxBytes int64
	txBytes int64
}

// TunnelController manages WaterWall tunnel nodes
type TunnelController struct {
	tag                   string
	apiClient             *panel.ClientV2
	serverId              int
	nodeConfig            *conf.Conf
	tunnelDir             string
	waterwallProcess      *exec.Cmd
	waterwallMu           sync.Mutex        // Protects waterwallProcess lifecycle (start/stop/reload)
	forwarderProcesses    map[int]*exec.Cmd // tunnel_id -> forwarder process
	forwarderMu           sync.Mutex
	forwarderWg           sync.WaitGroup
	tunnels               []panel.TunnelInfo
	configMonitorPeriodic *task.Task
	statusReportPeriodic  *task.Task
	logger                *log.Entry
	waterwallLogFile      *os.File
	forwarderLogFile      *os.File
	lastConfigHash        string
	waterwallWg           sync.WaitGroup
	// Traffic monitoring
	lastTraffic       map[int]trafficSnapshot // tunnel_id -> last traffic snapshot
	tunnelDeviceNames map[int]string          // tunnel_id -> TUN device name
	// Xray instances
	xrayInstances map[int]*core.Instance
	xrayMu        sync.Mutex
}

// NewTunnelController creates a new tunnel controller
func NewTunnelController(apiClient *panel.ClientV2, serverId int, nodeConfig *conf.Conf) *TunnelController {
	tag := generateTunnelTag(serverId)
	return &TunnelController{
		tag:                tag,
		apiClient:          apiClient,
		serverId:           serverId,
		nodeConfig:         nodeConfig,
		tunnelDir:          TunnelDir,
		forwarderProcesses: make(map[int]*exec.Cmd),
		logger:             log.WithField("tag", tag), // Initialize with default logger
		lastTraffic:        make(map[int]trafficSnapshot),
		tunnelDeviceNames:  make(map[int]string),
		xrayInstances:      make(map[int]*core.Instance),
	}
}

func generateTunnelTag(serverId int) string {
	return "tunnel-" + strconv.Itoa(serverId)
}

// Start starts the tunnel controller
func (c *TunnelController) Start() error {
	// Ensure tunnel directory exists
	if err := os.MkdirAll(c.tunnelDir, 0755); err != nil {
		return fmt.Errorf("failed to create tunnel directory: %v", err)
	}

	if err := os.MkdirAll(filepath.Join(c.tunnelDir, "log"), 0755); err != nil {
		return fmt.Errorf("failed to create log directory: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(c.tunnelDir, "libs"), 0755); err != nil {
		return fmt.Errorf("failed to create libs directory: %v", err)
	}

	// Initialize dedicated logger that writes to controller.log
	controllerLogPath := filepath.Join(c.tunnelDir, "log", ControllerLogFile)
	controllerLogFile, err := os.OpenFile(controllerLogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		log.WithField("err", err).Warn("Failed to open controller log file, using stdout")
		c.logger = log.WithField("tag", c.tag)
	} else {
		// Create a new logger instance for the controller
		controllerLogger := log.New()
		// Only write to file, NOT stdout
		controllerLogger.SetOutput(controllerLogFile)
		controllerLogger.SetFormatter(&log.TextFormatter{FullTimestamp: true})
		c.logger = controllerLogger.WithField("tag", c.tag)
	}

	// Open waterwall log file
	waterwallLogPath := filepath.Join(c.tunnelDir, "log", WaterwallLogFile)
	c.waterwallLogFile, err = os.OpenFile(waterwallLogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		c.logger.WithField("err", err).Warn("Failed to open waterwall log file")
	}

	// Open forwarder log file
	forwarderLogPath := filepath.Join(c.tunnelDir, "log", ForwarderLogFile)
	c.forwarderLogFile, err = os.OpenFile(forwarderLogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		c.logger.WithField("err", err).Warn("Failed to open forwarder log file")
	}

	// Auto-install missing binaries
	if err := c.CheckAndInstallBinaries(); err != nil {
		c.logger.WithField("err", err).Warn("Tunnel: Auto-installation failed, proceeding with existing binaries if possible")
	}

	// Fetch initial config
	resp, err := c.apiClient.GetTunnelConfig()
	if err != nil {
		return fmt.Errorf("failed to fetch tunnel config: %v", err)
	}
	if resp.Data == nil {
		return fmt.Errorf("tunnel config response has no data")
	}

	// Apply configuration
	if err := c.applyConfig(resp.Data); err != nil {
		return fmt.Errorf("failed to apply tunnel config: %v", err)
	}

	// Set initial config hash so configMonitor doesn't re-apply immediately
	configJSON, _ := json.Marshal(resp.Data)
	hash := sha256.Sum256(configJSON)
	c.lastConfigHash = hex.EncodeToString(hash[:])

	// Start background tasks
	c.startTasks()

	c.logger.WithFields(log.Fields{
		"tag":         c.tag,
		"tunnelCount": len(c.tunnels),
	}).Info("Tunnel controller started")

	return nil
}

// CheckAndInstallBinaries checks for missing binaries and installs them
func (c *TunnelController) CheckAndInstallBinaries() error {
	// Check Waterwall
	if _, err := os.Stat(WaterwallBinary); os.IsNotExist(err) {
		c.logger.Info("WaterWall binary missing, attempting auto-installation...")
		if err := installer.InstallWaterwall(c.tunnelDir); err != nil {
			return fmt.Errorf("failed to install WaterWall: %v", err)
		}
	}

	// Check Gost
	if _, err := os.Stat(GostBinary); os.IsNotExist(err) {
		c.logger.Info("Gost binary missing, attempting auto-installation...")
		if err := installer.InstallGost(); err != nil {
			c.logger.WithField("err", err).Warn("Gost auto-installation failed")
		}
	}

	// Check Nodepass
	if _, err := os.Stat(NodepassBinary); os.IsNotExist(err) {
		c.logger.Info("NodePass binary missing, attempting auto-installation...")
		if err := installer.InstallNodepass(); err != nil {
			c.logger.WithField("err", err).Warn("NodePass auto-installation failed")
		}
	}

	// Check Paqet
	if _, err := os.Stat(PaqetBinary); os.IsNotExist(err) {
		c.logger.Info("Paqet binary missing, attempting auto-installation...")
		if err := installer.InstallPaqet(); err != nil {
			c.logger.WithField("err", err).Warn("Paqet auto-installation failed")
		}
	}

	return nil
}

// Uninstall stops processes and removes tunnel directories/binaries
func (c *TunnelController) Uninstall() error {
	c.logger.Info("Uninstalling tunnel components...")

	// Stop everything first
	c.Close()

	// Remove tunnel directory
	if err := os.RemoveAll(c.tunnelDir); err != nil {
		c.logger.WithField("err", err).Warn("Failed to remove tunnel directory")
	}

	// Remove system binaries (optional, keep them if others might use them?)
	// User said "deleting everything too", so we remove them.
	_ = os.Remove(GostBinary)
	_ = os.Remove(NodepassBinary)
	_ = os.Remove(PaqetBinary)

	c.logger.Info("Tunnel components uninstalled")
	return nil
}

// Close stops the tunnel controller
func (c *TunnelController) Close() error {
	// Stop periodic tasks
	if c.configMonitorPeriodic != nil {
		c.configMonitorPeriodic.Close()
	}
	if c.statusReportPeriodic != nil {
		c.statusReportPeriodic.Close()
	}

	// Stop WaterWall
	c.stopWaterwall()

	// Stop all forwarders
	c.stopAllForwarders()

	// Stop all Xray instances
	c.stopAllXrayInstances()

	// Close log files
	if c.waterwallLogFile != nil {
		c.waterwallLogFile.Close()
	}
	if c.forwarderLogFile != nil {
		c.forwarderLogFile.Close()
	}

	if c.logger != nil {
		c.logger.Info("Tunnel controller closed")
	}
	return nil
}

func (c *TunnelController) startTasks() {
	// Config monitor task
	c.configMonitorPeriodic = &task.Task{
		Interval: ConfigPollSeconds * time.Second,
		Execute:  c.configMonitor,
	}
	_ = c.configMonitorPeriodic.Start(false)
	c.logger.Info("Tunnel config monitor task started")

	// Status report task
	c.statusReportPeriodic = &task.Task{
		Interval: StatusPushSeconds * time.Second,
		Execute:  c.statusReport,
	}
	_ = c.statusReportPeriodic.Start(false)
	c.logger.Info("Tunnel status report task started")
}

func (c *TunnelController) configMonitor() error {
	resp, err := c.apiClient.GetTunnelConfig()
	if err != nil {
		c.logger.WithField("err", err).Error("Tunnel: Get config failed")
		return nil
	}

	if resp.Data == nil {
		return nil
	}

	// Check for scan commands and cleanup
	scanRunning := false
	for _, t := range resp.Data.Tunnels {
		if t.ScanCommand != nil {
			if t.Role == "entry" {
				c.handleScanCommand(t)
			} else if t.Role == "exit" {
				c.handleExitScanCommand(t)
			}
		} else {
			// No scan command -> ensure echo servers are stopped (for exit nodes)
			if t.Role == "exit" {
				c.stopEchoServers(t.Id)
			}
		}

		if c.isScanRunning(t.Id) {
			scanRunning = true
		}
	}

	// 4. Update configurations if changed
	// Skip if a scan is currently running (to avoid overwriting temp config)
	if scanRunning {
		return nil
	}

	// Compute config hash to detect changes — strip scan_command to avoid
	// re-applying config while a scan is in progress
	hashData := *resp.Data
	cleanTunnels := make([]panel.TunnelInfo, len(hashData.Tunnels))
	for i, t := range hashData.Tunnels {
		t.ScanCommand = nil
		cleanTunnels[i] = t
	}
	hashData.Tunnels = cleanTunnels
	configJSON, _ := json.Marshal(hashData)
	hash := sha256.Sum256(configJSON)
	configHash := hex.EncodeToString(hash[:])

	if configHash == c.lastConfigHash {
		return nil // No changes, skip re-apply
	}

	c.logger.Info("Tunnel config changed, re-applying...")

	// Re-apply config (handles changes)
	if err := c.applyConfig(resp.Data); err != nil {
		c.logger.WithField("err", err).Error("Tunnel: Apply config failed")
		return nil
	}

	c.lastConfigHash = configHash
	return nil
}

// pingTarget pings a target IP and returns latency and online status
func (c *TunnelController) pingTarget(ip string) (int, bool) {
	if ip == "" {
		return 0, false
	}
	// Run: ping -c 1 -W 1 <ip>
	cmd := exec.Command("ping", "-c", "1", "-W", "1", ip)
	start := time.Now()
	err := cmd.Run()
	latency := int(time.Since(start).Milliseconds())
	if err != nil {
		return 0, false // Offline
	}
	return latency, true // Online
}

func (c *TunnelController) statusReport() error {
	statuses := make([]panel.TunnelStatus, 0, len(c.tunnels))
	for _, t := range c.tunnels {
		latency, online := c.pingTarget(t.RemoteIP)

		// Read TUN device traffic
		var deltaUpload, deltaDownload int64

		if t.Method == "xray" {
			// Pull Xray stats directly from memory
			c.xrayMu.Lock()
			instance := c.xrayInstances[t.Id]
			c.xrayMu.Unlock()

			if instance != nil {
				// Note: Currently Xray tunnels don't have their configs individually read back here for stats
				// because they are natively loaded.
				f := instance.GetFeature(xraystats.ManagerType())
				if f != nil {
					// Iterate through all counters dynamically rather than looking up by JSON struct
					statsManager := f.(xraystats.Manager)

					// Go through all up and down link traffic
					// We don't have exactly which inbounds are ours right now,
					// but there is typically only one inbound per tunnel node

					// However, we can't easily iterate all counters in xraystats.Manager without reflection or an internal API.
					// Xray stores these as sync.Map, but doesn't expose a Keys() method.
					// Instead of reading traffic dynamically, Xray currently provides `proxy` or `inbound-0` as defaults.
					// We'll hardcode checking the standard expected tags for tunnels:
					possibleTags := []string{"proxy", "inbound-0", "dokodemo-0", "dokodemo-1", "dokodemo-2"}
					for _, tag := range possibleTags {
						downName := fmt.Sprintf("inbound>>>%s>>>traffic>>>downlink", tag)
						upName := fmt.Sprintf("inbound>>>%s>>>traffic>>>uplink", tag)

						if cDown := statsManager.GetCounter(downName); cDown != nil {
							// For tunnels, downloaded from user = Upload into tunnel
							val := cDown.Value()
							if val > 0 {
								deltaUpload += val
								cDown.Set(0)
							}
						}
						if cUp := statsManager.GetCounter(upName); cUp != nil {
							// Uploaded to user = Download from tunnel
							val := cUp.Value()
							if val > 0 {
								deltaDownload += val
								cUp.Set(0)
							}
						}
					}
				}
			}
		} else {
			if deviceName, ok := c.tunnelDeviceNames[t.Id]; ok && deviceName != "" {
				rxBytes, txBytes, err := readTUNTraffic(deviceName)
				if err == nil {
					if last, exists := c.lastTraffic[t.Id]; exists {
						// Compute delta (handle counter reset)
						if rxBytes >= last.rxBytes {
							deltaDownload = rxBytes - last.rxBytes
						} else {
							deltaDownload = rxBytes // Counter reset
						}
						if txBytes >= last.txBytes {
							deltaUpload = txBytes - last.txBytes
						} else {
							deltaUpload = txBytes // Counter reset
						}
					}
					c.lastTraffic[t.Id] = trafficSnapshot{rxBytes: rxBytes, txBytes: txBytes}
				} else {
					c.logger.WithFields(log.Fields{
						"device": deviceName,
						"err":    err,
					}).Debug("Failed to read TUN traffic")
				}
			}
		}

		statuses = append(statuses, panel.TunnelStatus{
			TunnelId:      t.Id,
			Online:        online,
			LatencyMs:     latency,
			TotalUpload:   deltaUpload,
			TotalDownload: deltaDownload,
		})
	}

	if len(statuses) > 0 {
		err := c.apiClient.ReportTunnelStatus(&panel.TunnelStatusRequest{
			Tunnels: statuses,
		})
		if err != nil {
			c.logger.WithField("err", err).Warn("Tunnel: Report status failed")
		}
	}

	return nil
}

func (c *TunnelController) applyConfig(data *panel.TunnelData) error {
	// Stop existing processes
	c.stopWaterwall()
	c.stopAllForwarders()
	c.stopAllXrayInstances()

	var waterwallTunnels []panel.TunnelInfo
	var xrayTunnels []panel.TunnelInfo

	// Generate and write core.json
	for _, t := range data.Tunnels {
		if t.Method == "waterwall" || t.Method == "" {
			waterwallTunnels = append(waterwallTunnels, t)
		} else if t.Method == "xray" {
			xrayTunnels = append(xrayTunnels, t)
		}
	}

	if len(waterwallTunnels) > 0 {
		tunnelFiles := make([]string, 0, len(waterwallTunnels))
		for _, t := range waterwallTunnels {
			filename := fmt.Sprintf(TunnelConfigFmt, t.Id)
			tunnelFiles = append(tunnelFiles, filename)
		}

		coreJSON := c.generateCoreJSON(data.CoreConfig, tunnelFiles)
		corePath := filepath.Join(c.tunnelDir, CoreConfigFile)
		if err := os.WriteFile(corePath, coreJSON, 0644); err != nil {
			return fmt.Errorf("failed to write core.json: %v", err)
		}
	}

	// Write each tunnel config
	for _, t := range data.Tunnels {
		filename := fmt.Sprintf(TunnelConfigFmt, t.Id)
		tunnelPath := filepath.Join(c.tunnelDir, filename)
		if t.Method == "waterwall" || t.Method == "" {
			if err := os.WriteFile(tunnelPath, []byte(t.WaterwallConfig), 0644); err != nil {
				return fmt.Errorf("failed to write %s: %v", filename, err)
			}
		}
	}

	c.tunnels = data.Tunnels

	// Extract device names from tunnel configs for traffic monitoring
	for _, t := range data.Tunnels {
		if t.Method == "waterwall" || t.Method == "" {
			deviceName := extractDeviceNameFromConfig(t.WaterwallConfig)
			if deviceName != "" {
				c.tunnelDeviceNames[t.Id] = deviceName
			}
		}
	}

	// Start WaterWall if we have waterwall tunnels
	if len(waterwallTunnels) > 0 {
		if err := c.startWaterwall(); err != nil {
			return fmt.Errorf("failed to start WaterWall: %v", err)
		}
	}

	// Start Xray tunnels natively in Go
	for _, t := range xrayTunnels {
		if err := c.startXrayInstance(t); err != nil {
			c.logger.WithFields(log.Fields{
				"tunnelId": t.Id,
				"err":      err,
			}).Warn("Failed to start Xray tunnel instance")
		}
	}

	// Start forwarders
	for _, t := range data.Tunnels {
		if t.Method == "xray" {
			// Skip starting Gost/Paqet/Nodepass/Waterwall wrapper
			// The Xray core instance handles the forwarding
			continue
		}
		for _, f := range t.Forwarders {
			if err := c.startForwarder(t.Id, &f); err != nil {
				c.logger.WithFields(log.Fields{
					"tunnelId":  t.Id,
					"forwarder": f.ForwarderType,
					"err":       err,
				}).Warn("Failed to start forwarder")
			}
		}
	}

	c.logger.WithField("tunnelCount", len(data.Tunnels)).Info("Tunnel config applied")

	return nil
}

func (c *TunnelController) generateCoreJSON(cfg *panel.CoreConfig, tunnelFiles []string) []byte {
	if cfg == nil {
		cfg = &panel.CoreConfig{
			MTU:        1450,
			LogLevel:   "FATAL",
			Workers:    0,
			RamProfile: "server",
		}
	}

	filesJSON, _ := json.Marshal(tunnelFiles)

	coreConfig := fmt.Sprintf(`{
    "log": {
        "path": "log/",
        "core": {"loglevel": "%s", "file": "core.log", "console": true},
        "network": {"loglevel": "%s", "file": "network.log", "console": true},
        "dns": {"loglevel": "%s", "file": "dns.log", "console": false},
        "internal": {"loglevel": "%s", "file": "internal.log", "console": true}
    },
    "dns": {},
    "misc": {"workers": %d, "mtu": %d, "ram-profile": "%s", "libs-path": "libs/"},
    "configs": %s
}`, cfg.LogLevel, cfg.LogLevel, cfg.LogLevel, cfg.LogLevel,
		cfg.Workers, cfg.MTU, cfg.RamProfile, string(filesJSON))

	return []byte(coreConfig)
}

func (c *TunnelController) startWaterwall() error {
	c.waterwallMu.Lock()
	defer c.waterwallMu.Unlock()
	return c.startWaterwallLocked()
}

// startWaterwallLocked starts WaterWall — caller must hold waterwallMu
func (c *TunnelController) startWaterwallLocked() error {
	if _, err := os.Stat(WaterwallBinary); os.IsNotExist(err) {
		return fmt.Errorf("WaterWall binary not found at %s", WaterwallBinary)
	}

	cmd := exec.Command(WaterwallBinary)
	cmd.Dir = c.tunnelDir
	// Redirect output to waterwall log file
	if c.waterwallLogFile != nil {
		cmd.Stdout = c.waterwallLogFile
		cmd.Stderr = c.waterwallLogFile
	}
	// Set process group for proper cleanup
	setProcessGroup(cmd)

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start WaterWall: %v", err)
	}

	c.waterwallProcess = cmd
	c.waterwallWg.Add(1)

	// Monitor process in background
	go func() {
		defer c.waterwallWg.Done()
		err := cmd.Wait()
		if err != nil {
			c.logger.WithField("err", err).Warn("WaterWall process exited")
		}
	}()

	c.logger.Info("WaterWall started")
	return nil
}

func (c *TunnelController) stopWaterwall() {
	c.waterwallMu.Lock()
	defer c.waterwallMu.Unlock()
	c.stopWaterwallLocked()
}

// stopWaterwallLocked stops WaterWall — caller must hold waterwallMu
func (c *TunnelController) stopWaterwallLocked() {
	if c.waterwallProcess != nil && c.waterwallProcess.Process != nil {
		c.logger.Info("Stopping WaterWall...")
		// Kill process group
		killProcessGroup(c.waterwallProcess)

		// Wait for process to exit and cleanup
		c.waterwallWg.Wait()

		c.waterwallProcess = nil
		c.logger.Info("WaterWall stopped")
	}
}

func (c *TunnelController) startForwarder(tunnelId int, f *panel.Forwarder) error {
	var cmd *exec.Cmd

	switch f.ForwarderType {
	case "waterwall":
		// WaterWall handles its own forwarding via tunnel configs, skip
		c.logger.WithField("tunnelId", tunnelId).Debug("Skipping waterwall forwarder (handled by WaterWall binary)")
		return nil

	case "gost":
		if _, err := os.Stat(GostBinary); os.IsNotExist(err) {
			return fmt.Errorf("gost binary not found at %s", GostBinary)
		}
		// gost -L tcp://:listen_port/target_ip:target_port
		listener := fmt.Sprintf("%s://:%d/%s:%d", f.Protocol, f.ListenPort, f.TargetIP, f.TargetPort)
		cmd = exec.Command(GostBinary, "-L", listener)

	case "nodepass":
		if _, err := os.Stat(NodepassBinary); os.IsNotExist(err) {
			return fmt.Errorf("nodepass binary not found at %s", NodepassBinary)
		}
		// nodepass client://0.0.0.0:listen_port/target_ip:target_port
		target := fmt.Sprintf("client://0.0.0.0:%d/%s:%d", f.ListenPort, f.TargetIP, f.TargetPort)
		cmd = exec.Command(NodepassBinary, target)

	case "paqet":
		if _, err := os.Stat(PaqetBinary); os.IsNotExist(err) {
			return fmt.Errorf("paqet binary not found at %s", PaqetBinary)
		}

		// Detect network details
		iface, err := GetDefaultInterface()
		if err != nil {
			return fmt.Errorf("failed to detect default interface: %v", err)
		}

		localIP, err := GetLocalIP(iface)
		if err != nil {
			return fmt.Errorf("failed to detect local IP: %v", err)
		}

		gatewayMAC, err := GetGatewayMAC()
		if err != nil {
			return fmt.Errorf("failed to detect gateway MAC: %v", err)
		}

		// Start Paqet
		transportPort := c.extractPaqetPort(f.Config)
		role := c.extractPaqetRole(f.Config)

		// Determine bind port for network block
		// Client (Entry): 0 (ephemeral)
		// Server (Exit): transportPort
		bindPort := 0
		if role == "server" {
			bindPort = transportPort
		}

		// Setup firewall rules first (always on transport port)
		c.setupPaqetFirewall(transportPort)

		// Build TCP flags section based on role
		tcpFlags := `    local_flag: ["PA"]`
		if role == "client" {
			tcpFlags = `    local_flag: ["PA"]
    remote_flag: ["PA"]`
		}

		networkBlock := fmt.Sprintf(`
network:
  interface: "%s"
  ipv4:
    addr: "%s:%d"
    router_mac: "%s"
  tcp:
%s
    pcap:
      sockbuf: 8388608
`, iface, localIP, bindPort, gatewayMAC, tcpFlags)

		// Merge config
		fullConfig := f.Config + "\n" + networkBlock

		// Write config file
		configFilename := fmt.Sprintf("paqet_%d.yaml", f.ListenPort)
		configPath := filepath.Join(c.tunnelDir, configFilename)
		if err := os.WriteFile(configPath, []byte(fullConfig), 0644); err != nil {
			return fmt.Errorf("failed to write paqet config: %v", err)
		}

		// paqet run -c config_file
		cmd = exec.Command(PaqetBinary, "run", "-c", configPath)

	default:
		return fmt.Errorf("unknown forwarder type: %s", f.ForwarderType)
	}

	// Redirect output to forwarder log file
	if c.forwarderLogFile != nil {
		cmd.Stdout = c.forwarderLogFile
		cmd.Stderr = c.forwarderLogFile
	}

	setProcessGroup(cmd)

	if err := cmd.Start(); err != nil {
		return err
	}

	// Use composite key for multiple forwarders per tunnel
	key := tunnelId*10000 + f.ListenPort
	c.forwarderMu.Lock()
	c.forwarderProcesses[key] = cmd
	c.forwarderMu.Unlock()

	// Monitor process in background
	c.forwarderWg.Add(1)
	go func() {
		defer c.forwarderWg.Done()
		cmd.Wait()
		c.forwarderMu.Lock()
		delete(c.forwarderProcesses, key)
		c.forwarderMu.Unlock()
	}()

	c.logger.WithFields(log.Fields{
		"tunnelId":   tunnelId,
		"type":       f.ForwarderType,
		"port":       f.ListenPort,
		"targetIP":   f.TargetIP,
		"targetPort": f.TargetPort,
	}).Info("Forwarder started")

	return nil
}

func (c *TunnelController) startXrayInstance(t panel.TunnelInfo) error {
	if t.XrayConfig == nil {
		return fmt.Errorf("xray_config is missing for xray tunnel")
	}

	// Build raw JSON from the structured API struct
	xrayJSON := c.buildXrayJSON(t, t.XrayConfig)

	// Convert JSON string to Xray's strongly-typed initial protobuf array
	reader := bytes.NewReader([]byte(xrayJSON))
	confObj, err := confserial.DecodeJSONConfig(reader)
	if err != nil {
		return fmt.Errorf("failed to parse xray config JSON: %v", err)
	}

	configObj, err := confObj.Build()
	if err != nil {
		return fmt.Errorf("failed to build xray config protobuf: %v", err)
	}

	// We forcibly inject Node's global logging config so Xray prints everything to the Node controller's log output
	// Ensure fallback to warning if config is omitted
	logLevel := c.nodeConfig.LogConfig.Level
	if logLevel == "" {
		logLevel = "warning"
	}

	coreLogConfig := &coreConf.LogConfig{
		LogLevel:  logLevel,
		ErrorLog:  c.nodeConfig.LogConfig.Output,
		AccessLog: c.nodeConfig.LogConfig.Access,
	}
	appLogMsg := serial.ToTypedMessage(coreLogConfig.Build())

	// Prepend it to App configurations
	configObj.App = append([]*serial.TypedMessage{appLogMsg}, configObj.App...)

	instance, err := core.New(configObj)
	if err != nil {
		return fmt.Errorf("failed to initialize xray instance: %v", err)
	}

	if err := instance.Start(); err != nil {
		return fmt.Errorf("failed to start xray instance: %v", err)
	}

	c.xrayMu.Lock()
	if c.xrayInstances == nil {
		c.xrayInstances = make(map[int]*core.Instance)
	}
	c.xrayInstances[t.Id] = instance
	c.xrayMu.Unlock()

	c.logger.WithField("tunnelId", t.Id).Info("Xray tunnel instance started natively in Go")
	return nil
}

func (c *TunnelController) buildXrayJSON(t panel.TunnelInfo, cfg *panel.XrayTunnelProtocol) string {
	obj := map[string]interface{}{
		"log": map[string]interface{}{
			"loglevel": "none",
		},
		"inbounds":  []interface{}{},
		"outbounds": []interface{}{},
	}

	if t.Role == "entry" {
		// Entry node: Create dokodemo-door forwarders + outbound client proxy connection
		for _, f := range t.Forwarders {
			listen := "0.0.0.0"
			if cfg.ListenIP != "" {
				listen = cfg.ListenIP
			}
			inb := map[string]interface{}{
				"listen":   listen,
				"port":     f.ListenPort,
				"protocol": "dokodemo-door",
				"settings": map[string]interface{}{
					"address": f.TargetIP,
					"port":    f.TargetPort,
					"network": f.Protocol,
				},
				"tag": fmt.Sprintf("dokodemo-%d", f.ListenPort),
			}
			obj["inbounds"] = append(obj["inbounds"].([]interface{}), inb)
		}

		streamSettings := buildXrayStreamSettings(cfg, false)
		outb := map[string]interface{}{
			"protocol": cfg.Type,
			"settings": map[string]interface{}{
				"vnext": []interface{}{
					map[string]interface{}{
						"address": cfg.Address,
						"port":    cfg.Port,
						"users": []interface{}{
							buildXrayUser(cfg),
						},
					},
				},
			},
			"streamSettings": streamSettings,
			"tag":            "proxy",
		}
		obj["outbounds"] = append(obj["outbounds"].([]interface{}), outb)

	} else {
		// Exit node: Receive upstream proxy connections + outbound freedom internet
		streamSettings := buildXrayStreamSettings(cfg, true)

		// Handle raw PEM certificate strings directly from the DB by rewriting them to the disk
		if cfg.CertFile != "" && strings.Contains(cfg.CertFile, "-----BEGIN") {
			certPath := filepath.Join(c.tunnelDir, "libs", fmt.Sprintf("tunnel_%d_cert.pem", t.Id))
			os.WriteFile(certPath, []byte(cfg.CertFile), 0644)
			cfg.CertFile = certPath
		}
		if cfg.KeyFile != "" && strings.Contains(cfg.KeyFile, "-----BEGIN") {
			keyPath := filepath.Join(c.tunnelDir, "libs", fmt.Sprintf("tunnel_%d_key.pem", t.Id))
			os.WriteFile(keyPath, []byte(cfg.KeyFile), 0600)
			cfg.KeyFile = keyPath
		}

		// Because we're writing files mid-flight, update the nested map pointer directly
		if tlsSettings, ok := streamSettings["tlsSettings"].(map[string]interface{}); ok {
			if cfg.CertFile != "" && cfg.KeyFile != "" {
				tlsSettings["certificates"] = []interface{}{
					map[string]interface{}{
						"certificateFile": cfg.CertFile,
						"keyFile":         cfg.KeyFile,
					},
				}
			}
		}

		client := map[string]interface{}{
			"id": cfg.UUID,
		}
		if cfg.Flow != "" {
			client["flow"] = cfg.Flow
		}

		decryption := "none"
		if cfg.Encryption != "" && cfg.Encryption != "none" {
			decryption = cfg.Encryption
		}

		listen := "0.0.0.0"
		if cfg.ListenIP != "" {
			listen = cfg.ListenIP
		}

		inb := map[string]interface{}{
			"listen":   listen,
			"port":     cfg.Port,
			"protocol": cfg.Type,
			"settings": map[string]interface{}{
				"clients": []interface{}{
					client,
				},
				"decryption": decryption,
			},
			"streamSettings": streamSettings,
			"tag":            "proxy",
		}
		obj["inbounds"] = append(obj["inbounds"].([]interface{}), inb)

		outb := map[string]interface{}{
			"protocol": "freedom",
			"settings": map[string]interface{}{},
		}
		obj["outbounds"] = append(obj["outbounds"].([]interface{}), outb)
	}

	b, _ := json.Marshal(obj)
	return string(b)
}

func buildXrayUser(cfg *panel.XrayTunnelProtocol) map[string]interface{} {
	user := map[string]interface{}{
		"id": cfg.UUID,
	}
	if cfg.Encryption != "" {
		user["encryption"] = cfg.Encryption
	} else {
		user["encryption"] = "none"
	}
	if cfg.Flow != "" {
		user["flow"] = cfg.Flow
	}
	return user
}

func buildXrayStreamSettings(cfg *panel.XrayTunnelProtocol, isServer bool) map[string]interface{} {
	ss := map[string]interface{}{
		"network":  cfg.Transport,
		"security": cfg.Security,
	}

	if cfg.Security == "tls" {
		tlsSettings := map[string]interface{}{
			"serverName": cfg.SNI,
			"alpn":       []string{"h2", "http/1.1"},
		}
		if !isServer {
			// Client-side TLS needs fingerprint and allowInsecure for CDN/domain fronting
			if cfg.Fingerprint != "" {
				tlsSettings["fingerprint"] = cfg.Fingerprint
			}
			if cfg.AllowInsecure {
				tlsSettings["allowInsecure"] = true
			}
		}
		ss["tlsSettings"] = tlsSettings
	}

	if cfg.Security == "reality" {
		realitySettings := map[string]interface{}{
			"serverName": cfg.SNI,
			"shortId":    cfg.RealityShortId,
		}
		if isServer {
			realitySettings["privateKey"] = cfg.RealityPrivateKey
			realitySettings["dest"] = fmt.Sprintf("%s:%d", cfg.RealityServerAddr, cfg.RealityServerPort)
			realitySettings["serverNames"] = []string{cfg.SNI}
		} else {
			realitySettings["publicKey"] = cfg.RealityPublicKey
			realitySettings["fingerprint"] = cfg.Fingerprint
		}
		ss["realitySettings"] = realitySettings
	}

	if cfg.Transport == "xhttp" {
		xhttpSettings := map[string]interface{}{
			"mode": cfg.XhttpMode,
			"path": cfg.Path,
		}
		if cfg.Host != "" {
			xhttpSettings["host"] = cfg.Host
		}
		ss["xhttpSettings"] = xhttpSettings
	} else if cfg.Transport == "ws" {
		ss["wsSettings"] = map[string]interface{}{
			"path": cfg.Path,
		}
	} else if cfg.Transport == "grpc" {
		ss["grpcSettings"] = map[string]interface{}{
			"serviceName": cfg.ServiceName,
		}
	}

	return ss
}

func (c *TunnelController) stopAllXrayInstances() {
	c.xrayMu.Lock()
	defer c.xrayMu.Unlock()

	if c.xrayInstances == nil {
		c.xrayInstances = make(map[int]*core.Instance)
		return
	}

	for id, instance := range c.xrayInstances {
		if instance != nil {
			if err := instance.Close(); err != nil {
				c.logger.WithFields(log.Fields{
					"tunnelId": id,
					"err":      err,
				}).Warn("Failed to cleanly stop Xray instance")
			} else {
				c.logger.WithField("tunnelId", id).Info("Xray tunnel instance stopped")
			}
		}
	}
	// Reallocate the map cleanly
	c.xrayInstances = make(map[int]*core.Instance)
}

func (c *TunnelController) stopAllForwarders() {
	c.forwarderMu.Lock()
	for _, cmd := range c.forwarderProcesses {
		if cmd != nil && cmd.Process != nil {
			// Send SIGTERM first
			killProcessGroup(cmd)

			// If process doesn't die within 2s, force kill
			go func(proc *os.Process) {
				time.Sleep(2 * time.Second)
				if proc != nil {
					_ = proc.Kill() // SIGKILL
				}
			}(cmd.Process)
		}
	}
	c.forwarderMu.Unlock()

	// Wait for all forwarder goroutines to confirm processes are dead
	c.forwarderWg.Wait()
	// For Paqet specifically, we need to teardown the firewall rules for the transport port.
	// Since the transport port is inside the config file, we scan the tunnel directory for paqet configs.
	files, _ := filepath.Glob(filepath.Join(c.tunnelDir, "paqet_*.yaml"))
	for _, f := range files {
		content, err := os.ReadFile(f)
		if err == nil {
			transportPort := c.extractPaqetPort(string(content))
			if transportPort > 0 {
				c.teardownPaqetFirewall(transportPort)
			}
		}
	}

	c.logger.Info("All forwarders stopped")
}

func (c *TunnelController) setupPaqetFirewall(port int) {
	if port <= 0 {
		return
	}
	c.logger.WithField("port", port).Info("Setting up Paqet firewall rules (NOTRACK/RST-DROP)")

	rules := [][]string{
		{"-t", "raw", "-A", "PREROUTING", "-p", "tcp", "--dport", strconv.Itoa(port), "-j", "NOTRACK"},
		{"-t", "raw", "-A", "OUTPUT", "-p", "tcp", "--sport", strconv.Itoa(port), "-j", "NOTRACK"},
		{"-t", "mangle", "-A", "OUTPUT", "-p", "tcp", "--sport", strconv.Itoa(port), "--tcp-flags", "RST", "RST", "-j", "DROP"},
		{"-t", "filter", "-A", "INPUT", "-p", "tcp", "--dport", strconv.Itoa(port), "-j", "ACCEPT"},
		{"-t", "filter", "-A", "OUTPUT", "-p", "tcp", "--sport", strconv.Itoa(port), "-j", "ACCEPT"},
	}

	for _, rule := range rules {
		checkRule := make([]string, len(rule))
		copy(checkRule, rule)
		for i, v := range checkRule {
			if v == "-A" {
				checkRule[i] = "-C"
			}
		}

		if err := exec.Command("iptables", checkRule...).Run(); err != nil {
			if err := exec.Command("iptables", rule...).Run(); err != nil {
				c.logger.WithFields(log.Fields{
					"rule": rule,
					"err":  err,
				}).Warn("Failed to add iptables rule")
			}
		}
	}
}

func (c *TunnelController) teardownPaqetFirewall(port int) {
	if port <= 0 {
		return
	}
	c.logger.WithField("port", port).Info("Tearing down Paqet firewall rules")

	rules := [][]string{
		{"-t", "raw", "-D", "PREROUTING", "-p", "tcp", "--dport", strconv.Itoa(port), "-j", "NOTRACK"},
		{"-t", "raw", "-D", "OUTPUT", "-p", "tcp", "--sport", strconv.Itoa(port), "-j", "NOTRACK"},
		{"-t", "mangle", "-D", "OUTPUT", "-p", "tcp", "--sport", strconv.Itoa(port), "--tcp-flags", "RST", "RST", "-j", "DROP"},
		{"-t", "filter", "-D", "INPUT", "-p", "tcp", "--dport", strconv.Itoa(port), "-j", "ACCEPT"},
		{"-t", "filter", "-D", "OUTPUT", "-p", "tcp", "--sport", strconv.Itoa(port), "-j", "ACCEPT"},
	}

	for _, rule := range rules {
		_ = exec.Command("iptables", rule...).Run()
	}
}

// extractPaqetPort parses the partial YAML to find the transport port
func (c *TunnelController) extractPaqetPort(config string) int {
	// Simple line-by-line search to avoid importing a full YAML parser
	// Works for both listen: addr: ":29000" and server: addr: "IP:29000"
	lines := strings.Split(config, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.Contains(trimmed, "addr:") {
			parts := strings.Split(trimmed, ":")
			if len(parts) >= 2 {
				portStr := strings.Trim(parts[len(parts)-1], `"' `)
				if port, err := strconv.Atoi(portStr); err == nil {
					return port
				}
			}
		}
	}
	return 0
}

// extractPaqetRole parses the partial YAML to find the role
func (c *TunnelController) extractPaqetRole(config string) string {
	lines := strings.Split(config, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "role:") {
			parts := strings.Split(trimmed, ":")
			if len(parts) >= 2 {
				val := strings.TrimSpace(parts[1])
				return strings.Trim(val, `"'`)
			}
		}
	}
	return ""
}

// readTUNTraffic reads RX and TX bytes from sysfs for a network interface
func readTUNTraffic(deviceName string) (rxBytes, txBytes int64, err error) {
	rxPath := fmt.Sprintf("/sys/class/net/%s/statistics/rx_bytes", deviceName)
	txPath := fmt.Sprintf("/sys/class/net/%s/statistics/tx_bytes", deviceName)

	rxData, err := os.ReadFile(rxPath)
	if err != nil {
		return 0, 0, fmt.Errorf("read rx_bytes: %w", err)
	}
	txData, err := os.ReadFile(txPath)
	if err != nil {
		return 0, 0, fmt.Errorf("read tx_bytes: %w", err)
	}

	rxBytes, err = strconv.ParseInt(strings.TrimSpace(string(rxData)), 10, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("parse rx_bytes: %w", err)
	}
	txBytes, err = strconv.ParseInt(strings.TrimSpace(string(txData)), 10, 64)
	if err != nil {
		return 0, 0, fmt.Errorf("parse tx_bytes: %w", err)
	}

	return rxBytes, txBytes, nil
}

// extractDeviceNameFromConfig extracts the TUN device name from WaterWall config JSON
// It looks for the "device-name" field in a TunDevice node
var deviceNameRegex = regexp.MustCompile(`"device-name"\s*:\s*"([^"]+)"`)

func extractDeviceNameFromConfig(configJSON string) string {
	matches := deviceNameRegex.FindStringSubmatch(configJSON)
	if len(matches) >= 2 {
		return matches[1]
	}
	return ""
}

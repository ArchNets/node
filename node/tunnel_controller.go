package node

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"

	"github.com/archnets/node/api/panel"
	"github.com/archnets/node/common/installer"
	"github.com/archnets/node/common/task"
	log "github.com/sirupsen/logrus"
)

const (
	TunnelDir         = "/etc/archnets/tunnel"
	WaterwallBinary   = "/etc/archnets/tunnel/Waterwall"
	GostBinary        = "/usr/local/bin/gost"
	NodepassBinary    = "/usr/local/bin/nodepass"
	CoreConfigFile    = "core.json"
	TunnelConfigFmt   = "tunnel_%d.json"
	ConfigPollSeconds = 60
	StatusPushSeconds = 30
	ControllerLogFile = "controller.log"
	WaterwallLogFile  = "waterwall.log"
	ForwarderLogFile  = "forwarder.log"
)

// TunnelController manages WaterWall tunnel nodes
type TunnelController struct {
	tag                   string
	apiClient             *panel.ClientV2
	serverId              int
	tunnelDir             string
	waterwallProcess      *exec.Cmd
	forwarderProcesses    map[int]*exec.Cmd // tunnel_id -> forwarder process
	tunnels               []panel.TunnelInfo
	configMonitorPeriodic *task.Task
	statusReportPeriodic  *task.Task
	logger                *log.Entry
	waterwallLogFile      *os.File
	forwarderLogFile      *os.File
}

// NewTunnelController creates a new tunnel controller
func NewTunnelController(apiClient *panel.ClientV2, serverId int) *TunnelController {
	tag := generateTunnelTag(serverId)
	return &TunnelController{
		tag:                tag,
		apiClient:          apiClient,
		serverId:           serverId,
		tunnelDir:          TunnelDir,
		forwarderProcesses: make(map[int]*exec.Cmd),
		logger:             log.WithField("tag", tag), // Initialize with default logger
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

	// Re-apply config (handles changes)
	if err := c.applyConfig(resp.Data); err != nil {
		c.logger.WithField("err", err).Error("Tunnel: Apply config failed")
	}

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

		statuses = append(statuses, panel.TunnelStatus{
			TunnelId:  t.Id,
			Online:    online,
			LatencyMs: latency,
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

	// Generate and write core.json
	tunnelFiles := make([]string, 0, len(data.Tunnels))
	for _, t := range data.Tunnels {
		filename := fmt.Sprintf(TunnelConfigFmt, t.Id)
		tunnelFiles = append(tunnelFiles, filename)
	}

	coreJSON := c.generateCoreJSON(data.CoreConfig, tunnelFiles)
	corePath := filepath.Join(c.tunnelDir, CoreConfigFile)
	if err := os.WriteFile(corePath, coreJSON, 0644); err != nil {
		return fmt.Errorf("failed to write core.json: %v", err)
	}

	// Write each tunnel config
	for _, t := range data.Tunnels {
		filename := fmt.Sprintf(TunnelConfigFmt, t.Id)
		tunnelPath := filepath.Join(c.tunnelDir, filename)
		if err := os.WriteFile(tunnelPath, []byte(t.ConfigJSON), 0644); err != nil {
			return fmt.Errorf("failed to write %s: %v", filename, err)
		}
	}

	c.tunnels = data.Tunnels

	// Start WaterWall if we have tunnels
	if len(data.Tunnels) > 0 {
		if err := c.startWaterwall(); err != nil {
			return fmt.Errorf("failed to start WaterWall: %v", err)
		}
	}

	// Start forwarders
	for _, t := range data.Tunnels {
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

	// Monitor process in background
	go func() {
		err := cmd.Wait()
		if err != nil {
			c.logger.WithField("err", err).Warn("WaterWall process exited")
		}
		c.waterwallProcess = nil
	}()

	c.logger.Info("WaterWall started")
	return nil
}

func (c *TunnelController) stopWaterwall() {
	if c.waterwallProcess != nil && c.waterwallProcess.Process != nil {
		// Kill process group
		killProcessGroup(c.waterwallProcess)
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
	c.forwarderProcesses[key] = cmd

	// Monitor process in background
	go func() {
		cmd.Wait()
		delete(c.forwarderProcesses, key)
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

func (c *TunnelController) stopAllForwarders() {
	for key, cmd := range c.forwarderProcesses {
		if cmd != nil && cmd.Process != nil {
			killProcessGroup(cmd)
		}
		delete(c.forwarderProcesses, key)
	}
	c.logger.Info("All forwarders stopped")
}

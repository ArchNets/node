package node

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"time"

	"sync"

	"github.com/archnets/node/api/panel"
	certutil "github.com/archnets/node/common/cert"
	"github.com/archnets/node/common/file"
	"github.com/archnets/node/common/task"
	"github.com/archnets/node/conf"
	"github.com/archnets/node/core/relay/telemetry"
	"github.com/archnets/node/core/relay/transport"
	log "github.com/sirupsen/logrus"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	xraystats "github.com/xtls/xray-core/features/stats"
	coreConf "github.com/xtls/xray-core/infra/conf"
	confserial "github.com/xtls/xray-core/infra/conf/serial"
	_ "github.com/xtls/xray-core/main/distro/all"
)

const (
	TunnelDir = "/etc/archnets/tunnel"
)

const (
	ConfigPollSeconds = 60
	StatusPushSeconds = 30
	ControllerLogFile = "controller.log"
	ForwarderLogFile  = "forwarder.log"
)

// trafficSnapshot stores the last-seen RX/TX bytes for a TUN device
type trafficSnapshot struct {
	rxBytes int64
	txBytes int64
}

func ensureLogDir(path string) {
	p := strings.TrimSpace(path)
	if p == "" || p == "none" || p == "stdout" || p == "console" {
		return
	}
	dir := filepath.Dir(p)
	if dir != "." && dir != "/" {
		_ = os.MkdirAll(dir, 0755)
	}
}

// TunnelController manages tunnel nodes and native Go relay engines
type TunnelController struct {
	tag                   string
	apiClient             *panel.ClientV2
	serverId              int
	nodeConfig            *conf.Conf
	tunnelDir             string
	applyMu               sync.Mutex        // Serializes complete configuration transactions
	stateMu               sync.Mutex        // Protects tunnels and traffic-monitoring maps
	forwarderProcesses    map[int]*exec.Cmd // tunnel_id -> forwarder process
	forwarderMu           sync.Mutex
	forwarderWg           sync.WaitGroup
	tunnels               []panel.TunnelInfo
	configMonitorPeriodic *task.Task
	statusReportPeriodic  *task.Task
	logger                *log.Entry
	forwarderLogFile      *os.File
	lastConfigHash        string

	// Pluggable Tunnel Drivers
	relayDriver *RelayDriver

	// Xray instances
	xrayInstances map[int]*core.Instance
	xrayMu        sync.Mutex
}

// NewTunnelController creates a new tunnel controller
func NewTunnelController(apiClient *panel.ClientV2, serverId int, nodeConfig *conf.Conf) *TunnelController {
	tag := generateTunnelTag(serverId)
	relayDrv := NewRelayDriver(log.WithField("tag", tag))
	RegisterTunnelDriver("reverse-reality", relayDrv)
	RegisterTunnelDriver("tls-reverse", relayDrv)
	RegisterTunnelDriver("relay", relayDrv)
	RegisterTunnelDriver("waterwall", relayDrv)
	RegisterTunnelDriver("", relayDrv)

	return &TunnelController{
		tag:                  tag,
		apiClient:            apiClient,
		serverId:             serverId,
		nodeConfig:           nodeConfig,
		tunnelDir:            TunnelDir,
		forwarderProcesses:   make(map[int]*exec.Cmd),
		logger:               log.WithField("tag", tag),
		relayDriver:          relayDrv,
		xrayInstances:        make(map[int]*core.Instance),
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

	// Initialize dedicated logger that writes directly to stdout/journalctl
	c.logger = log.WithField("tag", c.tag)

	// Open forwarder log file
	forwarderLogPath := filepath.Join(c.tunnelDir, "log", ForwarderLogFile)
	if fFile, fErr := os.OpenFile(forwarderLogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644); fErr != nil {
		c.logger.WithField("err", fErr).Warn("Failed to open forwarder log file")
	} else {
		c.forwarderLogFile = fFile
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

	// Stop all registered drivers
	driversMu.RLock()
	for _, drv := range drivers {
		drv.StopAll()
	}
	driversMu.RUnlock()

	// Stop all forwarders
	c.stopAllForwarders()

	// Stop all Xray instances
	c.stopAllXrayInstances()

	// Close log files
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

// pingTarget checks connectivity and latency to a target IP or host using TCP or ICMP ping fallback
func (c *TunnelController) pingTarget(ip string, port int) (int, bool) {
	if ip == "" {
		return 0, false
	}
	// Prefer TCP dial if port is provided
	if port > 0 {
		start := time.Now()
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, strconv.Itoa(port)), 2*time.Second)
		if err == nil {
			_ = conn.Close()
			return int(time.Since(start).Milliseconds()), true
		}
	}
	// Fallback to ICMP ping
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
	c.stateMu.Lock()
	tunnels := append([]panel.TunnelInfo(nil), c.tunnels...)
	c.stateMu.Unlock()

	statuses := make([]panel.TunnelStatus, 0, len(tunnels))
	c.stateMu.Lock()
	defer c.stateMu.Unlock()

	for _, t := range tunnels {
		probePort := t.ExitXrayPort
		probeIP := t.RemoteIP
		if probeIP == "" {
			probeIP = t.ExitServerIP
		}

		// Check if handled by registered pluggable driver
		driver := GetTunnelDriver(t.Method)
		if driver != nil {
			var latency int
			var online bool
			if c.relayDriver != nil {
				if eng := c.relayDriver.GetEngine(t.Id); eng != nil && eng.Stats.LatencyMs.Load() > 0 {
					latency = int(eng.Stats.LatencyMs.Load())
					online = true
				}
			}
			if latency <= 0 {
				latency, online = c.pingTarget(probeIP, probePort)
			}
			if st, handled := driver.CollectStats(t, latency, online); handled {
				statuses = append(statuses, st)
				continue
			}
		}

		latency, online := c.pingTarget(probeIP, probePort)

		var deltaUpload, deltaDownload int64

		if t.Method == "xray" || t.Method == "xray-reverse" || t.Method == "xray-stealth" {
			c.xrayMu.Lock()
			instance := c.xrayInstances[t.Id]
			c.xrayMu.Unlock()

			if instance != nil {
				online = true
				if latency <= 0 && probeIP != "" && probePort > 0 {
					start := time.Now()
					conn, err := net.DialTimeout("tcp", net.JoinHostPort(probeIP, strconv.Itoa(probePort)), 2*time.Second)
					if err == nil {
						latency = int(time.Since(start).Milliseconds())
						_ = conn.Close()
					}
				}
				f := instance.GetFeature(xraystats.ManagerType())
				if f != nil {
					statsManager := f.(xraystats.Manager)
					possibleTags := []string{"proxy", "inbound-0", "dokodemo-0", "dokodemo-1", "dokodemo-2"}
					if t.Method == "xray-stealth" {
						if t.Role == "entry" {
							possibleTags = append(possibleTags, "stealth-out")
						} else {
							possibleTags = append(possibleTags, "stealth-inbound")
						}
					}
					for _, tag := range possibleTags {
						downName := fmt.Sprintf("inbound>>>%s>>>traffic>>>downlink", tag)
						upName := fmt.Sprintf("inbound>>>%s>>>traffic>>>uplink", tag)

						if cDown := statsManager.GetCounter(downName); cDown != nil {
							val := cDown.Value()
							if val > 0 {
								deltaUpload += val
								cDown.Set(0)
							}
						}
						if cUp := statsManager.GetCounter(upName); cUp != nil {
							val := cUp.Value()
							if val > 0 {
								deltaDownload += val
								cUp.Set(0)
							}
						}
					}
				}
			}
		}

		if deltaUpload > 0 || deltaDownload > 0 {
			online = true
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
			if c.relayDriver != nil {
				c.relayDriver.RefundStats(statuses)
			}
			c.logger.WithField("err", err).Warn("Tunnel: Report status failed")
		} else {
			c.logger.WithFields(log.Fields{
				"count":  len(statuses),
				"online": statuses[0].Online,
			}).Info("Reported tunnel status to panel")
		}
	}

	return nil
}

func (c *TunnelController) applyConfig(data *panel.TunnelData) error {
	c.applyMu.Lock()
	defer c.applyMu.Unlock()

	// Apply per-server CoreConfig (MTU / TCP MSS clamping)
	if data.CoreConfig != nil {
		transport.SetConfiguredMTU(data.CoreConfig.MTU)
	}

	// Update dynamic SNI origins pushed from backend
	if len(data.SNIOrigins) > 0 {
		presets := make([]telemetry.SNIPreset, 0, len(data.SNIOrigins))
		for _, o := range data.SNIOrigins {
			if o.Enabled {
				presets = append(presets, telemetry.SNIPreset{
					SNI:      o.SNI,
					Label:    o.Label,
					OriginIP: o.OriginIP,
					Category: o.Category,
				})
			}
		}
		telemetry.SetDynamicSNIOrigins(presets)
	}

	// Stop existing processes and drivers
	driversMu.RLock()
	for _, drv := range drivers {
		drv.StopAll()
	}
	driversMu.RUnlock()

	c.stopAllForwarders()
	c.stopAllXrayInstances()

	var unhandledTunnels []panel.TunnelInfo
	var xrayTunnels []panel.TunnelInfo
	var xrayReverseTunnels []panel.TunnelInfo
	var xrayStealthTunnels []panel.TunnelInfo

	for _, t := range data.Tunnels {
		// If handled by a registered driver, start it
		if drv := GetTunnelDriver(t.Method); drv != nil {
			if err := drv.Start(t); err != nil {
				c.logger.WithFields(log.Fields{
					"tunnelId": t.Id,
					"method":   t.Method,
					"err":      err,
				}).Warn("Failed to start tunnel via driver")
			}
			continue
		}

		switch t.Method {
		case "xray":
			xrayTunnels = append(xrayTunnels, t)
		case "xray-reverse":
			xrayReverseTunnels = append(xrayReverseTunnels, t)
		case "xray-stealth":
			xrayStealthTunnels = append(xrayStealthTunnels, t)
		default:
			unhandledTunnels = append(unhandledTunnels, t)
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

	// Start Xray-reverse tunnels natively in Go
	for _, t := range xrayReverseTunnels {
		if err := c.startXrayReverseInstance(t); err != nil {
			c.logger.WithFields(log.Fields{
				"tunnelId": t.Id,
				"err":      err,
			}).Warn("Failed to start Xray-reverse tunnel instance")
		}
	}

	// Start Xray-stealth tunnels natively in Go
	for _, t := range xrayStealthTunnels {
		if err := c.startXrayStealthInstance(t); err != nil {
			c.logger.WithFields(log.Fields{
				"tunnelId": t.Id,
				"err":      err,
			}).Warn("Failed to start Xray-stealth tunnel instance")
		}
	}

	// Start external forwarders (gost, nodepass) only for non-relay tunnels
	for _, t := range data.Tunnels {
		if t.Method == "xray" || t.Method == "xray-reverse" || t.Method == "xray-stealth" ||
			t.Method == "reverse-reality" || t.Method == "tls-reverse" || t.Method == "waterwall" || t.Method == "" {
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

	c.stateMu.Lock()
	c.tunnels = append([]panel.TunnelInfo(nil), data.Tunnels...)
	c.stateMu.Unlock()

	c.logger.WithField("tunnelCount", len(data.Tunnels)).Info("Tunnel config applied")

	// Trigger immediate status report so backend reflects online state without waiting for periodic interval
	go func() {
		time.Sleep(1 * time.Second)
		_ = c.statusReport()
	}()

	return nil
}

func (c *TunnelController) startForwarder(tunnelId int, f *panel.Forwarder) error {
	switch f.ForwarderType {
	case "relay", "waterwall":
		// Relay engine handles forwarding rules internally
		c.logger.WithField("tunnelId", tunnelId).Debug("Skipping relay forwarder (handled by relay engine)")
		return nil

	default:
		return fmt.Errorf("unknown forwarder type: %s", f.ForwarderType)
	}
}

func (c *TunnelController) startXrayInstance(t panel.TunnelInfo) error {
	if t.XrayConfig == nil {
		return fmt.Errorf("xray_config is missing for xray tunnel")
	}

	// Build raw JSON from the structured API struct
	logLevel := c.nodeConfig.LogConfig.Level
	if logLevel == "" {
		logLevel = "warning"
	}
	xrayJSON := c.buildXrayJSON(t, t.XrayConfig, logLevel)

	// Log the generated JSON at debug level for troubleshooting
	c.logger.WithField("json", xrayJSON).Debug("Generated Xray JSON")

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
	ensureLogDir(c.nodeConfig.LogConfig.Access)
	ensureLogDir(c.nodeConfig.LogConfig.Output)

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
		_ = instance.Close()
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

func (c *TunnelController) buildXrayReverseJSON(t panel.TunnelInfo, cfg *panel.XrayReverseTunnelConfig, logLevel string) string {
	obj := map[string]interface{}{
		"log": map[string]interface{}{
			"loglevel": logLevel,
		},
		"inbounds":  []interface{}{},
		"outbounds": []interface{}{},
		"routing": map[string]interface{}{
			"rules": []interface{}{},
		},
	}

	streamSettings := map[string]interface{}{
		"network": cfg.Transport,
	}

	if cfg.Transport == "ws" {
		wsSettings := map[string]interface{}{}
		if cfg.Path != "" {
			wsSettings["path"] = cfg.Path
		}
		if cfg.Host != "" {
			wsSettings["headers"] = map[string]interface{}{
				"Host": cfg.Host,
			}
		}
		streamSettings["wsSettings"] = wsSettings
	} else if cfg.Transport == "grpc" {
		streamSettings["grpcSettings"] = map[string]interface{}{
			"serviceName": cfg.Path,
		}
	} else if cfg.Transport == "tcp" {
		if cfg.Path != "" { // Using HTTP obfs
			streamSettings["tcpSettings"] = map[string]interface{}{
				"header": map[string]interface{}{
					"type": "http",
					"request": map[string]interface{}{
						"path": []string{cfg.Path},
					},
				},
			}
		}
	} else if cfg.Transport == "xhttp" || cfg.Transport == "splithttp" {
		xhttpSettings := map[string]interface{}{
			"path": cfg.Path,
		}
		if cfg.Host != "" {
			xhttpSettings["host"] = cfg.Host
		}
		if cfg.XhttpMode != "" {
			xhttpSettings["mode"] = cfg.XhttpMode
		}
		if cfg.XhttpExtra != "" {
			var extraObj interface{}
			if err := json.Unmarshal([]byte(cfg.XhttpExtra), &extraObj); err == nil {
				xhttpSettings["extra"] = extraObj
			}
		}
		streamSettings["xhttpSettings"] = xhttpSettings
	}

	if cfg.Security == "tls" || cfg.Security == "reality" {
		streamSettings["security"] = cfg.Security
		if cfg.Security == "tls" {
			tlsSettings := map[string]interface{}{}
			if cfg.ServerName != "" {
				tlsSettings["serverName"] = cfg.ServerName
			}
			if cfg.Fingerprint != "" {
				tlsSettings["fingerprint"] = cfg.Fingerprint
			}
			streamSettings["tlsSettings"] = tlsSettings
		} else if cfg.Security == "reality" {
			realitySettings := map[string]interface{}{
				"publicKey": cfg.RealityPublicKey,
				"shortId":   cfg.RealityShortId,
			}
			if cfg.ServerName != "" {
				realitySettings["serverName"] = cfg.ServerName
			}
			if cfg.Fingerprint != "" {
				realitySettings["fingerprint"] = cfg.Fingerprint
			}
			if cfg.RealitySpiderX != "" {
				realitySettings["spiderX"] = cfg.RealitySpiderX
			}
			streamSettings["realitySettings"] = realitySettings
		}
	}

	if t.Role == "entry" {
		// Portal node
		// 1. Inbound for clients (Forwarders)
		for _, f := range t.Forwarders {
			inb := map[string]interface{}{
				"listen":   "0.0.0.0",
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
			
			// Routing rule: forwarder -> portal
			rule := map[string]interface{}{
				"type":        "field",
				"inboundTag":  []string{fmt.Sprintf("dokodemo-%d", f.ListenPort)},
				"outboundTag": "portal",
			}
			obj["routing"].(map[string]interface{})["rules"] = append(obj["routing"].(map[string]interface{})["rules"].([]interface{}), rule)
		}

		// 2. Inbound for Bridge (Portal inbound)
		inbPortal := map[string]interface{}{
			"tag":      "inbound-portal",
			"port":     cfg.PortalPort,
			"protocol": "vless",
			"settings": map[string]interface{}{
				"clients": []interface{}{
					map[string]interface{}{
						"id": cfg.UUID,
						"reverse": map[string]interface{}{
							"tag": "portal",
						},
					},
				},
				"decryption": "none",
			},
			"streamSettings": streamSettings,
		}
		obj["inbounds"] = append(obj["inbounds"].([]interface{}), inbPortal)

	} else {
		// Bridge node
		// 1. Outbound to Portal
		outbBridge := map[string]interface{}{
			"protocol": "vless",
			"settings": map[string]interface{}{
				"address":    cfg.PortalAddress,
				"port":       cfg.PortalPublicPort,
				"id":         cfg.UUID,
				"encryption": "none",
				"reverse": map[string]interface{}{
					"tag": "bridge",
				},
			},
			"tag":            "bridge-out",
			"streamSettings": streamSettings,
		}
		obj["outbounds"] = append(obj["outbounds"].([]interface{}), outbBridge)

		// 2. Default Outbound (Freedom)
		outbFreedom := map[string]interface{}{
			"protocol": "freedom",
			"settings": map[string]interface{}{},
			"tag":      "direct",
		}
		obj["outbounds"] = append(obj["outbounds"].([]interface{}), outbFreedom)

		// 3. Routing from bridge to freedom
		rule := map[string]interface{}{
			"type":        "field",
			"inboundTag":  []string{"bridge"},
			"outboundTag": "direct",
		}
		obj["routing"].(map[string]interface{})["rules"] = append(obj["routing"].(map[string]interface{})["rules"].([]interface{}), rule)
	}

	b, _ := json.Marshal(obj)
	return string(b)
}

func (c *TunnelController) startXrayReverseInstance(t panel.TunnelInfo) error {
	if t.XrayReverseConfig == nil {
		return fmt.Errorf("xray_reverse_config is missing for xray-reverse tunnel")
	}

	logLevel := c.nodeConfig.LogConfig.Level
	if logLevel == "" {
		logLevel = "warning"
	}

	xrayJSON := c.buildXrayReverseJSON(t, t.XrayReverseConfig, logLevel)

	// 1. Write config to disk for debugging/persisting
	configPath := filepath.Join(c.tunnelDir, fmt.Sprintf("xray-reverse-%d.json", t.Id))
	if err := os.WriteFile(configPath, []byte(xrayJSON), 0644); err != nil {
		c.logger.WithFields(log.Fields{
			"tunnelId": t.Id,
			"err":      err,
		}).Warn("Failed to write xray-reverse config to disk")
	}

	// 2. Start Xray-core process natively
	c.logger.WithField("json", xrayJSON).Debug("Generated Xray Reverse JSON")

	reader := bytes.NewReader([]byte(xrayJSON))
	confObj, err := confserial.DecodeJSONConfig(reader)
	if err != nil {
		return fmt.Errorf("failed to parse xray-reverse config JSON: %v", err)
	}

	configObj, err := confObj.Build()
	if err != nil {
		return fmt.Errorf("failed to build xray-reverse config protobuf: %v", err)
	}

	ensureLogDir(c.nodeConfig.LogConfig.Access)
	ensureLogDir(c.nodeConfig.LogConfig.Output)

	coreLogConfig := &coreConf.LogConfig{
		LogLevel:  logLevel,
		ErrorLog:  c.nodeConfig.LogConfig.Output,
		AccessLog: c.nodeConfig.LogConfig.Access,
	}
	appLogMsg := serial.ToTypedMessage(coreLogConfig.Build())

	configObj.App = append([]*serial.TypedMessage{appLogMsg}, configObj.App...)

	instance, err := core.New(configObj)
	if err != nil {
		return fmt.Errorf("failed to initialize xray-reverse instance: %v", err)
	}

	if err := instance.Start(); err != nil {
		_ = instance.Close()
		return fmt.Errorf("failed to start xray-reverse instance: %v", err)
	}

	c.xrayMu.Lock()
	if c.xrayInstances == nil {
		c.xrayInstances = make(map[int]*core.Instance)
	}
	c.xrayInstances[t.Id] = instance
	c.xrayMu.Unlock()

	c.logger.WithField("tunnelId", t.Id).Info("Xray-reverse tunnel instance started natively in Go")
	return nil
}

func (c *TunnelController) buildXrayJSON(t panel.TunnelInfo, cfg *panel.XrayTunnelProtocol, logLevel string) string {
	obj := map[string]interface{}{
		"log": map[string]interface{}{
			"loglevel": logLevel,
		},
		"inbounds":  []interface{}{},
		"outbounds": []interface{}{},
	}

	if t.Role == "entry" {
		// Entry node: Create dokodemo-door forwarders + outbound client proxy connection
		for _, f := range t.Forwarders {
			listen := "0.0.0.0"
			if f.ListenIP != "" {
				listen = f.ListenIP
			} else if cfg.ListenIP != "" {
				// Fallback to global ListenIP ONLY for backward compatibility 
				// (ideally dokodemo-door should bind to 0.0.0.0 by default)
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

		// Handle raw PEM certificate strings directly from the DB by rewriting them to the disk using central certutil
		if cfg.CertFile != "" && strings.Contains(cfg.CertFile, "-----BEGIN") {
			certPath, keyPath := certutil.GetCertPaths(cfg.SNI, "tunnel", t.Id)

			// Ensure the directory exists
			dir := filepath.Dir(certPath)
			if !file.IsExist(dir) {
				os.MkdirAll(dir, 0755)
			}

			os.WriteFile(certPath, []byte(cfg.CertFile), 0644)
			cfg.CertFile = certPath

			if cfg.KeyFile != "" && strings.Contains(cfg.KeyFile, "-----BEGIN") {
				os.WriteFile(keyPath, []byte(cfg.KeyFile), 0600)
				cfg.KeyFile = keyPath
			}
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

	if cfg.Transport == "xhttp" || cfg.Transport == "splithttp" {
		xhttpSettings := map[string]interface{}{
			"mode": cfg.XhttpMode,
			"path": cfg.Path,
		}
		if cfg.Host != "" {
			xhttpSettings["host"] = cfg.Host
		}
		if cfg.XhttpExtra != "" {
			var extraObj interface{}
			if err := json.Unmarshal([]byte(cfg.XhttpExtra), &extraObj); err == nil {
				xhttpSettings["extra"] = extraObj
			}
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

	c.logger.Info("All forwarders stopped")
}

func (c *TunnelController) startXrayStealthInstance(t panel.TunnelInfo) error {
	if t.XrayConfig == nil {
		return fmt.Errorf("xray_config is missing for xray-stealth tunnel")
	}

	logLevel := c.nodeConfig.LogConfig.Level
	if logLevel == "" {
		logLevel = "warning"
	}

	xrayJSON := c.buildXrayJSON(t, t.XrayConfig, logLevel)

	// Write Xray config to disk
	configPath := filepath.Join(c.tunnelDir, fmt.Sprintf("xray_stealth_%d.json", t.Id))
	if err := os.WriteFile(configPath, []byte(xrayJSON), 0644); err != nil {
		c.logger.WithFields(log.Fields{
			"tunnelId": t.Id,
			"err":      err,
		}).Warn("Failed to write xray_stealth config to disk")
	}

	// Start Xray
	reader := bytes.NewReader([]byte(xrayJSON))
	confObj, err := confserial.DecodeJSONConfig(reader)
	if err != nil {
		return fmt.Errorf("failed to parse xray-stealth config JSON: %v", err)
	}

	configObj, err := confObj.Build()
	if err != nil {
		return fmt.Errorf("failed to build xray-stealth config protobuf: %v", err)
	}

	ensureLogDir(c.nodeConfig.LogConfig.Access)
	ensureLogDir(c.nodeConfig.LogConfig.Output)

	coreLogConfig := &coreConf.LogConfig{
		LogLevel:  logLevel,
		ErrorLog:  c.nodeConfig.LogConfig.Output,
		AccessLog: c.nodeConfig.LogConfig.Access,
	}
	appLogMsg := serial.ToTypedMessage(coreLogConfig.Build())
	configObj.App = append([]*serial.TypedMessage{appLogMsg}, configObj.App...)

	instance, err := core.New(configObj)
	if err != nil {
		return fmt.Errorf("failed to initialize xray-stealth instance: %v", err)
	}

	if err := instance.Start(); err != nil {
		_ = instance.Close()
		return fmt.Errorf("failed to start xray-stealth instance: %v", err)
	}

	c.xrayMu.Lock()
	if c.xrayInstances == nil {
		c.xrayInstances = make(map[int]*core.Instance)
	}
	c.xrayInstances[t.Id] = instance
	c.xrayMu.Unlock()

	c.logger.WithField("tunnelId", t.Id).Info("Xray-stealth tunnel instance started natively in Go")
	return nil
}

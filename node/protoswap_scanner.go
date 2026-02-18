package node

import (
	"context"
	"fmt"
	"math"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/archnets/node/api/panel"
	log "github.com/sirupsen/logrus"
)

// scanState tracks whether a scan is currently running for a tunnel
var (
	activeScansMu sync.Mutex
	activeScans   = make(map[int]*scanContext) // tunnel_id -> context
)

type scanContext struct {
	cancel context.CancelFunc
	signal string // "cancel" or "pause" set by handleScanCommand
	mu     sync.Mutex
}

// setSignal safely sets the signal
func (s *scanContext) setSignal(sig string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.signal = sig
}

// getSignal safely gets the signal
func (s *scanContext) getSignal() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.signal
}

// isScanRunning checks if a scan is running for the given tunnel ID
func (c *TunnelController) isScanRunning(tunnelId int) bool {
	activeScansMu.Lock()
	defer activeScansMu.Unlock()
	_, exists := activeScans[tunnelId]
	return exists
}

// handleScanCommand checks if a scan command should be launched or controlled for a tunnel
func (c *TunnelController) handleScanCommand(t panel.TunnelInfo) {
	activeScansMu.Lock()
	sCtx, exists := activeScans[t.Id]
	activeScansMu.Unlock()

	cmd := t.ScanCommand

	// Handle existing scan
	if exists {
		// Check if we need to cancel or pause
		if cmd.Signal == "cancel" || cmd.Signal == "pause" {
			// Only cancel if not already signaled (to avoid repeated cancels)
			if sCtx.getSignal() == "" {
				c.logger.WithField("tunnel_id", t.Id).Infof("Received %s signal for active scan", cmd.Signal)
				sCtx.setSignal(cmd.Signal)
				sCtx.cancel()
			}
		}
		return
	}

	// Should not start if signal is present (it's a stale signal)
	if cmd.Signal != "" {
		return
	}

	// Start new scan
	ctx, cancel := context.WithCancel(context.Background())
	newSCtx := &scanContext{
		cancel: cancel,
	}

	activeScansMu.Lock()
	activeScans[t.Id] = newSCtx
	activeScansMu.Unlock()

	c.logger.WithFields(log.Fields{
		"tunnel_id": t.Id,
		"protocol":  cmd.Protocol,
		"resume":    cmd.ResumeFrom > 0 || cmd.ResumePhase != "",
	}).Info("ProtoSwap scan command received, starting scan")

	// Report running status
	if err := c.apiClient.ReportScanResults(&panel.ScanResultsRequest{
		TunnelId: t.Id,
		Status:   "running",
		Progress: 0,
		Results:  []panel.ScanResultItem{},
	}); err != nil {
		c.logger.WithField("err", err).Warn("Failed to report scan running status")
	}

	go c.runProtoswapScan(ctx, t, newSCtx)
}

// runProtoswapScan performs the two-phase protocol scan for a tunnel
func (c *TunnelController) runProtoswapScan(ctx context.Context, t panel.TunnelInfo, sCtx *scanContext) {
	defer func() {
		activeScansMu.Lock()
		delete(activeScans, t.Id)
		activeScansMu.Unlock()
	}()

	cmd := t.ScanCommand
	results := []panel.ScanResultItem{}
	originalConfig := t.ConfigJSON // Save original config for restore

	// Get the current tunnel's device name and private IPs from config
	deviceName := extractDeviceNameFromConfig(t.ConfigJSON)
	if deviceName == "" {
		c.reportScanError(t.Id, "could not find TUN device name in config")
		return
	}

	// Extract current protoswap values from config
	currentTCP, currentUDP := extractProtoswapValues(t.ConfigJSON)

	// Determine which protocols to scan
	scanTCP := cmd.Protocol == "tcp" || cmd.Protocol == "both"
	scanUDP := cmd.Protocol == "udp" || cmd.Protocol == "both"

	// Handle resume logic
	// If resuming UDP, skip TCP entirely
	if cmd.ResumePhase == "udp" {
		scanTCP = false
		scanUDP = true // Ensure UDP is scanned even if original was "tcp" (though backend handles this)
	}

	totalTests := 0
	if scanTCP {
		totalTests += 256
	}
	if scanUDP {
		totalTests += 256
	}
	if totalTests == 0 {
		return
	}

	completed := 0
	// If resuming, adjust completed count validly is tricky without exact history,
	// but we can estimate or just use the resume loop index.
	// For progress bar, strict exactness isn't critical, but nice to have.
	// We'll calculate progress based on loops.

	// Time-slotted execution constants
	const slotDuration = 15 * time.Second
	const entryNodeDelay = 3 * time.Second

	// Helper to wait for the correct time slot for a protocol
	waitAndSetProto := func(proto int, targetPhase string) bool {
		// Calculate target time for this protocol
		// Protocol index: 0..255 for TCP, then 256..511 for UDP (if both scanned)
		// But here we might be running just one phase or both.
		// To keep it simple and synchronized, we map:
		// TCP 0-255 -> Slot 0-255
		// UDP 0-255 -> Slot 256-511 (if TCP scanned first), or 0-255 if only UDP?
		// User requirement says "Entry/Exit nodes ... same protocol at same time".
		// Implies: Slot N = Protocol N.
		// If we are scanning UDP, and it's 2nd phase, does it reuse slots 0-255 or continue?
		// Rationale: If Exit node is also looping 0-255, we must align with that.
		// Exit node logic (planned): Loop 0-255 for current phase.
		// So both nodes must agree on "Current Phase".
		// Problem: How does Exit node know we switched to UDP?
		// Be simpler: The StartTime defines the start of THIS scan command.
		// ScanCommand has specific Protocol (tcp/udp/both).
		// If "both":
		//   Slots 0-255: TCP 0-255
		//   Slots 256-511: UDP 0-255
		// If "tcp":
		//   Slots 0-255: TCP 0-255
		// If "udp":
		//   Slots 0-255: UDP 0-255 (Exit node will run UDP loop)

		slotIndex := proto
		if targetPhase == "udp" && scanTCP {
			slotIndex += 256
		}

		targetTime := time.Unix(cmd.StartTime, 0).Add(time.Duration(slotIndex) * slotDuration)

		// Entry node adds a buffer to allow Exit node to restart first
		readyTime := targetTime.Add(entryNodeDelay)

		// Check if we are already past the slot window (15s)
		if time.Now().After(readyTime.Add(slotDuration - entryNodeDelay)) {
			// Too late for this slot, skip or fail?
			// If we are way behind, we should skip to catch up.
			return false // Signal to skip
		}

		// Wait until readyTime
		wait := time.Until(readyTime)
		if wait > 0 {
			select {
			case <-time.After(wait):
			case <-ctx.Done():
				return false
			}
		}

		// Set config
		var newConfigJSON string
		if targetPhase == "tcp" {
			newConfigJSON = setProtoswapInConfig(t.ConfigJSON, proto, currentUDP)
		} else {
			// Use bestTCP if available, otherwise currentTCP
			tcpVal := currentTCP
			if targetPhase == "udp" && scanTCP && len(results) > 0 {
				bestSpeed := int64(0)
				for _, r := range results {
					if r.Type == "tcp" && r.DownloadSpeed > bestSpeed {
						bestSpeed = r.DownloadSpeed
						tcpVal = r.ProtocolNumber
					}
				}
			}
			newConfigJSON = setProtoswapInConfig(t.ConfigJSON, tcpVal, proto)
		}

		if err := c.hotReloadWaterwallConfig(t.Id, newConfigJSON); err != nil {
			c.logger.WithField("err", err).Error("Failed to hot-reload WaterWall")
			return false
		}

		// Wait for TUN
		time.Sleep(2 * time.Second)
		return true
	}

	// Phase 1+2 for TCP
	if scanTCP {
		for proto := 0; proto < 256; proto++ {
			// Check cancel
			select {
			case <-ctx.Done():
				c.handleScanInterruption(t.Id, sCtx.getSignal(), originalConfig, results, proto-1, "tcp")
				return
			default:
			}

			// Resume skipping
			if cmd.ResumePhase == "tcp" && proto <= cmd.ResumeFrom {
				completed++
				continue
			}

			// Skip current UDP value
			if proto == currentUDP {
				completed++
				continue
			}

			// Sync Wait
			if !waitAndSetProto(proto, "tcp") {
				// Skipped or interrupted
				select {
				case <-ctx.Done():
					c.handleScanInterruption(t.Id, sCtx.getSignal(), originalConfig, results, proto-1, "tcp")
					return
				default:
					c.logger.WithField("proto", proto).Warn("Skipped TCP slot due to lag")
					completed++
					continue
				}
			}

			// Run checks (Phase 1 & 2) - reduced timeout to fit in slot
			// Slot is 15s. We waited 2s for TUN + 3s buffer = 5s used.
			// Remaining: 10s.
			// Conn check: 2s timeout. Speed test: 7s.

			latency, ok := c.tcpConnectivityCheck(t.RemoteIP, cmd.TcpTestPort, 2*time.Second)
			if ok {
				upload, download := c.tcpSpeedTest(t.RemoteIP, cmd.TcpTestPort, 7*time.Second)
				results = append(results, panel.ScanResultItem{
					ProtocolNumber: proto,
					Type:           "tcp",
					LatencyMs:      latency,
					UploadSpeed:    upload,
					DownloadSpeed:  download,
				})
			}

			completed++
			progress := int(float64(completed) / float64(totalTests) * 100)

			if completed%10 == 0 || completed == totalTests {
				if err := c.apiClient.ReportScanResults(&panel.ScanResultsRequest{
					TunnelId:   t.Id,
					Status:     "running",
					Progress:   progress,
					Results:    results,
					LastTested: proto,
					Phase:      "tcp",
				}); err != nil {
					c.logger.WithField("err", err).Warn("Failed to report scan progress")
				}
			}
		}
	}

	// Phase 1+2 for UDP
	if scanUDP {
		bestTCP := currentTCP
		if scanTCP && len(results) > 0 {
			bestSpeed := int64(0)
			for _, r := range results {
				if r.Type == "tcp" && r.DownloadSpeed > bestSpeed {
					bestSpeed = r.DownloadSpeed
					bestTCP = r.ProtocolNumber
				}
			}
		}

		for proto := 0; proto < 256; proto++ {
			select {
			case <-ctx.Done():
				c.handleScanInterruption(t.Id, sCtx.getSignal(), originalConfig, results, proto-1, "udp")
				return
			default:
			}

			if cmd.ResumePhase == "udp" && proto <= cmd.ResumeFrom {
				completed++
				continue
			}

			if proto == bestTCP {
				completed++
				continue
			}

			// Sync Wait
			if !waitAndSetProto(proto, "udp") {
				select {
				case <-ctx.Done():
					c.handleScanInterruption(t.Id, sCtx.getSignal(), originalConfig, results, proto-1, "udp")
					return
				default:
					c.logger.WithField("proto", proto).Warn("Skipped UDP slot due to lag")
					completed++
					continue
				}
			}

			latency, packetLoss, jitter, ok := c.udpConnectivityCheck(t.RemoteIP, cmd.UdpTestPort, 2*time.Second)
			if ok {
				upload, download := c.udpSpeedTest(t.RemoteIP, cmd.UdpTestPort, 7*time.Second)
				results = append(results, panel.ScanResultItem{
					ProtocolNumber: proto,
					Type:           "udp",
					LatencyMs:      latency,
					UploadSpeed:    upload,
					DownloadSpeed:  download,
					PacketLoss:     packetLoss,
					Jitter:         jitter,
				})
			}

			completed++
			progress := int(float64(completed) / float64(totalTests) * 100)

			if completed%10 == 0 || completed == totalTests {
				if err := c.apiClient.ReportScanResults(&panel.ScanResultsRequest{
					TunnelId:   t.Id,
					Status:     "running",
					Progress:   progress,
					Results:    results,
					LastTested: proto,
					Phase:      "udp",
				}); err != nil {
					c.logger.WithField("err", err).Warn("Failed to report scan progress")
				}
			}
		}
	}

	// Restore WaterWall config with best-found protocol values
	bestTCPVal, bestUDPVal := currentTCP, currentUDP
	for _, r := range results {
		if r.Type == "tcp" && r.DownloadSpeed > 0 {
			if bestTCPVal == currentTCP || r.DownloadSpeed > findSpeed(results, bestTCPVal, "tcp") {
				bestTCPVal = r.ProtocolNumber
			}
		}
		if r.Type == "udp" && r.DownloadSpeed > 0 {
			if bestUDPVal == currentUDP || r.DownloadSpeed > findSpeed(results, bestUDPVal, "udp") {
				bestUDPVal = r.ProtocolNumber
			}
		}
	}

	// Ensure exclusivity: if best TCP == best UDP, keep UDP as original
	if bestTCPVal == bestUDPVal {
		bestUDPVal = currentUDP
	}

	finalConfig := setProtoswapInConfig(t.ConfigJSON, bestTCPVal, bestUDPVal)
	if err := c.hotReloadWaterwallConfig(t.Id, finalConfig); err != nil {
		c.logger.WithField("err", err).Error("Failed to restore WaterWall config after scan")
	} else {
		c.logger.WithFields(log.Fields{
			"tunnel_id": t.Id,
			"best_tcp":  bestTCPVal,
			"best_udp":  bestUDPVal,
		}).Info("WaterWall config restored with best protocol values")
	}

	// Report completion
	if err := c.apiClient.ReportScanResults(&panel.ScanResultsRequest{
		TunnelId: t.Id,
		Status:   "completed",
		Progress: 100,
		Results:  results,
	}); err != nil {
		c.logger.WithField("err", err).Warn("Failed to report scan completion")
	}

	c.logger.WithFields(log.Fields{
		"tunnel_id": t.Id,
		"results":   len(results),
	}).Info("ProtoSwap scan completed")
}

// handleScanInterruption handles pause or cancel: restores original config and reports status
func (c *TunnelController) handleScanInterruption(tunnelId int, signal string, originalConfig string, results []panel.ScanResultItem, lastProto int, phase string) {
	// Restore original config
	if err := c.hotReloadWaterwallConfig(tunnelId, originalConfig); err != nil {
		c.logger.WithField("err", err).Error("Failed to restore original config after interruption")
	} else {
		c.logger.WithField("tunnel_id", tunnelId).Info("Original WaterWall config restored")
	}

	status := "cancelled"
	if signal == "pause" {
		status = "paused"
	}

	c.logger.WithFields(log.Fields{
		"tunnel_id": tunnelId,
		"status":    status,
		"phase":     phase,
		"last":      lastProto,
	}).Info("Scan interrupted")

	// Report interruption
	c.apiClient.ReportScanResults(&panel.ScanResultsRequest{
		TunnelId:   tunnelId,
		Status:     status,
		Progress:   0, // Irrelevant for these states
		Results:    results,
		LastTested: lastProto,
		Phase:      phase,
	})
}

// testProtocol tests a single protocol number for TCP or UDP
// Returns nil if protocol did not connect (Phase 1 fail)
func (c *TunnelController) testProtocol(t panel.TunnelInfo, proto int, protoType string, testPort int, deviceName string, otherProtoValue int) *panel.ScanResultItem {
	// Modify the WaterWall config with the new protocol number
	var newConfigJSON string
	if protoType == "tcp" {
		newConfigJSON = setProtoswapInConfig(t.ConfigJSON, proto, otherProtoValue)
	} else {
		newConfigJSON = setProtoswapInConfig(t.ConfigJSON, otherProtoValue, proto)
	}

	// Write the modified config and restart WaterWall
	if err := c.hotReloadWaterwallConfig(t.Id, newConfigJSON); err != nil {
		c.logger.WithFields(log.Fields{
			"proto": proto,
			"type":  protoType,
			"err":   err,
		}).Debug("Failed to hot-reload WaterWall config")
		return nil
	}

	// Wait for WaterWall to restart and TUN interface to come up
	time.Sleep(2 * time.Second)

	// Phase 1: Quick connectivity check
	if protoType == "tcp" {
		latency, ok := c.tcpConnectivityCheck(t.RemoteIP, testPort, 3*time.Second)
		if !ok {
			return nil // Connection failed
		}

		// Phase 2: Speed test (only if Phase 1 passed)
		upload, download := c.tcpSpeedTest(t.RemoteIP, testPort, 10*time.Second)

		return &panel.ScanResultItem{
			ProtocolNumber: proto,
			Type:           "tcp",
			LatencyMs:      latency,
			UploadSpeed:    upload,
			DownloadSpeed:  download,
		}
	} else {
		// UDP connectivity check
		latency, packetLoss, jitter, ok := c.udpConnectivityCheck(t.RemoteIP, testPort, 3*time.Second)
		if !ok {
			return nil
		}

		// UDP speed test
		upload, download := c.udpSpeedTest(t.RemoteIP, testPort, 10*time.Second)

		return &panel.ScanResultItem{
			ProtocolNumber: proto,
			Type:           "udp",
			LatencyMs:      latency,
			UploadSpeed:    upload,
			DownloadSpeed:  download,
			PacketLoss:     packetLoss,
			Jitter:         jitter,
		}
	}
}

// tcpConnectivityCheck performs Phase 1 TCP check: try to connect to the test port
// through the tunnel and measure latency
func (c *TunnelController) tcpConnectivityCheck(remoteIP string, port int, timeout time.Duration) (latencyMs int, ok bool) {
	addr := net.JoinHostPort(remoteIP, strconv.Itoa(port))
	start := time.Now()
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return 0, false
	}
	latency := time.Since(start)
	conn.Close()
	return int(latency.Milliseconds()), true
}

// tcpSpeedTest performs Phase 2 TCP speed test: send and receive data to measure throughput
func (c *TunnelController) tcpSpeedTest(remoteIP string, port int, timeout time.Duration) (uploadBps, downloadBps int64) {
	addr := net.JoinHostPort(remoteIP, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return 0, 0
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	// Upload test: send 1MB of data
	uploadData := make([]byte, 1024*1024) // 1MB
	for i := range uploadData {
		uploadData[i] = byte(i % 256)
	}

	start := time.Now()
	n, err := conn.Write(uploadData)
	uploadDuration := time.Since(start)
	if err != nil || n == 0 {
		return 0, 0
	}
	uploadBps = int64(float64(n) / uploadDuration.Seconds())

	// Download test: read as much as possible in remaining time
	downloadBuf := make([]byte, 1024*1024)
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	start = time.Now()
	totalRead := 0
	for {
		n, err := conn.Read(downloadBuf)
		totalRead += n
		if err != nil || totalRead >= 1024*1024 {
			break
		}
	}
	downloadDuration := time.Since(start)
	if totalRead > 0 && downloadDuration.Seconds() > 0 {
		downloadBps = int64(float64(totalRead) / downloadDuration.Seconds())
	}

	return uploadBps, downloadBps
}

// udpConnectivityCheck performs Phase 1 UDP check: send packets and measure
// latency, packet loss, and jitter
func (c *TunnelController) udpConnectivityCheck(remoteIP string, port int, timeout time.Duration) (latencyMs, packetLoss, jitterMs int, ok bool) {
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", remoteIP, port))
	if err != nil {
		return 0, 100, 0, false
	}

	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return 0, 100, 0, false
	}
	defer conn.Close()

	const numPackets = 20
	var latencies []int64
	received := 0

	for i := 0; i < numPackets; i++ {
		// Send a numbered packet
		payload := fmt.Sprintf("PING:%d:%d", time.Now().UnixNano(), i)
		conn.SetWriteDeadline(time.Now().Add(timeout))
		_, err := conn.Write([]byte(payload))
		if err != nil {
			continue
		}

		// Wait for echo reply
		buf := make([]byte, 1024)
		conn.SetReadDeadline(time.Now().Add(timeout))
		_, err = conn.Read(buf)
		if err != nil {
			continue
		}

		rtt := time.Since(time.Unix(0, extractTimestamp(payload)))
		latencies = append(latencies, rtt.Milliseconds())
		received++
	}

	if received == 0 {
		return 0, 100, 0, false
	}

	// Calculate statistics
	var totalLatency int64
	for _, l := range latencies {
		totalLatency += l
	}
	avgLatency := totalLatency / int64(received)
	loss := int((1.0 - float64(received)/float64(numPackets)) * 100)

	// Calculate jitter (average deviation from mean)
	var totalDeviation float64
	for _, l := range latencies {
		totalDeviation += math.Abs(float64(l) - float64(avgLatency))
	}
	jitter := int(totalDeviation / float64(len(latencies)))

	return int(avgLatency), loss, jitter, loss < 50 // Consider OK if <50% loss
}

// udpSpeedTest performs Phase 2 UDP speed test
func (c *TunnelController) udpSpeedTest(remoteIP string, port int, timeout time.Duration) (uploadBps, downloadBps int64) {
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", remoteIP, port))
	if err != nil {
		return 0, 0
	}

	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return 0, 0
	}
	defer conn.Close()

	// Upload test: send 100 x 1KB packets
	packet := make([]byte, 1024) // 1KB
	for i := range packet {
		packet[i] = byte(i % 256)
	}

	start := time.Now()
	totalSent := 0
	for i := 0; i < 100; i++ {
		conn.SetWriteDeadline(time.Now().Add(1 * time.Second))
		n, err := conn.Write(packet)
		if err != nil {
			break
		}
		totalSent += n
	}
	uploadDuration := time.Since(start)
	if totalSent > 0 && uploadDuration.Seconds() > 0 {
		uploadBps = int64(float64(totalSent) / uploadDuration.Seconds())
	}

	// Download test: read replies
	downloadBuf := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	start = time.Now()
	totalRead := 0
	for {
		n, err := conn.Read(downloadBuf)
		totalRead += n
		if err != nil {
			break
		}
	}
	downloadDuration := time.Since(start)
	if totalRead > 0 && downloadDuration.Seconds() > 0 {
		downloadBps = int64(float64(totalRead) / downloadDuration.Seconds())
	}

	return uploadBps, downloadBps
}

// hotReloadWaterwallConfig writes a modified config and restarts WaterWall
func (c *TunnelController) hotReloadWaterwallConfig(tunnelId int, configJSON string) error {
	filename := fmt.Sprintf(TunnelConfigFmt, tunnelId)
	tunnelPath := fmt.Sprintf("%s/%s", c.tunnelDir, filename)
	if err := os.WriteFile(tunnelPath, []byte(configJSON), 0644); err != nil {
		return fmt.Errorf("write config: %w", err)
	}

	// Restart WaterWall with the new config (hold mutex across stop+start)
	c.waterwallMu.Lock()
	defer c.waterwallMu.Unlock()
	c.stopWaterwallLocked()
	time.Sleep(500 * time.Millisecond)
	return c.startWaterwallLocked()
}

// setProtoswapInConfig modifies the protoswap-tcp and protoswap-udp values in a WaterWall config JSON
func setProtoswapInConfig(configJSON string, tcpValue, udpValue int) string {
	tcpRegex := regexp.MustCompile(`"protoswap-tcp"\s*:\s*\d+`)
	udpRegex := regexp.MustCompile(`"protoswap-udp"\s*:\s*\d+`)

	result := tcpRegex.ReplaceAllString(configJSON, fmt.Sprintf(`"protoswap-tcp": %d`, tcpValue))
	result = udpRegex.ReplaceAllString(result, fmt.Sprintf(`"protoswap-udp": %d`, udpValue))
	return result
}

// extractProtoswapValues extracts current protoswap-tcp and protoswap-udp from config JSON
func extractProtoswapValues(configJSON string) (tcp, udp int) {
	tcpRegex := regexp.MustCompile(`"protoswap-tcp"\s*:\s*(\d+)`)
	udpRegex := regexp.MustCompile(`"protoswap-udp"\s*:\s*(\d+)`)

	if matches := tcpRegex.FindStringSubmatch(configJSON); len(matches) >= 2 {
		tcp, _ = strconv.Atoi(matches[1])
	}
	if matches := udpRegex.FindStringSubmatch(configJSON); len(matches) >= 2 {
		udp, _ = strconv.Atoi(matches[1])
	}
	return tcp, udp
}

// extractTimestamp extracts the nanosecond timestamp from a PING payload
func extractTimestamp(payload string) int64 {
	parts := strings.Split(payload, ":")
	if len(parts) >= 2 {
		ts, _ := strconv.ParseInt(parts[1], 10, 64)
		return ts
	}
	return 0
}

// findSpeed returns the download speed for a given protocol number and type in the results
func findSpeed(results []panel.ScanResultItem, protoNum int, protoType string) int64 {
	for _, r := range results {
		if r.ProtocolNumber == protoNum && r.Type == protoType {
			return r.DownloadSpeed
		}
	}
	return 0
}

// reportScanError reports a scan error to the backend
func (c *TunnelController) reportScanError(tunnelId int, errMsg string) {
	c.logger.WithFields(log.Fields{
		"tunnel_id": tunnelId,
		"error":     errMsg,
	}).Error("ProtoSwap scan failed")

	c.apiClient.ReportScanResults(&panel.ScanResultsRequest{
		TunnelId: tunnelId,
		Status:   "failed",
		Error:    errMsg,
		Progress: 0,
		Results:  []panel.ScanResultItem{},
	})
}

// ---- Echo servers for exit node ----

// echoServerState tracks active echo servers per tunnel
var (
	echoServersMu sync.Mutex
	echoServers   = make(map[int]*echoState) // tunnel_id -> state
)

type echoState struct {
	tcpListener net.Listener
	udpConn     *net.UDPConn
	stopChan    chan struct{}
	cancel      context.CancelFunc
}

// handleExitScanCommand starts echo servers on the exit node when a scan is requested
func (c *TunnelController) handleExitScanCommand(t panel.TunnelInfo) {
	echoServersMu.Lock()
	if _, exists := echoServers[t.Id]; exists {
		echoServersMu.Unlock()
		return // Already running
	}
	echoServersMu.Unlock()

	cmd := t.ScanCommand
	ctx, cancel := context.WithCancel(context.Background())
	state := &echoState{
		stopChan: make(chan struct{}),
		cancel:   cancel,
	}

	c.logger.WithFields(log.Fields{
		"tunnel_id":     t.Id,
		"tcp_test_port": cmd.TcpTestPort,
		"udp_test_port": cmd.UdpTestPort,
		"start_time":    cmd.StartTime,
	}).Info("Exit node: starting echo servers & sync loop for scan")

	// Start TCP echo server
	if cmd.TcpTestPort > 0 && (cmd.Protocol == "tcp" || cmd.Protocol == "both") {
		listener, err := startTCPEchoServer(cmd.TcpTestPort, state.stopChan, c.logger)
		if err != nil {
			c.logger.WithField("err", err).Error("Failed to start TCP echo server")
		} else {
			state.tcpListener = listener
		}
	}

	// Start UDP echo server
	if cmd.UdpTestPort > 0 && (cmd.Protocol == "udp" || cmd.Protocol == "both") {
		conn, err := startUDPEchoServer(cmd.UdpTestPort, state.stopChan, c.logger)
		if err != nil {
			c.logger.WithField("err", err).Error("Failed to start UDP echo server")
		} else {
			state.udpConn = conn
		}
	}

	echoServersMu.Lock()
	echoServers[t.Id] = state
	echoServersMu.Unlock()

	// Start active scanning loop if StartTime is set
	if cmd.StartTime > 0 {
		go c.runExitScanLoop(ctx, t)
	}

	// Auto-stop after 30 minutes (safety timeout)
	go func() {
		select {
		case <-state.stopChan:
			return
		case <-time.After(30 * time.Minute):
			c.logger.WithField("tunnel_id", t.Id).Info("Echo servers auto-stopping after 30min timeout")
			c.stopEchoServers(t.Id)
		}
	}()
}

// stopEchoServers stops echo servers for a tunnel
func (c *TunnelController) stopEchoServers(tunnelId int) {
	echoServersMu.Lock()
	state, exists := echoServers[tunnelId]
	if !exists {
		echoServersMu.Unlock()
		return
	}
	delete(echoServers, tunnelId)
	echoServersMu.Unlock()

	close(state.stopChan)
	if state.cancel != nil {
		state.cancel()
	}
	if state.tcpListener != nil {
		state.tcpListener.Close()
	}
	if state.udpConn != nil {
		state.udpConn.Close()
	}
	c.logger.WithField("tunnel_id", tunnelId).Info("Echo servers stopped")
}

// startTCPEchoServer starts a TCP listener that echoes all received data back
func startTCPEchoServer(port int, stop chan struct{}, logger *log.Entry) (net.Listener, error) {
	listener, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", port))
	if err != nil {
		return nil, fmt.Errorf("tcp listen on port %d: %w", port, err)
	}

	go func() {
		defer listener.Close()
		for {
			select {
			case <-stop:
				return
			default:
			}

			// Set accept deadline so we can check stop channel
			listener.(*net.TCPListener).SetDeadline(time.Now().Add(1 * time.Second))
			conn, err := listener.Accept()
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				return
			}

			// Handle each connection in a goroutine
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 32*1024) // 32KB buffer
				for {
					c.SetReadDeadline(time.Now().Add(30 * time.Second))
					n, err := c.Read(buf)
					if err != nil {
						return
					}
					c.SetWriteDeadline(time.Now().Add(10 * time.Second))
					_, err = c.Write(buf[:n])
					if err != nil {
						return
					}
				}
			}(conn)
		}
	}()

	logger.WithField("port", port).Info("TCP echo server started")
	return listener, nil
}

// startUDPEchoServer starts a UDP listener that echoes packets back to sender
func startUDPEchoServer(port int, stop chan struct{}, logger *log.Entry) (*net.UDPConn, error) {
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("0.0.0.0:%d", port))
	if err != nil {
		return nil, err
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("udp listen on port %d: %w", port, err)
	}

	go func() {
		defer conn.Close()
		buf := make([]byte, 65535)
		for {
			select {
			case <-stop:
				return
			default:
			}

			conn.SetReadDeadline(time.Now().Add(1 * time.Second))
			n, remoteAddr, err := conn.ReadFromUDP(buf)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				return
			}

			// Echo back
			conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			conn.WriteToUDP(buf[:n], remoteAddr)
		}
	}()

	logger.WithField("port", port).Info("UDP echo server started")
	return conn, nil
}

// runExitScanLoop manages the time-synchronized protocol switching for the exit server
func (c *TunnelController) runExitScanLoop(ctx context.Context, t panel.TunnelInfo) {
	cmd := t.ScanCommand
	startTime := time.Unix(cmd.StartTime, 0)

	// Determine protocols to scan
	scanTCP := cmd.Protocol == "tcp" || cmd.Protocol == "both"
	scanUDP := cmd.Protocol == "udp" || cmd.Protocol == "both"

	// Determine offset for UDP phase
	udpOffset := 256
	if !scanTCP {
		// If strict sync is required, we should align with Entry Node's logic.
		// If Entry Node starts UDP at 0 when protocol="udp", Exit must too.
		udpOffset = 0
		if scanTCP {
			udpOffset = 256
		}
	} else {
		// If both, TCP is 0, UDP is 256
		udpOffset = 256
	}

	const SlotDuration = 15 * time.Second

	c.logger.WithFields(log.Fields{
		"tunnel_id":  t.Id,
		"start_time": startTime,
		"udp_offset": udpOffset,
	}).Info("Starting exit scan loop")

	// Main Loop
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			c.logger.WithField("tunnel_id", t.Id).Info("Exit scan loop stopped")
			return
		case <-ticker.C:
			now := time.Now()
			elapsed := now.Sub(startTime)
			if elapsed < 0 {
				continue // Waiting for start time
			}

			slotIndex := int(elapsed / SlotDuration)

			// Determine which phase and protocol this slot belongs to
			var currentPhase string
			var proto int

			if scanTCP && slotIndex < 256 {
				currentPhase = "tcp"
				proto = slotIndex
			} else if scanUDP && slotIndex >= udpOffset && slotIndex < (udpOffset+256) {
				currentPhase = "udp"
				proto = slotIndex - udpOffset
			} else {
				// Slot out of range or in gap
				if slotIndex >= (udpOffset + 256) {
					// Scan finished
					cancelState(t.Id)
					return
				}
				continue // gap or waiting
			}

			// Apply config if new slot
			if shouldApplyConfig(t.Id, currentPhase, proto) {
				c.logger.WithFields(log.Fields{
					"phase": currentPhase,
					"proto": proto,
				}).Info("Exit node switching protocol")

				// Apply config
				var newConfigJSON string
				// Extract current values from original config
				currentTCP, currentUDP := extractProtoswapValues(t.ConfigJSON)

				if currentPhase == "tcp" {
					newConfigJSON = setProtoswapInConfig(t.ConfigJSON, proto, currentUDP)
				} else {
					// Use original TCP value for UDP scan
					newConfigJSON = setProtoswapInConfig(t.ConfigJSON, currentTCP, proto)
				}

				if err := c.hotReloadWaterwallConfig(t.Id, newConfigJSON); err != nil {
					c.logger.Error("Failed to switch config on exit node: ", err)
				}
				markConfigApplied(t.Id, currentPhase, proto)
			}
		}
	}
}

// Helper to deduce if we need to apply config
var (
	appliedConfigsMu sync.Mutex
	appliedConfigs   = make(map[int]string) // tunnelId -> "phase:proto"
)

func shouldApplyConfig(tunnelId int, phase string, proto int) bool {
	appliedConfigsMu.Lock()
	defer appliedConfigsMu.Unlock()
	key := fmt.Sprintf("%s:%d", phase, proto)
	if appliedConfigs[tunnelId] == key {
		return false
	}
	return true
}

func markConfigApplied(tunnelId int, phase string, proto int) {
	appliedConfigsMu.Lock()
	defer appliedConfigsMu.Unlock()
	appliedConfigs[tunnelId] = fmt.Sprintf("%s:%d", phase, proto)
}

func cancelState(tunnelId int) {
	echoServersMu.Lock()
	defer echoServersMu.Unlock()
	if state, exists := echoServers[tunnelId]; exists && state.cancel != nil {
		state.cancel()
	}
}

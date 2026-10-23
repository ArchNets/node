package node

import (
	"context"
	"math"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/archnets/node/api/panel"
	"github.com/archnets/node/core/relay"
	"github.com/archnets/node/core/relay/telemetry"
	log "github.com/sirupsen/logrus"
)

const (
	SandboxCarrierPort = 58443
	BenchmarkSlotDur   = 4 * time.Second
)

var (
	activeScansMu sync.Mutex
	activeScans   = make(map[int]*scanContext)

	exitSandboxMu sync.Mutex
	exitSandboxes = make(map[int]*exitSandboxState)
)

type scanContext struct {
	cancel context.CancelFunc
	signal string
	mu     sync.Mutex
}

func (s *scanContext) setSignal(sig string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.signal = sig
}

func (s *scanContext) getSignal() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.signal
}

type exitSandboxState struct {
	cancel context.CancelFunc
	engine *relay.Engine
	mu     sync.Mutex
}

// BenchmarkCandidate represents a single SNI or Transport/Method variation to benchmark.
type BenchmarkCandidate struct {
	Index         int
	SNI           string
	OriginIP      string
	Transport     string // "reverse-reality", "tls-reverse"
	MethodLabel   string
	UseHalfDuplex bool
	UseFisher     bool
}

// BuildBenchmarkCandidates constructs the ordered list of benchmark profiles for a ScanCommand.
func BuildBenchmarkCandidates(cmd *panel.ScanCommand, baseCfg *panel.RelayTunnelConfig) []BenchmarkCandidate {
	mode := "hospital"
	if cmd != nil && cmd.ScanMode != "" {
		mode = strings.ToLower(strings.TrimSpace(cmd.ScanMode))
	}

	baseSNI := ""
	if baseCfg != nil && baseCfg.SNI != "" {
		baseSNI = baseCfg.SNI
	}

	var candidates []BenchmarkCandidate
	switch mode {
	case "methods":
		variations := []struct {
			transport string
			label     string
			hd        bool
			fisher    bool
		}{
			{"reverse-reality", "Reverse Reality + HalfDuplex + Fisher", true, true},
			{"reverse-reality", "Reverse Reality + HalfDuplex", true, false},
			{"reverse-reality", "Reverse Reality + Fisher (Full-Duplex)", false, true},
			{"reverse-reality", "Reverse Reality (Base Full-Duplex)", false, false},
			{"tls-reverse", "TLS 1.3 Reverse + HalfDuplex + Fisher", true, true},
			{"tls-reverse", "TLS 1.3 Reverse + HalfDuplex", true, false},
			{"tls-reverse", "TLS 1.3 Reverse + Fisher", false, true},
			{"tls-reverse", "UDP-over-TCP Reality Mux + HalfDuplex + Fisher", true, true},
		}
		for i, v := range variations {
			candidates = append(candidates, BenchmarkCandidate{
				Index:         i + 1,
				SNI:           baseSNI,
				OriginIP:      "",
				Transport:     v.transport,
				MethodLabel:   v.label,
				UseHalfDuplex: v.hd,
				UseFisher:     v.fisher,
			})
		}

	default:
		var snis []telemetry.SNIPreset
		if cmd != nil && len(cmd.CustomSNIs) > 0 {
			for _, custom := range cmd.CustomSNIs {
				clean := strings.TrimSpace(custom)
				if clean != "" {
					orig, _ := telemetry.ResolveOriginIP(clean, "")
					snis = append(snis, telemetry.SNIPreset{
						SNI:      clean,
						Label:    clean,
						OriginIP: orig,
						Category: "custom",
					})
				}
			}
		}
		if len(snis) == 0 {
			snis = telemetry.GetActiveSNIPresets()
		}

		for i, preset := range snis {
			candidates = append(candidates, BenchmarkCandidate{
				Index:         i + 1,
				SNI:           preset.SNI,
				OriginIP:      preset.OriginIP,
				Transport:     "reverse-reality",
				MethodLabel:   "Reverse Reality + HalfDuplex + Fisher",
				UseHalfDuplex: true,
				UseFisher:     true,
			})
		}
	}

	return candidates
}

// ComputeBenchmarkScore computes a composite performance score from throughput, RTT, and packet loss.
func ComputeBenchmarkScore(uploadBps, downloadBps int64, latencyMs, packetLoss int) float64 {
	upMbps := float64(uploadBps) * 8.0 / 1_000_000.0
	downMbps := float64(downloadBps) * 8.0 / 1_000_000.0
	raw := (downMbps * 0.60) + (upMbps * 0.40) - (float64(latencyMs) * 0.12) - (float64(packetLoss) * 2.5)
	if raw < 0.1 {
		raw = 0.1
	}
	return math.Round(raw*100) / 100
}

func (c *TunnelController) isScanRunning(tunnelId int) bool {
	activeScansMu.Lock()
	defer activeScansMu.Unlock()
	_, exists := activeScans[tunnelId]
	return exists
}

func (c *TunnelController) handleScanCommand(t panel.TunnelInfo) {
	cmd := t.ScanCommand
	if cmd == nil {
		return
	}

	if cmd.ProbeNow {
		go c.runImmediateBandwidthProbe(t)
		return
	}

	activeScansMu.Lock()
	sCtx, exists := activeScans[t.Id]
	activeScansMu.Unlock()

	if exists {
		if cmd.Signal == "cancel" || cmd.Signal == "pause" {
			if sCtx.getSignal() == "" {
				c.logger.WithField("tunnel_id", t.Id).Infof("Received %s signal for active benchmark sweep", cmd.Signal)
				sCtx.setSignal(cmd.Signal)
				sCtx.cancel()
			}
		}
		return
	}

	if cmd.Signal != "" {
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	newSCtx := &scanContext{
		cancel: cancel,
	}

	activeScansMu.Lock()
	if _, exists := activeScans[t.Id]; exists {
		activeScansMu.Unlock()
		cancel()
		return
	}
	activeScans[t.Id] = newSCtx
	activeScansMu.Unlock()

	scanMode := cmd.ScanMode
	if scanMode == "" {
		scanMode = "hospital"
	}

	c.logger.WithFields(log.Fields{
		"tunnel_id": t.Id,
		"scan_mode": scanMode,
	}).Info("Starting Native Go Tunnel SNI & Method Benchmark Sweep")

	_ = c.apiClient.ReportScanResults(&panel.ScanResultsRequest{
		TunnelId: t.Id,
		Status:   "running",
		ScanMode: scanMode,
		Progress: 0,
		Results:  []panel.ScanResultItem{},
	})

	go c.runTunnelBenchmarkSweep(ctx, t, newSCtx)
}

func (c *TunnelController) runImmediateBandwidthProbe(t panel.TunnelInfo) {
	if c.relayDriver == nil {
		return
	}
	engine := c.relayDriver.GetEngine(t.Id)
	if engine == nil {
		return
	}

	sample, err := telemetry.RunBandwidthProbe(engine.ClaimReverseStream, engine.Stats, 2*time.Second)
	if err != nil || sample == nil {
		c.logger.WithFields(log.Fields{"tunnel_id": t.Id, "err": err}).Warn("Immediate bandwidth probe failed")
		return
	}

	c.relayDriver.QueueProbeSample(t.Id, sample)
	_ = c.statusReport()
}

func (c *TunnelController) runTunnelBenchmarkSweep(ctx context.Context, t panel.TunnelInfo, sCtx *scanContext) {
	defer func() {
		activeScansMu.Lock()
		delete(activeScans, t.Id)
		activeScansMu.Unlock()
	}()

	cmd := t.ScanCommand
	scanMode := "hospital"
	if cmd != nil && cmd.ScanMode != "" {
		scanMode = cmd.ScanMode
	}

	candidates := BuildBenchmarkCandidates(cmd, t.RelayConfig)
	total := len(candidates)
	if total == 0 {
		c.reportScanError(t.Id, "no benchmark candidates configured")
		return
	}

	sandboxPort := SandboxCarrierPort
	if cmd != nil && cmd.TcpTestPort > 1024 && cmd.TcpTestPort != 49999 {
		sandboxPort = cmd.TcpTestPort
	}

	password := "archnet-default-secret"
	if t.RelayConfig != nil && t.RelayConfig.Password != "" {
		password = t.RelayConfig.Password
	}

	results := make([]panel.ScanResultItem, 0, total)

	for idx, cand := range candidates {
		select {
		case <-ctx.Done():
			c.handleBenchmarkInterruption(t.Id, sCtx.getSignal(), scanMode, results, cand.Index-1)
			return
		default:
		}

		if cmd != nil && cmd.ResumeFrom > 0 && cand.Index <= cmd.ResumeFrom {
			continue
		}

		item := c.evaluateCandidate(ctx, t, cand, sandboxPort, password)
		if item != nil {
			results = append(results, *item)
			sort.SliceStable(results, func(i, j int) bool {
				return results[i].Score > results[j].Score
			})
		}

		progress := int(float64(idx+1) / float64(total) * 100)
		_ = c.apiClient.ReportScanResults(&panel.ScanResultsRequest{
			TunnelId:   t.Id,
			Status:     "running",
			ScanMode:   scanMode,
			Progress:   progress,
			Results:    results,
			LastTested: cand.Index,
			Phase:      scanMode,
		})
	}

	_ = c.apiClient.ReportScanResults(&panel.ScanResultsRequest{
		TunnelId:   t.Id,
		Status:     "completed",
		ScanMode:   scanMode,
		Progress:   100,
		Results:    results,
		LastTested: total,
		Phase:      scanMode,
	})

	c.logger.WithFields(log.Fields{
		"tunnel_id": t.Id,
		"scan_mode": scanMode,
		"results":   len(results),
	}).Info("Native Go Tunnel Benchmark Sweep completed")
}

func (c *TunnelController) evaluateCandidate(
	ctx context.Context,
	t panel.TunnelInfo,
	cand BenchmarkCandidate,
	sandboxPort int,
	password string,
) *panel.ScanResultItem {
	originRTT := measureOriginTCPHandshake(cand.OriginIP, 443, 1200*time.Millisecond)

	sandboxEngine := relay.NewEngine(relay.Config{
		TunnelID:           t.Id*1000 + cand.Index,
		Role:               "entry",
		Transport:          cand.Transport,
		CarrierPort:        sandboxPort,
		ListenIP:           "0.0.0.0",
		SNI:                cand.SNI,
		OriginIP:           cand.OriginIP,
		Password:           password,
		UseHalfDuplex:      cand.UseHalfDuplex,
		UseFisher:          cand.UseFisher,
		FisherConnections:  3,
		MinHeldConnections: 4,
		Logger:             c.logger,
	})

	var sample *telemetry.BandwidthSample
	if err := sandboxEngine.Start(); err == nil {
		waitDeadline := time.Now().Add(1500 * time.Millisecond)
		for time.Now().Before(waitDeadline) {
			select {
			case <-ctx.Done():
				_ = sandboxEngine.Close()
				return nil
			default:
			}
			if sandboxEngine.Stats.PoolIdleConnections.Load() > 0 {
				break
			}
			time.Sleep(50 * time.Millisecond)
		}

		if sandboxEngine.Stats.PoolIdleConnections.Load() > 0 {
			sample, _ = telemetry.RunBandwidthProbe(sandboxEngine.ClaimReverseStream, sandboxEngine.Stats, 1200*time.Millisecond)
		}
		_ = sandboxEngine.Close()
	}

	if sample == nil && c.relayDriver != nil {
		activeEngine := c.relayDriver.GetEngine(t.Id)
		if activeEngine != nil && activeEngine.Stats.PoolIdleConnections.Load() > 0 {
			sample, _ = telemetry.RunBandwidthProbe(activeEngine.ClaimReverseStream, activeEngine.Stats, 1000*time.Millisecond)
		}
	}

	if sample == nil {
		return nil
	}

	latencyMs := sample.RttMs
	if originRTT > 0 && latencyMs > 0 {
		latencyMs = latencyMs + (originRTT / 10)
	} else if latencyMs <= 0 {
		latencyMs = originRTT
	}
	if latencyMs <= 0 {
		latencyMs = 1
	}

	uploadBps := int64(sample.UploadMbps * 1_000_000.0 / 8.0)
	downloadBps := int64(sample.DownloadMbps * 1_000_000.0 / 8.0)
	score := ComputeBenchmarkScore(uploadBps, downloadBps, latencyMs, sample.PacketLoss)

	return &panel.ScanResultItem{
		ProtocolNumber: cand.Index,
		Type:           cand.Transport,
		SNI:            cand.SNI,
		MethodLabel:    cand.MethodLabel,
		UseHalfDuplex:  cand.UseHalfDuplex,
		UseFisher:      cand.UseFisher,
		LatencyMs:      latencyMs,
		UploadSpeed:    uploadBps,
		DownloadSpeed:  downloadBps,
		PacketLoss:     sample.PacketLoss,
		Jitter:         sample.JitterMs,
		Score:          score,
	}
}

func measureOriginTCPHandshake(ip string, port int, timeout time.Duration) int {
	if ip == "" {
		return 0
	}
	start := time.Now()
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, strconv.Itoa(port)), timeout)
	if err != nil {
		return 0
	}
	_ = conn.Close()
	ms := int(time.Since(start).Milliseconds())
	if ms <= 0 {
		ms = 1
	}
	return ms
}

func (c *TunnelController) handleBenchmarkInterruption(tunnelId int, signal, scanMode string, results []panel.ScanResultItem, lastIndex int) {
	status := "cancelled"
	if signal == "pause" {
		status = "paused"
	}

	_ = c.apiClient.ReportScanResults(&panel.ScanResultsRequest{
		TunnelId:   tunnelId,
		Status:     status,
		ScanMode:   scanMode,
		Progress:   0,
		Results:    results,
		LastTested: lastIndex,
		Phase:      scanMode,
	})
}

func (c *TunnelController) reportScanError(tunnelId int, errMsg string) {
	c.logger.WithFields(log.Fields{
		"tunnel_id": tunnelId,
		"error":     errMsg,
	}).Error("Tunnel benchmark sweep failed")

	_ = c.apiClient.ReportScanResults(&panel.ScanResultsRequest{
		TunnelId: tunnelId,
		Status:   "failed",
		Error:    errMsg,
		Progress: 0,
		Results:  []panel.ScanResultItem{},
	})
}

func (c *TunnelController) handleExitScanCommand(t panel.TunnelInfo) {
	cmd := t.ScanCommand
	if cmd == nil || cmd.ProbeNow || cmd.Signal != "" {
		return
	}

	exitSandboxMu.Lock()
	if _, exists := exitSandboxes[t.Id]; exists {
		exitSandboxMu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	state := &exitSandboxState{cancel: cancel}
	exitSandboxes[t.Id] = state
	exitSandboxMu.Unlock()

	go func() {
		defer c.stopEchoServers(t.Id)

		candidates := BuildBenchmarkCandidates(cmd, t.RelayConfig)
		sandboxPort := SandboxCarrierPort
		if cmd.TcpTestPort > 1024 && cmd.TcpTestPort != 49999 {
			sandboxPort = cmd.TcpTestPort
		}
		password := "archnet-default-secret"
		if t.RelayConfig != nil && t.RelayConfig.Password != "" {
			password = t.RelayConfig.Password
		}
		entryIP := t.RemoteIP

		for _, cand := range candidates {
			select {
			case <-ctx.Done():
				return
			default:
			}

			eng := relay.NewEngine(relay.Config{
				TunnelID:           t.Id*1000 + cand.Index,
				Role:               "exit",
				Transport:          cand.Transport,
				CarrierPort:        sandboxPort,
				EntryServerIP:      entryIP,
				TargetIP:           "127.0.0.1",
				SNI:                cand.SNI,
				Password:           password,
				UseHalfDuplex:      cand.UseHalfDuplex,
				UseFisher:          cand.UseFisher,
				FisherConnections:  3,
				MinHeldConnections: 4,
				Logger:             c.logger,
			})
			state.mu.Lock()
			state.engine = eng
			state.mu.Unlock()

			_ = eng.Start()

			select {
			case <-ctx.Done():
				_ = eng.Close()
				return
			case <-time.After(BenchmarkSlotDur):
				_ = eng.Close()
			}
		}
	}()
}

func (c *TunnelController) stopEchoServers(tunnelId int) {
	exitSandboxMu.Lock()
	state, exists := exitSandboxes[tunnelId]
	if !exists {
		exitSandboxMu.Unlock()
		return
	}
	delete(exitSandboxes, tunnelId)
	exitSandboxMu.Unlock()

	if state.cancel != nil {
		state.cancel()
	}
	state.mu.Lock()
	if state.engine != nil {
		_ = state.engine.Close()
		state.engine = nil
	}
	state.mu.Unlock()
}

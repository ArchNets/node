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
	"github.com/archnets/node/core/relay/transport"
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
	cancel  context.CancelFunc
	engines []*relay.Engine
	mu      sync.Mutex
}

// BenchmarkCandidate represents a single SNI or Transport/Method variation to benchmark.
type BenchmarkCandidate struct {
	Index         int
	Direction     string // "reverse" or "direct"
	SNI           string
	OriginIP      string
	Transport     string
	MethodLabel   string
	UseHalfDuplex bool
	UseFisher     bool
}

var (
	reverseBenchmarkTransports = []string{
		"stealth", "tcpmux", "tcp", "ws-reverse", "wsmux",
		"wss-reverse", "wssmux", "quic-reverse", "kcp",
		"pck", "xdi", "tls-reverse", "reverse-reality",
	}
	directBenchmarkTransports = []string{
		"stealth", "tcpmux", "wssmux", "quic-reverse", "kcp",
		"l3-udp", "l3-quic", "l3-pck", "l3-xdi", "l3-sni",
	}
	allRouteBenchmarkTransports = []struct {
		direction string
		transport string
	}{
		{"reverse", "stealth"},
		{"reverse", "tcpmux"},
		{"reverse", "tcp"},
		{"reverse", "ws-reverse"},
		{"reverse", "wsmux"},
		{"reverse", "wss-reverse"},
		{"reverse", "wssmux"},
		{"reverse", "quic-reverse"},
		{"reverse", "kcp"},
		{"reverse", "pck"},
		{"reverse", "xdi"},
		{"reverse", "tls-reverse"},
		{"reverse", "reverse-reality"},
		{"direct", "stealth"},
		{"direct", "quic-reverse"},
		{"direct", "kcp"},
		{"direct", "l3-udp"},
		{"direct", "l3-pck"},
		{"direct", "l3-xdi"},
	}
)

func buildTransportCandidate(idx int, direction, tr, baseSNI string) BenchmarkCandidate {
	spec := transport.GetTransportSpec(tr)
	prefix := "Reverse • "
	if spec.IsL3 {
		prefix = ""
	} else if direction == "direct" {
		prefix = "Direct • "
	}
	sni := ""
	if spec.NeedsSNI {
		sni = baseSNI
	}
	return BenchmarkCandidate{
		Index:         idx,
		Direction:     direction,
		SNI:           sni,
		OriginIP:      "",
		Transport:     tr,
		MethodLabel:   prefix + spec.Label,
		UseHalfDuplex: spec.DefaultHalfDuplex,
		UseFisher:     spec.DefaultFisher,
	}
}

// BuildBenchmarkCandidates constructs the ordered list of benchmark profiles for a ScanCommand.
func BuildBenchmarkCandidates(cmd *panel.ScanCommand, baseCfg *panel.RelayTunnelConfig) []BenchmarkCandidate {
	mode := "methods"
	if cmd != nil && cmd.ScanMode != "" {
		mode = strings.ToLower(strings.TrimSpace(cmd.ScanMode))
	}

	baseSNI := ""
	if baseCfg != nil && baseCfg.SNI != "" {
		baseSNI = baseCfg.SNI
	}
	if baseSNI == "" {
		if presets := telemetry.GetActiveSNIPresets(); len(presets) > 0 {
			baseSNI = presets[0].SNI
		} else {
			baseSNI = "divar.ir"
		}
	}

	var candidates []BenchmarkCandidate
	switch mode {
	case "current", "configured":
		tr := "reverse-reality"
		direction := "reverse"
		hd := true
		fisher := true
		sni := baseSNI
		if baseCfg != nil {
			if baseCfg.Transport != "" {
				tr = baseCfg.Transport
			}
			if baseCfg.Direction != "" {
				direction = baseCfg.Direction
			}
			hd = baseCfg.UseHalfDuplex
			fisher = baseCfg.UseFisher
			if baseCfg.SNI != "" {
				sni = baseCfg.SNI
			}
		}
		spec := transport.GetTransportSpec(tr)
		if !spec.NeedsSNI {
			sni = ""
		}
		prefix := "Reverse • "
		if spec.IsL3 {
			prefix = ""
		} else if direction == "direct" {
			prefix = "Direct • "
		}
		candidates = append(candidates, BenchmarkCandidate{
			Index:         1,
			Direction:     direction,
			SNI:           sni,
			OriginIP:      "",
			Transport:     tr,
			MethodLabel:   prefix + spec.Label + " (Active Config)",
			UseHalfDuplex: hd,
			UseFisher:     fisher,
		})

	case "methods", "all":
		for i, v := range allRouteBenchmarkTransports {
			candidates = append(candidates, buildTransportCandidate(i+1, v.direction, v.transport, baseSNI))
		}

	case "reverse":
		for i, tr := range reverseBenchmarkTransports {
			candidates = append(candidates, buildTransportCandidate(i+1, "reverse", tr, baseSNI))
		}

	case "direct":
		for i, tr := range directBenchmarkTransports {
			candidates = append(candidates, buildTransportCandidate(i+1, "direct", tr, baseSNI))
		}

	case "matrix":
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
		if len(snis) > 4 {
			snis = snis[:4]
		}

		idx := 1
		// 1. Stealth (SNI-independent)
		candidates = append(candidates, BenchmarkCandidate{
			Index:         idx,
			SNI:           "",
			OriginIP:      "",
			Transport:     "stealth",
			MethodLabel:   "Stealth (Noise NNpsk0 + Random Padding)",
			UseHalfDuplex: true,
			UseFisher:     false,
		})
		idx++

		// 2. Test QUIC, WSS, WS, and Reverse Reality across the top domains
		for _, preset := range snis {
			for _, m := range []struct {
				transport string
				label     string
				hd        bool
				fisher    bool
			}{
				{"quic-reverse", "QUIC Reverse (UDP)", false, false},
				{"wss-reverse", "WSS Reverse (TLS 1.3 + Decoy)", true, false},
				{"ws-reverse", "WebSocket Reverse (Decoy)", true, false},
				{"reverse-reality", "Reverse Reality (Anti-DPI TLS 1.3)", true, true},
			} {
				candidates = append(candidates, BenchmarkCandidate{
					Index:         idx,
					SNI:           preset.SNI,
					OriginIP:      preset.OriginIP,
					Transport:     m.transport,
					MethodLabel:   m.label,
					UseHalfDuplex: m.hd,
					UseFisher:     m.fisher,
				})
				idx++
			}
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
	exitCheckedIn := false

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

		// Wait up to 35s on the first candidate so Exit has time to poll /v2/server/:id/tunnel (30s interval)
		// and launch its parallel sandbox engines. Once Exit checks in once, subsequent candidates need only 4s.
		waitTimeout := 4 * time.Second
		if !exitCheckedIn {
			waitTimeout = 35 * time.Second
		} else {
			spec := transport.GetTransportSpec(cand.Transport)
			if spec.IsPacket || spec.IsQuic || spec.NeedsTLSServerCfg {
				waitTimeout = 12 * time.Second
			}
		}

		item := c.evaluateCandidate(ctx, t, cand, sandboxPort, password, waitTimeout)
		if item != nil {
			exitCheckedIn = true
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

	if len(results) == 0 {
		c.reportScanError(t.Id, "Benchmark sweep produced 0 valid results (Exit server disconnected during test)")
		return
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
	waitTimeout time.Duration,
) *panel.ScanResultItem {
	c.logger.WithFields(log.Fields{
		"tunnel_id": t.Id,
		"idx":       cand.Index,
		"method":    cand.MethodLabel,
		"transport": cand.Transport,
		"direction": cand.Direction,
		"sni":       cand.SNI,
		"port":      sandboxPort + cand.Index,
	}).Info("[Benchmark] >>> Starting candidate benchmark")

	spec := transport.GetTransportSpec(cand.Transport)

	originRTT := measureOriginTCPHandshake(cand.OriginIP, 443, 1200*time.Millisecond)

	direction := cand.Direction
	if direction == "" {
		direction = "reverse"
		if t.RelayConfig != nil && t.RelayConfig.Direction != "" {
			direction = t.RelayConfig.Direction
		}
	}
	exitIP := t.ExitServerIP
	if exitIP == "" {
		exitIP = t.RemoteIP
	}
	if t.RelayConfig != nil && t.RelayConfig.ExitOverrideIP != "" {
		exitIP = t.RelayConfig.ExitOverrideIP
	}

	candPort := sandboxPort + cand.Index
	certMode := ""
	if spec.NeedsTLSServerCfg {
		certMode = "self"
	}

	sandboxEngine := relay.NewEngine(relay.Config{
		TunnelID:           t.Id*1000 + cand.Index,
		Role:               "entry",
		Direction:          direction,
		Transport:          cand.Transport,
		CarrierPort:        candPort,
		ListenIP:           "0.0.0.0",
		ExitServerIP:       exitIP,
		SNI:                cand.SNI,
		OriginIP:           cand.OriginIP,
		Password:           password,
		UseHalfDuplex:      cand.UseHalfDuplex,
		UseFisher:          false,
		FisherConnections:  1,
		MinHeldConnections: 1,
		CertMode:           certMode,
		Logger:             c.logger,
	})

	var sample *telemetry.BandwidthSample
	if err := sandboxEngine.Start(); err == nil {
		waitDeadline := time.Now().Add(waitTimeout)
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
		} else {
			c.logger.WithFields(log.Fields{
				"tunnel_id": t.Id,
				"idx":       cand.Index,
				"transport": cand.Transport,
				"timeout":   waitTimeout,
			}).Warn("[Benchmark] Candidate failed to establish warm reverse connection (exit did not check in)")
		}
		_ = sandboxEngine.Close()
		time.Sleep(150 * time.Millisecond) // Allow port release between sequential candidates
	} else {
		c.logger.WithFields(log.Fields{
			"tunnel_id": t.Id,
			"idx":       cand.Index,
			"transport": cand.Transport,
			"err":       err,
		}).Warn("[Benchmark] Candidate sandbox engine failed to start")
	}

	if sample == nil && c.relayDriver != nil {
		activeEngine := c.relayDriver.GetEngine(t.Id)
		if activeEngine != nil && activeEngine.Stats.PoolIdleConnections.Load() > 0 {
			sample, _ = telemetry.RunBandwidthProbe(activeEngine.ClaimReverseStream, activeEngine.Stats, 1000*time.Millisecond)
		}
	}

	if sample == nil {
		c.logger.WithFields(log.Fields{
			"tunnel_id": t.Id,
			"idx":       cand.Index,
			"transport": cand.Transport,
		}).Warn("[Benchmark] <<< Candidate benchmark failed (carrier blocked or dropped)")
		return &panel.ScanResultItem{
			ProtocolNumber: cand.Index,
			Type:           cand.Transport,
			SNI:            cand.SNI,
			MethodLabel:    cand.MethodLabel,
			UseHalfDuplex:  cand.UseHalfDuplex,
			UseFisher:      cand.UseFisher,
			LatencyMs:      0,
			UploadSpeed:    0,
			DownloadSpeed:  0,
			PacketLoss:     100,
			Status:         "blocked",
			Detail:         "Blocked (Carrier connection dropped or timed out)",
			Score:          0,
		}
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

	c.logger.WithFields(log.Fields{
		"tunnel_id": t.Id,
		"idx":       cand.Index,
		"method":    cand.MethodLabel,
		"downMbps":  sample.DownloadMbps,
		"upMbps":    sample.UploadMbps,
		"rttMs":     latencyMs,
		"score":     score,
	}).Info("[Benchmark] <<< Candidate benchmark SUCCESS")

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
		Status:         "ok",
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
		direction := "reverse"
		entryIP := t.RemoteIP
		if t.RelayConfig != nil {
		 if t.RelayConfig.Password != "" {
		  password = t.RelayConfig.Password
		 }
		 if t.RelayConfig.Direction != "" {
		  direction = t.RelayConfig.Direction
		 }
		 if t.RelayConfig.EntryOverrideIP != "" {
		  entryIP = t.RelayConfig.EntryOverrideIP
		 }
		}

		exitBindIP := "0.0.0.0"
		if t.LocalIP != "" {
		 exitBindIP = t.LocalIP
		}

		// Start all candidate sandbox engines concurrently on their dedicated port (sandboxPort + cand.Index)
		// so Entry and Exit never suffer from 30-second config poll clock skew.
		c.logger.WithFields(log.Fields{
			"tunnel_id":  t.Id,
			"candidates": len(candidates),
			"basePort":   sandboxPort,
			"entryIP":    entryIP,
		}).Info("[Benchmark] Exit node starting parallel candidate sandbox engines")

		for _, cand := range candidates {
			select {
			case <-ctx.Done():
				return
			default:
			}

			candDirection := cand.Direction
			if candDirection == "" {
				candDirection = direction
			}
			candPort := sandboxPort + cand.Index

			// For Direct mode, Exit is the Listener, so ListenIP is exitBindIP
			// For Reverse mode, Exit dials Entry, so EntryServerIP is entryIP
			exitCertMode := ""
			if transport.GetTransportSpec(cand.Transport).NeedsTLSServerCfg {
				exitCertMode = "self"
			}

			eng := relay.NewEngine(relay.Config{
				TunnelID:           t.Id*1000 + cand.Index,
				Role:               "exit",
				Direction:          candDirection,
				Transport:          cand.Transport,
				CarrierPort:        candPort,
				ListenIP:           exitBindIP,
				EntryServerIP:      entryIP,
				TargetIP:           "127.0.0.1",
				SNI:                cand.SNI,
				Password:           password,
				UseHalfDuplex:      cand.UseHalfDuplex,
				UseFisher:          false,
				FisherConnections:  1,
				MinHeldConnections: 1,
				CertMode:           exitCertMode,
				Logger:             c.logger,
			})
			if err := eng.Start(); err == nil {
				state.mu.Lock()
				state.engines = append(state.engines, eng)
				state.mu.Unlock()
			}
		}

		select {
		case <-ctx.Done():
		case <-time.After(300 * time.Second):
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
	for _, eng := range state.engines {
		if eng != nil {
			_ = eng.Close()
		}
	}
	state.engines = nil
	state.mu.Unlock()
}

package node

import (
	"encoding/json"
	"sync"

	"github.com/archnets/node/api/panel"
	"github.com/archnets/node/core/relay"
	"github.com/archnets/node/core/relay/routing"
	"github.com/archnets/node/core/relay/telemetry"
	log "github.com/sirupsen/logrus"
)

// RelayDriver manages Native Go Relay Engine tunnels (reverse-reality, tls-reverse).
type RelayDriver struct {
	mu             sync.Mutex
	engines        map[int]*relay.Engine
	lastErrors     map[int]string
	pendingSamples map[int]*panel.BandwidthSamplePayload
	samplesMu      sync.Mutex
	logger         *log.Entry
}

func NewRelayDriver(logger *log.Entry) *RelayDriver {
	return &RelayDriver{
		engines:        make(map[int]*relay.Engine),
		lastErrors:     make(map[int]string),
		pendingSamples: make(map[int]*panel.BandwidthSamplePayload),
		logger:         logger,
	}
}

func (d *RelayDriver) QueueProbeSample(tunnelID int, sample *telemetry.BandwidthSample) {
	if sample == nil {
		return
	}
	d.samplesMu.Lock()
	defer d.samplesMu.Unlock()
	d.pendingSamples[tunnelID] = &panel.BandwidthSamplePayload{
		Timestamp:      sample.Timestamp,
		UploadMbps:     sample.UploadMbps,
		DownloadMbps:   sample.DownloadMbps,
		RttMs:          sample.RttMs,
		JitterMs:       sample.JitterMs,
		PacketLoss:     sample.PacketLoss,
		Status:         sample.Status,
		RecommendedMTU: sample.RecommendedMTU,
	}
}

func (d *RelayDriver) Start(t panel.TunnelInfo) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	// Stop existing instance if running
	if old, ok := d.engines[t.Id]; ok && old != nil {
		_ = old.Close()
		delete(d.engines, t.Id)
	}

	var forwarderRules []routing.ForwarderRule
	for _, f := range t.Forwarders {
		forwarderRules = append(forwarderRules, routing.ForwarderRule{
			ID:         f.Id,
			Protocol:   f.Protocol,
			ListenIP:   f.ListenIP,
			ListenPort: f.ListenPort,
			TargetIP:   f.TargetIP,
			TargetPort: f.TargetPort,
			PortRange:  f.PortRange,
		})
	}

	carrierPort := 443
	transport := "reverse-reality"
	sni := ""
	originIP := ""
	password := "archnet-default-secret"
	useHalfDuplex := true
	useFisher := true
	fisherConns := 3
	minHeld := 8
	var floatingIPs []string
	enableProbe := true
	probeInterval := 30
	certMode := ""
	certFile := ""
	keyFile := ""
	certDNSProvider := ""
	certDNSEnv := ""

	rc := t.RelayConfig
	if rc == nil && t.Config != "" {
		var parsed panel.RelayTunnelConfig
		if json.Unmarshal([]byte(t.Config), &parsed) == nil && (parsed.Transport != "" || parsed.SNI != "") {
			rc = &parsed
		}
	}

	if rc != nil {
		if rc.CarrierPort > 0 {
			carrierPort = rc.CarrierPort
		}
		if rc.Transport != "" {
			transport = rc.Transport
		}
		if rc.SNI != "" {
			sni = rc.SNI
		}
		if rc.OriginIP != "" {
			originIP = rc.OriginIP
		}
		if rc.Password != "" {
			password = rc.Password
		}
		useHalfDuplex = rc.UseHalfDuplex
		useFisher = rc.UseFisher
		if rc.FisherConnections > 0 {
			fisherConns = rc.FisherConnections
		}
		if rc.MinHeldConnections > 0 {
			minHeld = rc.MinHeldConnections
		}
		floatingIPs = rc.FloatingIPs
		enableProbe = rc.EnableProbe
		if rc.ProbeIntervalMin > 0 {
			probeInterval = rc.ProbeIntervalMin
		}
		certMode = rc.CertMode
		certFile = rc.CertFile
		keyFile = rc.KeyFile
		certDNSProvider = rc.CertDNSProvider
		certDNSEnv = rc.CertDNSEnv
	} else if t.Method == "tls-reverse" {
		transport = "tls-reverse"
	}

	// Reuse the node's unified certificate manager (EnsureNodeCertificate in node/cert.go)
	if t.Role == "entry" && transport == "tls-reverse" && sni != "" {
		nodeInfo := &panel.NodeInfo{
			Id:   t.Id,
			Type: "relay",
			Protocol: &panel.Protocol{
				SNI:             sni,
				CertMode:        certMode,
				CertFile:        certFile,
				KeyFile:         keyFile,
				CertDNSProvider: certDNSProvider,
				CertDNSEnv:      certDNSEnv,
			},
		}
		if resolvedCert, resolvedKey, err := EnsureNodeCertificate(nodeInfo, "relay"); err != nil {
			d.logger.WithFields(log.Fields{"sni": sni, "certMode": certMode, "err": err}).Warn("[Relay] Certificate provisioning warning")
		} else if resolvedCert != "" && resolvedKey != "" {
			certFile = resolvedCert
			keyFile = resolvedKey
		}
	}

	if originIP == "" && sni != "" {
		if resolved, err := telemetry.ResolveOriginIP(sni, ""); err == nil {
			originIP = resolved
		}
	}

	entryIP := t.RemoteIP
	if t.Role == "entry" {
		entryIP = t.LocalIP
	} else if entryIP == "" {
		entryIP = t.ExitServerIP
	}

	cfg := relay.Config{
		TunnelID:           t.Id,
		Role:               t.Role,
		Transport:          transport,
		CarrierPort:        carrierPort,
		ListenIP:           "0.0.0.0",
		EntryServerIP:      entryIP,
		ExitServerIP:       t.ExitServerIP,
		TargetIP:           "127.0.0.1",
		SNI:                sni,
		OriginIP:           originIP,
		Password:           password,
		UseHalfDuplex:      useHalfDuplex,
		UseFisher:          useFisher,
		FisherConnections:  fisherConns,
		MinHeldConnections: minHeld,
		FloatingIPs:        floatingIPs,
		EnableProbe:        enableProbe,
		ProbeIntervalMin:   probeInterval,
		CertMode:           certMode,
		CertFile:           certFile,
		KeyFile:            keyFile,
		Forwarders:         forwarderRules,
		Logger:             d.logger,
		OnProbeSample:      d.QueueProbeSample,
	}

	eng := relay.NewEngine(cfg)
	if err := eng.Start(); err != nil {
		d.lastErrors[t.Id] = err.Error()
		return err
	}

	delete(d.lastErrors, t.Id)
	d.engines[t.Id] = eng
	d.logger.WithFields(log.Fields{
		"tunnelId":  t.Id,
		"role":      t.Role,
		"transport": transport,
		"sni":       sni,
		"origin":    originIP,
		"carrier":   carrierPort,
	}).Info("[Relay] Native Go Relay Engine started")
	return nil
}

func (d *RelayDriver) Stop(tunnelId int) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if eng, ok := d.engines[tunnelId]; ok && eng != nil {
		_ = eng.Close()
		delete(d.engines, tunnelId)
		d.logger.WithField("tunnelId", tunnelId).Info("[Relay] Native Go Relay Engine stopped")
	}
	return nil
}

func (d *RelayDriver) StopAll() {
	d.mu.Lock()
	defer d.mu.Unlock()
	for id, eng := range d.engines {
		if eng != nil {
			_ = eng.Close()
			d.logger.WithField("tunnelId", id).Info("RelayDriver: stopped engine instance")
		}
	}
	d.engines = make(map[int]*relay.Engine)
}

func (d *RelayDriver) CollectStats(t panel.TunnelInfo, pingLatency int, pingOnline bool) (panel.TunnelStatus, bool) {
	d.mu.Lock()
	eng := d.engines[t.Id]
	lastErr := d.lastErrors[t.Id]
	d.mu.Unlock()

	if eng == nil {
		probeStatus := "THROTTLED"
		if lastErr != "" {
			probeStatus = "ERROR: " + lastErr
		}
		return panel.TunnelStatus{
			TunnelId:    t.Id,
			Online:      false,
			ProbeStatus: probeStatus,
		}, true
	}

	online := eng.IsAlive()
	if t.Role == "exit" {
		online = eng.IsAlive() && (eng.Stats.PoolIdleConnections.Load() > 0 || eng.Stats.ActiveConnections.Load() > 0)
	}
	deltaUpload, deltaDownload := eng.Stats.SnapshotDelta()
	curUpBps := eng.Stats.CurrentUploadBps.Load()
	curDownBps := eng.Stats.CurrentDownloadBps.Load()
	latency := int(eng.Stats.LatencyMs.Load())
	if latency <= 0 {
		latency = pingLatency
	}
	lastProbeUp, lastProbeDown, probeStatus := eng.Stats.GetLastProbeResult()

	var samplePayload *panel.BandwidthSamplePayload
	d.samplesMu.Lock()
	if s, exists := d.pendingSamples[t.Id]; exists {
		samplePayload = s
		delete(d.pendingSamples, t.Id)
	}
	d.samplesMu.Unlock()

	if deltaUpload > 0 || deltaDownload > 0 {
		online = true
	}

	return panel.TunnelStatus{
		TunnelId:              t.Id,
		Online:                online,
		LatencyMs:             latency,
		TotalUpload:           deltaUpload,
		TotalDownload:         deltaDownload,
		CurrentUploadBps:      curUpBps,
		CurrentDownloadBps:    curDownBps,
		LastProbeUploadMbps:   lastProbeUp,
		LastProbeDownloadMbps: lastProbeDown,
		ProbeStatus:           probeStatus,
		ProbeSample:           samplePayload,
	}, true
}

func (d *RelayDriver) GetEngine(tunnelId int) *relay.Engine {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.engines[tunnelId]
}

package node

import (
	"encoding/json"
	"strings"
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
	unsentUpload   map[int]int64
	unsentDownload map[int]int64
	pendingSamples map[int]*panel.BandwidthSamplePayload
	samplesMu      sync.Mutex
	logger         *log.Entry
}

func NewRelayDriver(logger *log.Entry) *RelayDriver {
	return &RelayDriver{
		engines:        make(map[int]*relay.Engine),
		lastErrors:     make(map[int]string),
		unsentUpload:   make(map[int]int64),
		unsentDownload: make(map[int]int64),
		pendingSamples: make(map[int]*panel.BandwidthSamplePayload),
		logger:         logger,
	}
}

func (d *RelayDriver) harvestUnsentLocked(tunnelId int, eng *relay.Engine) {
	if eng == nil || eng.Stats == nil {
		return
	}
	up, down := eng.Stats.SnapshotDelta()
	if up > 0 {
		d.unsentUpload[tunnelId] += up
	}
	if down > 0 {
		d.unsentDownload[tunnelId] += down
	}
}

// RefundStats restores unsent traffic deltas and probe samples if a panel API status push fails.
func (d *RelayDriver) RefundStats(statuses []panel.TunnelStatus) {
	d.mu.Lock()
	for _, st := range statuses {
		if st.TotalUpload > 0 {
			d.unsentUpload[st.TunnelId] += st.TotalUpload
		}
		if st.TotalDownload > 0 {
			d.unsentDownload[st.TunnelId] += st.TotalDownload
		}
	}
	d.mu.Unlock()

	d.samplesMu.Lock()
	for _, st := range statuses {
		if st.ProbeSample != nil {
			if _, exists := d.pendingSamples[st.TunnelId]; !exists {
				d.pendingSamples[st.TunnelId] = st.ProbeSample
			}
		}
	}
	d.samplesMu.Unlock()
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

	var forwarderRules []routing.ForwarderRule
	for _, f := range t.Forwarders {
		gaming := false
		if f.Config != "" {
			var fwdCfg struct {
				Gaming bool `json:"gaming"`
			}
			if json.Unmarshal([]byte(f.Config), &fwdCfg) == nil {
				gaming = fwdCfg.Gaming
			}
		}
		forwarderRules = append(forwarderRules, routing.ForwarderRule{
			ID:         f.Id,
			Protocol:   f.Protocol,
			ListenIP:   f.ListenIP,
			ListenPort: f.ListenPort,
			TargetIP:   f.TargetIP,
			TargetPort: f.TargetPort,
			PortRange:  f.PortRange,
			GamingMode: gaming,
		})
	}

	direction := "reverse"
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
		if rc.Direction != "" {
			direction = rc.Direction
		}
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
	} else if t.Method != "" && t.Method != "waterwall" {
		transport = t.Method
	}

	// Reuse the node's unified certificate manager (EnsureNodeCertificate in node/cert.go)
	isListener := (direction == "direct" && t.Role == "exit") || (direction != "direct" && t.Role == "entry")
	needsCert := (transport == "tls-reverse" || transport == "wss-reverse" || transport == "quic-reverse") && sni != ""
	if isListener && needsCert {
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
	exitIP := t.ExitServerIP
	if rc != nil {
		if rc.ExitOverrideIP != "" {
			exitIP = rc.ExitOverrideIP
		}
		if rc.EntryOverrideIP != "" {
			entryIP = rc.EntryOverrideIP
		}
	}

	preset := "turbo"
	var tcpNoDelay *bool
	var pckFlags []string
	var edgeIP, wsPath string
	var simpleAuth bool
	var kcpDataShards, kcpParityShards, kcpMTU int
	var l3LocalIP, l3PeerIP, l3Iface string
	var l3MTU int
	var spoofSrcIP, spoofProfile string
	var spoofSrcPool []string
	var spoofPeerSrcIP string
	var spoofUplink, spoofDownlink string
	var spoofFakeTLS, spoofTTLJitter, spoofRandomDSCP bool
	var spoofPortMin, spoofPortMax, spoofPaddingMax int
	var spoofPadding, spoofShufflePort bool
	var spoofInterface string

	if rc != nil {
		if rc.Preset != "" {
			preset = rc.Preset
		}
		tcpNoDelay = rc.TCPNoDelay
		pckFlags = rc.PCKFlags
		edgeIP = rc.EdgeIP
		wsPath = rc.WSPath
		simpleAuth = rc.SimpleAuth
		kcpDataShards = rc.KCPDataShards
		kcpParityShards = rc.KCPParityShards
		kcpMTU = rc.KCPMTU
		l3LocalIP = rc.L3LocalIP
		l3PeerIP = rc.L3PeerIP
		l3Iface = rc.L3Iface
		l3MTU = rc.L3MTU
		spoofSrcIP = rc.SpoofSrcIP
		spoofSrcPool = rc.SpoofSrcPool
		spoofPeerSrcIP = rc.SpoofPeerSrcIP
		spoofProfile = rc.SpoofProfile
		spoofUplink = rc.SpoofUplink
		spoofDownlink = rc.SpoofDownlink
		spoofFakeTLS = rc.SpoofFakeTLS
		spoofTTLJitter = rc.SpoofTTLJitter
		spoofRandomDSCP = rc.SpoofRandomDSCP
		spoofPortMin = rc.SpoofPortMin
		spoofPortMax = rc.SpoofPortMax
		spoofPadding = rc.SpoofPadding
		spoofPaddingMax = rc.SpoofPaddingMax
		spoofShufflePort = rc.SpoofShufflePort
		spoofInterface = rc.SpoofInterface
	}

	cfg := relay.Config{
		TunnelID:           t.Id,
		Role:               t.Role,
		Direction:          direction,
		Preset:             preset,
		Transport:          transport,
		CarrierPort:        carrierPort,
		ListenIP:           "0.0.0.0",
		EntryServerIP:      entryIP,
		ExitServerIP:       exitIP,
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
		TCPNoDelay:         tcpNoDelay,
		PCKFlags:           pckFlags,
		EdgeIP:             edgeIP,
		WSPath:             wsPath,
		SimpleAuth:         simpleAuth,
		KCPDataShards:      kcpDataShards,
		KCPParityShards:    kcpParityShards,
		KCPMTU:             kcpMTU,
		L3LocalIP:          l3LocalIP,
		L3PeerIP:           l3PeerIP,
		L3Iface:            l3Iface,
		L3MTU:              l3MTU,
		SpoofSrcIP:         spoofSrcIP,
		SpoofSrcPool:       spoofSrcPool,
		SpoofPeerSrcIP:     spoofPeerSrcIP,
		SpoofProfile:       spoofProfile,
		SpoofUplink:        spoofUplink,
		SpoofDownlink:      spoofDownlink,
		SpoofFakeTLS:       spoofFakeTLS,
		SpoofTTLJitter:     spoofTTLJitter,
		SpoofRandomDSCP:    spoofRandomDSCP,
		SpoofPortMin:       spoofPortMin,
		SpoofPortMax:       spoofPortMax,
		SpoofPadding:       spoofPadding,
		SpoofPaddingMax:    spoofPaddingMax,
		SpoofShufflePort:   spoofShufflePort,
		SpoofInterface:     spoofInterface,
		Forwarders:         forwarderRules,
		Logger:             d.logger,
		OnProbeSample:      d.QueueProbeSample,
	}

	// If existing engine is running and carrier settings are identical, update forwarders in-place without restarting
	if old, ok := d.engines[t.Id]; ok && old != nil && old.IsAlive() && carrierSettingsEqual(old.Config(), cfg) {
		d.logger.WithFields(log.Fields{
			"tunnelId": t.Id,
			"role":     t.Role,
		}).Info("[Relay] Carrier configuration unchanged; updating forwarders in-place with zero downtime")
		if err := old.UpdateForwarders(forwarderRules); err != nil {
			d.logger.WithField("err", err).Warn("[Relay] In-place forwarder update failed, falling back to full restart")
		} else {
			return nil
		}
	}

	// Stop existing instance if running, harvesting any unsent traffic delta first
	if old, ok := d.engines[t.Id]; ok && old != nil {
		d.harvestUnsentLocked(t.Id, old)
		_ = old.Close()
		delete(d.engines, t.Id)
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

func hasGamingForwarder(rules []routing.ForwarderRule) bool {
	for _, r := range rules {
		if r.GamingMode {
			return true
		}
	}
	return false
}

func carrierSettingsEqual(a, b relay.Config) bool {
	return a.Transport == b.Transport &&
		hasGamingForwarder(a.Forwarders) == hasGamingForwarder(b.Forwarders) &&
		a.CarrierPort == b.CarrierPort &&
		a.Password == b.Password &&
		a.SNI == b.SNI &&
		a.OriginIP == b.OriginIP &&
		a.Direction == b.Direction &&
		a.Role == b.Role &&
		a.EntryServerIP == b.EntryServerIP &&
		a.ExitServerIP == b.ExitServerIP &&
		a.UseHalfDuplex == b.UseHalfDuplex &&
		a.UseFisher == b.UseFisher &&
		a.FisherConnections == b.FisherConnections &&
		a.MinHeldConnections == b.MinHeldConnections &&
		a.CertMode == b.CertMode &&
		a.CertFile == b.CertFile &&
		a.KeyFile == b.KeyFile &&
		a.EdgeIP == b.EdgeIP &&
		a.WSPath == b.WSPath &&
		a.SimpleAuth == b.SimpleAuth &&
		a.KCPDataShards == b.KCPDataShards &&
		a.KCPParityShards == b.KCPParityShards &&
		a.KCPMTU == b.KCPMTU &&
		a.L3LocalIP == b.L3LocalIP &&
		a.L3PeerIP == b.L3PeerIP &&
		a.L3Iface == b.L3Iface &&
		a.L3MTU == b.L3MTU &&
		a.SpoofSrcIP == b.SpoofSrcIP &&
		a.SpoofPeerSrcIP == b.SpoofPeerSrcIP &&
		a.SpoofProfile == b.SpoofProfile &&
		a.SpoofUplink == b.SpoofUplink &&
		a.SpoofDownlink == b.SpoofDownlink &&
		a.SpoofFakeTLS == b.SpoofFakeTLS &&
		a.SpoofTTLJitter == b.SpoofTTLJitter &&
		a.SpoofRandomDSCP == b.SpoofRandomDSCP &&
		a.SpoofPortMin == b.SpoofPortMin &&
		a.SpoofPortMax == b.SpoofPortMax &&
		a.SpoofPadding == b.SpoofPadding &&
		a.SpoofPaddingMax == b.SpoofPaddingMax &&
		a.SpoofShufflePort == b.SpoofShufflePort &&
		a.SpoofInterface == b.SpoofInterface
}

func (d *RelayDriver) Stop(tunnelId int) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if eng, ok := d.engines[tunnelId]; ok && eng != nil {
		d.harvestUnsentLocked(tunnelId, eng)
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
			d.harvestUnsentLocked(id, eng)
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
	carriedUp := d.unsentUpload[t.Id]
	carriedDown := d.unsentDownload[t.Id]
	delete(d.unsentUpload, t.Id)
	delete(d.unsentDownload, t.Id)
	d.mu.Unlock()

	if eng == nil {
		probeStatus := "THROTTLED"
		if lastErr != "" {
			probeStatus = "ERROR: " + lastErr
		}
		return panel.TunnelStatus{
			TunnelId:      t.Id,
			Online:        false,
			TotalUpload:   carriedUp,
			TotalDownload: carriedDown,
			ProbeStatus:   probeStatus,
		}, true
	}

	deltaUpload, deltaDownload := eng.Stats.SnapshotDelta()
	deltaUpload += carriedUp
	deltaDownload += carriedDown

	isDirect := t.RelayConfig != nil && strings.ToLower(t.RelayConfig.Direction) == "direct"
	isDialer := (t.Role == "exit" && !isDirect) || (t.Role == "entry" && isDirect)
	hasPeerActivity := eng.Stats.PoolIdleConnections.Load() > 0 || eng.Stats.ActiveConnections.Load() > 0 || deltaUpload > 0 || deltaDownload > 0
	online := eng.IsAlive()
	if hasPeerActivity {
		online = true
	} else if isDialer {
		online = false
	}
	curUpBps := eng.Stats.CurrentUploadBps.Load()
	curDownBps := eng.Stats.CurrentDownloadBps.Load()
	latency := int(eng.Stats.LatencyMs.Load())
	if !hasPeerActivity {
		latency = 0
		curUpBps = 0
		curDownBps = 0
	} else if latency <= 0 {
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

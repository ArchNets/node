package relay

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/archnets/node/core/relay/routing"
	"github.com/archnets/node/core/relay/telemetry"
	"github.com/archnets/node/core/relay/transport"
	quic "github.com/apernet/quic-go"
	log "github.com/sirupsen/logrus"
)

// Config configures a Native Go Relay Engine instance for either Entry (Iran) or Exit (Kharej).
type Config struct {
	TunnelID           int
	Role               string // "entry" or "exit"
	Direction          string // "reverse" (default) or "direct"
	Transport          string // "reverse-reality", "tls-reverse", "stealth", "ws-reverse", "wss-reverse", "quic-reverse"
	CarrierPort        int    // Default: 443
	ListenIP           string // Default: "0.0.0.0"
	EntryServerIP      string // Entry public IP (dialed by Exit)
	ExitServerIP       string // Optional Exit public IP (whitelist on Entry)
	TargetIP           string // Default: "127.0.0.1" on Exit
	SNI                string // Camouflage SNI domain
	OriginIP           string // Resolved camouflage origin IP
	Password           string // Shared authentication secret
	UseHalfDuplex      bool   // Default: true
	UseFisher          bool   // Default: true
	FisherConnections  int    // Default: 3
	MinHeldConnections int    // Default: 8
	FloatingIPs        []string
	EnableProbe        bool
	ProbeIntervalMin   int
	CertMode           string
	CertFile           string
	KeyFile            string
	Forwarders         []routing.ForwarderRule
	Logger             *log.Entry
	OnProbeSample      func(tunnelID int, sample *telemetry.BandwidthSample)
}

type pooledStream struct {
	conn      net.Conn
	createdAt time.Time
}

// Engine is the L4 reverse tunnel & zero-copy relay engine in pure Go.
type Engine struct {
	cfg           Config
	Stats         *telemetry.Stats
	ctx           context.Context
	cancel        context.CancelFunc
	wg            sync.WaitGroup
	mu            sync.Mutex
	carrierLn      net.Listener
	quicLn         *quic.Listener
	quicUDPConn    *net.UDPConn
	udpCarrierLn   *transport.UDPCarrierListener
	activeQuicConn *quic.Conn
	activeMuxSess  *transport.MuxSession
	l3TunDev       *transport.L3TUNDevice
	tcpListeners   []net.Listener
	udpListeners  []*net.UDPConn
	hdMatcher     *transport.HalfDuplexMatcher
	tlsServerCfg  *tls.Config
	idlePool      chan pooledStream
	replenishCh   chan struct{}
	idleWaiters   atomic.Int64
	activeStreams sync.Map
	alive         atomic.Bool
	lastDialLog   atomic.Int64
	carrierFwd    atomic.Int64
	logger        *log.Entry
}

// NewEngine initializes a new Relay Engine instance.
func NewEngine(cfg Config) *Engine {
	if cfg.Transport == "" {
		cfg.Transport = "reverse-reality"
	}
	if cfg.Direction == "" {
		cfg.Direction = "reverse"
	}
	if cfg.Password == "" {
		cfg.Password = "archnet-default-secret"
	}
	if cfg.FisherConnections <= 0 {
		cfg.FisherConnections = transport.DefaultFisherCount
	}
	if cfg.MinHeldConnections <= 0 {
		cfg.MinHeldConnections = 8
	}
	if cfg.ProbeIntervalMin <= 0 {
		cfg.ProbeIntervalMin = 30
	}
	if cfg.CarrierPort <= 0 {
		cfg.CarrierPort = 443
	}
	if cfg.Logger == nil {
		cfg.Logger = log.WithField("tunnel_id", cfg.TunnelID)
	}

	ctx, cancel := context.WithCancel(context.Background())
	poolCap := cfg.MinHeldConnections * 4
	if poolCap < 32 {
		poolCap = 32
	}

	return &Engine{
		cfg:         cfg,
		Stats:       telemetry.NewStats(),
		ctx:         ctx,
		cancel:      cancel,
		idlePool:    make(chan pooledStream, poolCap),
		replenishCh: make(chan struct{}, 1),
		logger:      cfg.Logger,
	}
}

// Start launches the relay engine according to its role ("entry" or "exit").
func (e *Engine) Start() error {
	if e.cfg.Role == "entry" {
		if err := e.startEntry(); err != nil {
			e.cancel()
			return err
		}
	} else if e.cfg.Role == "exit" {
		if err := e.startExit(); err != nil {
			e.cancel()
			return err
		}
	} else {
		e.cancel()
		return fmt.Errorf("unknown relay engine role: %q", e.cfg.Role)
	}

	e.alive.Store(true)

	if strings.HasPrefix(e.cfg.Transport, "l3-") {
		if tunDev, err := transport.OpenL3TUN(e.cfg.TunnelID, e.cfg.Role, e.cfg.Password, transport.GetConfiguredMTU()); err == nil {
			e.mu.Lock()
			e.l3TunDev = tunDev
			e.mu.Unlock()
			e.logger.WithFields(log.Fields{
				"iface":   tunDev.Name(),
				"localIP": tunDev.LocalIP(),
				"peerIP":  tunDev.PeerIP(),
			}).Info("[Relay] Layer-3 TUN interface (GRE + ChaCha20-Poly1305) brought up")
		} else {
			e.logger.WithField("err", err).Debug("[Relay] Layer-3 TUN device skipped (running unprivileged or in sandbox)")
		}
	}

	e.wg.Add(1)
	go e.telemetryLoop()

	return nil
}

// CarrierAddr returns the bound carrier listener address on Entry.
func (e *Engine) CarrierAddr() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.carrierLn != nil {
		return e.carrierLn.Addr().String()
	}
	return ""
}

// IsAlive reports whether the engine is active.
func (e *Engine) IsAlive() bool {
	return e.alive.Load()
}

func (e *Engine) isDirect() bool {
	return strings.ToLower(e.cfg.Direction) == "direct"
}

// Close gracefully stops all listeners, pooled connections, and active streams.
func (e *Engine) Close() error {
	e.alive.Store(false)
	e.cancel()

	e.mu.Lock()
	if e.carrierLn != nil {
		_ = e.carrierLn.Close()
	}
	if e.quicLn != nil {
		_ = e.quicLn.Close()
	}
	if e.quicUDPConn != nil {
		_ = e.quicUDPConn.Close()
	}
	if e.udpCarrierLn != nil {
		_ = e.udpCarrierLn.Close()
	}
	if e.activeQuicConn != nil {
		_ = e.activeQuicConn.CloseWithError(0, "engine closed")
	}
	if e.activeMuxSess != nil {
		_ = e.activeMuxSess.Close()
	}
	if e.l3TunDev != nil {
		_ = e.l3TunDev.Close()
		e.l3TunDev = nil
	}
	for _, ln := range e.tcpListeners {
		_ = ln.Close()
	}
	e.tcpListeners = nil
	for _, uln := range e.udpListeners {
		_ = uln.Close()
	}
	e.udpListeners = nil
	if e.hdMatcher != nil {
		e.hdMatcher.Close()
	}
	e.mu.Unlock()

	for {
		select {
		case item := <-e.idlePool:
			_ = item.conn.Close()
			e.Stats.PoolIdleConnections.Add(-1)
		default:
			goto drained
		}
	}
drained:

	e.activeStreams.Range(func(key, _ any) bool {
		if c, ok := key.(net.Conn); ok {
			_ = c.Close()
		}
		e.activeStreams.Delete(key)
		return true
	})

	e.wg.Wait()
	return nil
}

func (e *Engine) startEntry() error {
	listenIP := e.cfg.ListenIP
	if listenIP == "" {
		listenIP = "0.0.0.0"
	}

	if e.isDirect() {
		if e.cfg.ExitServerIP == "" {
			return fmt.Errorf("direct relay engine on entry requires ExitServerIP")
		}
		e.wg.Add(1)
		go e.exitPoolLoop()
		e.triggerReplenish()
	} else {
		if err := e.startCarrierListener(listenIP); err != nil {
			return err
		}
	}

	for _, rule := range e.cfg.Forwarders {
		pairs := routing.ExpandPortRange(rule)
		proto := strings.ToLower(strings.TrimSpace(rule.Protocol))
		for _, pair := range pairs {
			lPort, tPort := pair[0], pair[1]
			if !e.isDirect() && lPort == e.cfg.CarrierPort && (proto == "tcp" || proto == "tcp,udp" || proto == "both") {
				e.carrierFwd.Store(int64(tPort))
				e.logger.WithFields(log.Fields{
					"carrierPort": lPort,
					"targetPort":  tPort,
				}).Info("[Relay] Sharing carrier port with user forwarder (single-port multiplexing)")
			} else if proto == "tcp" || proto == "tcp,udp" || proto == "both" {
				if err := e.startTCPForwarderListener(rule.ListenIP, lPort, tPort); err != nil {
					e.logger.WithFields(log.Fields{"port": lPort, "err": err}).Warn("Failed to start TCP forwarder listener")
				}
			}
			if proto == "udp" || proto == "tcp,udp" || proto == "both" {
				if err := e.startUDPForwarderListener(rule.ListenIP, lPort, tPort); err != nil {
					e.logger.WithFields(log.Fields{"port": lPort, "err": err}).Warn("Failed to start UDP forwarder listener")
				}
			}
		}
	}

	return nil
}

func (e *Engine) isQuicTransport() bool {
	return e.cfg.Transport == "quic-reverse" || e.cfg.Transport == "quic" || e.cfg.Transport == "l3-quic"
}

func (e *Engine) isPacketTransport() bool {
	switch e.cfg.Transport {
	case "kcp", "udp", "pck", "xdi", "l3-udp", "l3-pck", "l3-xdi", "l3-sni", "spoof":
		return true
	}
	return false
}

func (e *Engine) isMuxTransport() bool {
	switch e.cfg.Transport {
	case "tcpmux", "wsmux", "wssmux":
		return true
	}
	return e.isPacketTransport()
}

func (e *Engine) startCarrierListener(listenIP string) error {
	if e.cfg.Transport == "tls-reverse" || e.cfg.Transport == "wss-reverse" || e.cfg.Transport == "wssmux" || e.isQuicTransport() {
		tlsCfg, err := transport.BuildRelayTLSConfig(e.cfg.SNI, e.cfg.CertMode, e.cfg.CertFile, e.cfg.KeyFile)
		if err != nil {
			return fmt.Errorf("build relay tls config: %w", err)
		}
		e.tlsServerCfg = tlsCfg
	}

	if e.cfg.UseHalfDuplex && !e.isQuicTransport() && !e.isMuxTransport() {
		e.hdMatcher = transport.NewHalfDuplexMatcher()
	}

	carrierAddr := net.JoinHostPort(listenIP, strconv.Itoa(e.cfg.CarrierPort))

	if e.isQuicTransport() {
		qLn, udpConn, err := transport.ListenQuicCarrier(carrierAddr, e.cfg.SNI, e.cfg.CertMode, e.cfg.CertFile, e.cfg.KeyFile)
		if err != nil {
			return fmt.Errorf("listen quic carrier on %s: %w", carrierAddr, err)
		}
		e.mu.Lock()
		e.quicLn = qLn
		e.quicUDPConn = udpConn
		e.mu.Unlock()
		e.logger.WithFields(log.Fields{
			"carrierPort": e.cfg.CarrierPort,
			"sni":         e.cfg.SNI,
			"transport":   e.cfg.Transport,
		}).Info("[Relay] QUIC carrier listener started successfully")
		e.wg.Add(1)
		go e.quicAcceptLoop(qLn)
		return nil
	}

	if e.isPacketTransport() {
		var uLn *transport.UDPCarrierListener
		var uConn *net.UDPConn
		var err error
		switch e.cfg.Transport {
		case "xdi", "l3-xdi":
			uLn, uConn, err = transport.ListenXDICarrier(carrierAddr, e.cfg.Password, e.cfg.CarrierPort)
		case "pck", "l3-pck", "l3-sni":
			uLn, uConn, err = transport.ListenPCKCarrier(carrierAddr, e.cfg.Password)
		default:
			useFEC := e.cfg.Transport == "kcp"
			uLn, uConn, err = transport.ListenUDPCarrier(carrierAddr, e.cfg.Password, useFEC)
		}
		if err != nil {
			return fmt.Errorf("listen packet carrier (%s) on %s: %w", e.cfg.Transport, carrierAddr, err)
		}
		e.mu.Lock()
		e.udpCarrierLn = uLn
		e.quicUDPConn = uConn
		e.mu.Unlock()
		e.logger.WithFields(log.Fields{
			"carrierPort": e.cfg.CarrierPort,
			"transport":   e.cfg.Transport,
		}).Info("[Relay] Packet/Datagram carrier listener started successfully")
		e.wg.Add(1)
		go e.packetCarrierAcceptLoop(uLn)
		return nil
	}

	ln, err := transport.ListenTCP(e.ctx, carrierAddr)
	if err != nil {
		if transport.ReclaimPortIfOrphanedNode(e.cfg.CarrierPort) {
			e.logger.WithField("port", e.cfg.CarrierPort).Warn("[Relay] Terminated orphaned node process holding carrier port, retrying bind...")
			time.Sleep(300 * time.Millisecond)
			ln, err = transport.ListenTCP(e.ctx, carrierAddr)
		}
	}
	if err != nil {
		conflictErr := transport.FormatPortConflictError(e.cfg.CarrierPort, err)
		e.logger.WithFields(log.Fields{
			"port": e.cfg.CarrierPort,
			"addr": carrierAddr,
			"err":  conflictErr,
		}).Error("[Relay] Relay carrier port bind failed. Another process is occupying this port!")
		return conflictErr
	}
	e.mu.Lock()
	e.carrierLn = ln
	e.mu.Unlock()

	e.logger.WithFields(log.Fields{
		"carrierPort": e.cfg.CarrierPort,
		"sni":         e.cfg.SNI,
		"transport":   e.cfg.Transport,
	}).Info("[Relay] Carrier listener started successfully")

	e.wg.Add(1)
	go e.entryAcceptLoop(ln)
	return nil
}

func (e *Engine) quicAcceptLoop(ln *quic.Listener) {
	defer e.wg.Done()
	for {
		qConn, err := ln.Accept(e.ctx)
		if err != nil {
			select {
			case <-e.ctx.Done():
				return
			default:
				continue
			}
		}
		go func(conn *quic.Conn) {
			for {
				stream, err := conn.AcceptStream(e.ctx)
				if err != nil {
					return
				}
				streamConn, err := transport.AcceptQuicCarrierStream(stream, conn, e.cfg.SNI, e.cfg.Password)
				if err != nil {
					continue
				}
				if e.isDirect() {
					e.wg.Add(1)
					go e.serveExitStream(streamConn)
				} else {
					e.pushIdleStream(streamConn)
				}
			}
		}(qConn)
	}
}

func (e *Engine) packetCarrierAcceptLoop(ln *transport.UDPCarrierListener) {
	defer e.wg.Done()
	for {
		sessConn, err := ln.Accept(e.ctx)
		if err != nil {
			return
		}
		go e.serveMuxSession(sessConn)
	}
}

func (e *Engine) bindL3TUNDuplex(conn net.Conn) {
	uSess, ok := conn.(*transport.UDPSessionConn)
	if !ok {
		return
	}
	e.mu.Lock()
	tunDev := e.l3TunDev
	e.mu.Unlock()
	if tunDev == nil {
		return
	}
	tunDev.SetSender(func(wire []byte) error {
		e.Stats.AddUpload(int64(len(wire)))
		return uSess.WriteTUNPacket(wire)
	})
	uSess.SetTUNPacketHandler(func(wire []byte) {
		e.Stats.AddDownload(int64(len(wire)))
		_ = tunDev.InjectWirePacket(wire)
	})
}

func (e *Engine) serveMuxSession(rawConn net.Conn) {
	e.bindL3TUNDuplex(rawConn)
	muxSess := transport.NewMuxSession(rawConn, false)
	defer muxSess.Close()
	for {
		stream, err := muxSess.AcceptStream()
		if err != nil {
			return
		}
		if e.isDirect() {
			e.wg.Add(1)
			go e.serveExitStream(stream)
		} else {
			e.pushIdleStream(stream)
		}
	}
}

func (e *Engine) entryAcceptLoop(ln net.Listener) {
	defer e.wg.Done()
	for {
		rawConn, err := ln.Accept()
		if err != nil {
			select {
			case <-e.ctx.Done():
				return
			default:
				continue
			}
		}
		go e.handleIncomingCarrier(rawConn)
	}
}

func (e *Engine) handleIncomingCarrier(rawConn net.Conn) {
	isDirect := e.isDirect()
	targetFwd := e.carrierFwd.Load()
	hasUserFwd := targetFwd > 0 && !isDirect
	var carrierConn net.Conn

	switch e.cfg.Transport {
	case "tls-reverse":
		tlsConn, err := transport.AcceptTLSReverseCarrier(rawConn, e.tlsServerCfg, e.cfg.SNI, e.cfg.Password)
		if err != nil {
			return
		}
		carrierConn = tlsConn

	case "wss-reverse", "wssmux":
		if e.tlsServerCfg == nil {
			_ = rawConn.Close()
			return
		}
		tlsConn := tls.Server(rawConn, e.tlsServerCfg)
		_ = tlsConn.SetDeadline(time.Now().Add(5 * time.Second))
		if err := tlsConn.Handshake(); err != nil {
			_ = tlsConn.Close()
			return
		}
		_ = tlsConn.SetDeadline(time.Time{})
		action, inspectedConn, err := transport.InspectWSTraffic(tlsConn, e.cfg.SNI, e.cfg.Password, hasUserFwd)
		if err != nil || action != transport.ActionReverseCarrier {
			if action == transport.ActionUserClient && inspectedConn != nil {
				go routing.HandleEntryTCPClient(inspectedConn, uint16(targetFwd), e.ClaimReverseStream, e.Stats)
			}
			return
		}
		carrierConn = inspectedConn

	case "ws-reverse", "wsmux":
		action, inspectedConn, err := transport.InspectWSTraffic(rawConn, e.cfg.SNI, e.cfg.Password, hasUserFwd)
		if err != nil || action != transport.ActionReverseCarrier {
			if action == transport.ActionUserClient && inspectedConn != nil {
				go routing.HandleEntryTCPClient(inspectedConn, uint16(targetFwd), e.ClaimReverseStream, e.Stats)
			}
			return
		}
		carrierConn = inspectedConn

	case "tcp", "tcpmux":
		action, inspectedConn, err := transport.InspectTCPTraffic(rawConn, e.cfg.Password, hasUserFwd)
		if err != nil || action != transport.ActionReverseCarrier {
			if action == transport.ActionUserClient && inspectedConn != nil {
				go routing.HandleEntryTCPClient(inspectedConn, uint16(targetFwd), e.ClaimReverseStream, e.Stats)
			}
			return
		}
		carrierConn = inspectedConn

	case "stealth":
		action, inspectedConn, err := transport.InspectStealthTraffic(rawConn, e.cfg.Password, hasUserFwd)
		if err != nil || action != transport.ActionReverseCarrier {
			if action == transport.ActionUserClient && inspectedConn != nil {
				go routing.HandleEntryTCPClient(inspectedConn, uint16(targetFwd), e.ClaimReverseStream, e.Stats)
			}
			return
		}
		carrierConn = inspectedConn

	default: // "reverse-reality"
		action, inspectedConn, err := transport.InspectRealityTraffic(rawConn, e.cfg.SNI, e.cfg.Password, hasUserFwd)
		if err != nil {
			return
		}
		switch action {
		case transport.ActionReverseCarrier:
			carrierConn = inspectedConn

		case transport.ActionUserClient:
			go routing.HandleEntryTCPClient(inspectedConn, uint16(targetFwd), e.ClaimReverseStream, e.Stats)
			return

		case transport.ActionDPIProbe:
			originAddr := e.cfg.OriginIP
			if originAddr == "" && e.cfg.SNI != "" {
				if resolved, err := telemetry.ResolveOriginIP(e.cfg.SNI, ""); err == nil {
					originAddr = resolved
				}
			}
			go transport.SpliceToOrigin(inspectedConn, originAddr)
			return
		}
	}

	if e.isMuxTransport() {
		e.serveMuxSession(carrierConn)
		return
	}

	var stream net.Conn
	if e.cfg.UseHalfDuplex && e.hdMatcher != nil {
		hdConn, err := e.hdMatcher.AcceptHalf(carrierConn)
		if err != nil || hdConn == nil {
			return
		}
		stream = hdConn
	} else {
		stream = carrierConn
	}

	if isDirect {
		e.wg.Add(1)
		go e.serveExitStream(stream)
	} else {
		e.pushIdleStream(stream)
	}
}

func (e *Engine) pushIdleStream(stream net.Conn) {
	select {
	case <-e.ctx.Done():
		_ = stream.Close()
		return
	default:
	}

	item := pooledStream{
		conn:      stream,
		createdAt: time.Now(),
	}

	select {
	case e.idlePool <- item:
		idleCount := e.Stats.PoolIdleConnections.Add(1)
		if idleCount == 1 {
			e.logger.WithFields(log.Fields{
				"carrierPort": e.cfg.CarrierPort,
				"remote":      stream.RemoteAddr().String(),
			}).Info("[Relay] Entry reverse carrier pool active: authenticated reverse socket received")
		}
	default:
		select {
		case old := <-e.idlePool:
			_ = old.conn.Close()
		default:
			e.Stats.PoolIdleConnections.Add(1)
		}
		select {
		case e.idlePool <- item:
		default:
			_ = stream.Close()
			e.Stats.PoolIdleConnections.Add(-1)
		}
	}
}

// ClaimReverseStream claims a warm connection from the idle pool for forwarding.
func (e *Engine) ClaimReverseStream(timeout time.Duration) (net.Conn, error) {
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	for {
		select {
		case <-e.ctx.Done():
			return nil, e.ctx.Err()
		case <-timer.C:
			return nil, fmt.Errorf("timeout waiting for reverse pool connection")
		case item := <-e.idlePool:
			e.Stats.PoolIdleConnections.Add(-1)
			if time.Since(item.createdAt) > 3*time.Minute || !transport.IsStreamAlive(item.conn) {
				_ = item.conn.Close()
				continue
			}
			if e.isDirect() {
				e.triggerReplenish()
			}
			return item.conn, nil
		}
	}
}

func (e *Engine) startTCPForwarderListener(listenIP string, listenPort, targetPort int) error {
	if listenIP == "" {
		listenIP = "0.0.0.0"
	}
	addr := net.JoinHostPort(listenIP, strconv.Itoa(listenPort))
	ln, err := transport.ListenTCP(e.ctx, addr)
	if err != nil {
		if transport.ReclaimPortIfOrphanedNode(listenPort) {
			e.logger.WithField("port", listenPort).Warn("Terminated orphaned node process holding forwarder port, retrying bind...")
			time.Sleep(300 * time.Millisecond)
			ln, err = transport.ListenTCP(e.ctx, addr)
		}
	}
	if err != nil {
		conflictErr := transport.FormatPortConflictError(listenPort, err)
		e.logger.WithFields(log.Fields{
			"port": listenPort,
			"addr": addr,
			"err":  conflictErr,
		}).Error("TCP forwarder bind failed. Port is already in use!")
		return conflictErr
	}

	e.mu.Lock()
	e.tcpListeners = append(e.tcpListeners, ln)
	e.mu.Unlock()

	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		for {
			clientConn, err := ln.Accept()
			if err != nil {
				select {
				case <-e.ctx.Done():
					return
				default:
					continue
				}
			}
			transport.TuneTCPConn(clientConn)
			go routing.HandleEntryTCPClient(clientConn, uint16(targetPort), e.ClaimReverseStream, e.Stats)
		}
	}()
	return nil
}

func (e *Engine) startUDPForwarderListener(listenIP string, listenPort, targetPort int) error {
	if listenIP == "" {
		listenIP = "0.0.0.0"
	}
	udpAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(listenIP, strconv.Itoa(listenPort)))
	if err != nil {
		return err
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		conflictErr := transport.FormatPortConflictError(listenPort, err)
		e.logger.WithFields(log.Fields{
			"port": listenPort,
			"addr": udpAddr.String(),
			"err":  conflictErr,
		}).Error("UDP forwarder bind failed. Port is already in use!")
		return conflictErr
	}

	e.mu.Lock()
	e.udpListeners = append(e.udpListeners, udpConn)
	e.mu.Unlock()

	routing.StartUDPListenerLoop(e.ctx, udpConn, targetPort, e.ClaimReverseStream, e.Stats)
	return nil
}

func (e *Engine) startExit() error {
	listenIP := e.cfg.ListenIP
	if listenIP == "" {
		listenIP = "0.0.0.0"
	}

	if e.isDirect() {
		return e.startCarrierListener(listenIP)
	}

	if e.cfg.EntryServerIP == "" && len(e.cfg.FloatingIPs) == 0 {
		return fmt.Errorf("exit relay engine requires EntryServerIP")
	}

	e.wg.Add(1)
	go e.exitPoolLoop()
	e.triggerReplenish()
	return nil
}

func (e *Engine) triggerReplenish() {
	select {
	case e.replenishCh <- struct{}{}:
	default:
	}
}

func (e *Engine) logDialFailure(err error) {
	now := time.Now().Unix()
	last := e.lastDialLog.Load()
	if now-last >= 10 {
		if e.lastDialLog.CompareAndSwap(last, now) {
			e.logger.WithFields(log.Fields{
				"carrierPort": e.cfg.CarrierPort,
				"entryIP":     e.cfg.EntryServerIP,
				"err":         err,
			}).Warn("[Relay] Exit node failed to connect to entry carrier port (check firewall or port conflict on entry)")
		}
	}
}

func (e *Engine) exitPoolLoop() {
	defer e.wg.Done()
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	var dialingCount atomic.Int64

	spawnDial := func() {
		dialingCount.Add(1)
		go func() {
			defer dialingCount.Add(-1)
			stream, err := e.dialCarrierStream()
			if err != nil {
				e.logDialFailure(err)
				return
			}
			select {
			case <-e.ctx.Done():
				_ = stream.Close()
				return
			default:
			}
			if e.isDirect() {
				e.pushIdleStream(stream)
			} else {
				e.wg.Add(1)
				go e.serveExitStream(stream)
			}
		}()
	}

	for {
		select {
		case <-e.ctx.Done():
			return
		case <-e.replenishCh:
		case <-ticker.C:
		}

		minHeld := int64(e.cfg.MinHeldConnections)
		var current int64
		if e.isDirect() {
			current = e.Stats.PoolIdleConnections.Load() + dialingCount.Load()
		} else {
			current = e.idleWaiters.Load() + dialingCount.Load()
		}
		needed := minHeld - current
		for i := int64(0); i < needed; i++ {
			spawnDial()
		}
	}
}

func (e *Engine) dialCarrierStream() (net.Conn, error) {
	if e.isQuicTransport() {
		return e.dialQuicCarrier()
	}
	if e.isMuxTransport() {
		return e.dialMuxCarrier()
	}
	if e.cfg.UseHalfDuplex {
		return transport.DialHalfDuplexPair(e.dialSingleCarrier)
	}
	return e.dialSingleCarrier()
}

func (e *Engine) dialMuxCarrier() (net.Conn, error) {
	e.mu.Lock()
	muxSess := e.activeMuxSess
	e.mu.Unlock()

	if muxSess == nil || muxSess.IsClosed() {
		baseConn, err := e.dialSingleCarrier()
		if err != nil {
			return nil, err
		}
		e.bindL3TUNDuplex(baseConn)
		newSess := transport.NewMuxSession(baseConn, true)
		e.mu.Lock()
		e.activeMuxSess = newSess
		muxSess = newSess
		e.mu.Unlock()
	}

	stream, err := muxSess.OpenStream()
	if err != nil {
		_ = muxSess.Close()
		e.mu.Lock()
		e.activeMuxSess = nil
		e.mu.Unlock()
		baseConn, bErr := e.dialSingleCarrier()
		if bErr != nil {
			return nil, bErr
		}
		retrySess := transport.NewMuxSession(baseConn, true)
		e.mu.Lock()
		e.activeMuxSess = retrySess
		e.mu.Unlock()
		return retrySess.OpenStream()
	}
	return stream, nil
}

func (e *Engine) dialQuicCarrier() (net.Conn, error) {
	candidates := e.targetDialIPs()
	if len(candidates) == 0 {
		return nil, fmt.Errorf("no target server IP configured for quic dial")
	}
	addr := net.JoinHostPort(candidates[0], strconv.Itoa(e.cfg.CarrierPort))

	e.mu.Lock()
	qConn := e.activeQuicConn
	e.mu.Unlock()

	if qConn == nil || qConn.Context().Err() != nil {
		newConn, err := transport.DialQuicSession(e.ctx, addr, e.cfg.SNI)
		if err != nil {
			return nil, err
		}
		e.mu.Lock()
		e.activeQuicConn = newConn
		qConn = newConn
		e.mu.Unlock()
	}

	stream, err := transport.OpenQuicCarrierStream(e.ctx, qConn, e.cfg.SNI, e.cfg.Password)
	if err != nil {
		_ = qConn.CloseWithError(0, "stream open failed")
		e.mu.Lock()
		e.activeQuicConn = nil
		e.mu.Unlock()
		retryConn, rErr := transport.DialQuicSession(e.ctx, addr, e.cfg.SNI)
		if rErr != nil {
			return nil, rErr
		}
		e.mu.Lock()
		e.activeQuicConn = retryConn
		e.mu.Unlock()
		return transport.OpenQuicCarrierStream(e.ctx, retryConn, e.cfg.SNI, e.cfg.Password)
	}
	return stream, nil
}

func (e *Engine) dialSingleCarrier() (net.Conn, error) {
	candidates := e.targetDialIPs()
	if len(candidates) == 0 {
		return nil, fmt.Errorf("no target server IP configured")
	}

	if e.isPacketTransport() {
		addr := net.JoinHostPort(candidates[0], strconv.Itoa(e.cfg.CarrierPort))
		switch e.cfg.Transport {
		case "xdi", "l3-xdi":
			return transport.DialXDICarrier(e.ctx, addr, e.cfg.Password, e.cfg.CarrierPort)
		case "pck", "l3-pck", "l3-sni":
			return transport.DialPCKCarrier(e.ctx, addr, e.cfg.Password)
		default:
			useFEC := e.cfg.Transport == "kcp"
			return transport.DialUDPCarrier(e.ctx, addr, e.cfg.Password, useFEC)
		}
	}

	rawDial := func() (net.Conn, error) {
		dialTCP := func(ctx context.Context, idx int) (net.Conn, error) {
			ip := candidates[idx%len(candidates)]
			addr := net.JoinHostPort(ip, strconv.Itoa(e.cfg.CarrierPort))
			return transport.DialTCPContext(ctx, addr, 4*time.Second)
		}
		if e.cfg.UseFisher && e.cfg.FisherConnections > 1 {
			fisher := transport.NewFisherDialer(e.cfg.FisherConnections)
			return fisher.DialContext(e.ctx, dialTCP)
		}
		return dialTCP(e.ctx, 0)
	}

	switch e.cfg.Transport {
	case "tls-reverse":
		return transport.DialTLSReverseCarrier(rawDial, e.cfg.SNI, e.cfg.Password)
	case "tcp", "tcpmux":
		return transport.DialTCPCarrier(rawDial, e.cfg.Password)
	case "stealth":
		return transport.DialStealthCarrier(rawDial, e.cfg.Password)
	case "ws-reverse", "wsmux":
		return transport.DialWSCarrier(rawDial, false, e.cfg.SNI, e.cfg.Password)
	case "wss-reverse", "wssmux":
		return transport.DialWSCarrier(rawDial, true, e.cfg.SNI, e.cfg.Password)
	default:
		return transport.DialRealityCarrier(rawDial, e.cfg.SNI, e.cfg.Password)
	}
}

func (e *Engine) targetDialIPs() []string {
	if e.isDirect() {
		if e.cfg.ExitServerIP != "" {
			return []string{e.cfg.ExitServerIP}
		}
		return nil
	}
	return e.targetEntryIPs()
}

func (e *Engine) targetEntryIPs() []string {
	var ips []string
	if e.cfg.EntryServerIP != "" {
		ips = append(ips, e.cfg.EntryServerIP)
	}
	for _, fip := range e.cfg.FloatingIPs {
		trimmed := strings.TrimSpace(fip)
		if trimmed != "" && trimmed != e.cfg.EntryServerIP {
			ips = append(ips, trimmed)
		}
	}
	return ips
}

func (e *Engine) serveExitStream(stream net.Conn) {
	defer e.wg.Done()

	e.activeStreams.Store(stream, struct{}{})
	defer e.activeStreams.Delete(stream)

	e.idleWaiters.Add(1)
	idleCount := e.Stats.PoolIdleConnections.Add(1)
	if idleCount == 1 {
		e.logger.WithFields(log.Fields{
			"carrierPort": e.cfg.CarrierPort,
			"sni":         e.cfg.SNI,
		}).Info("[Relay] Exit reverse carrier connected and warm connections ready in pool")
	}

	_ = stream.SetReadDeadline(time.Now().Add(4 * time.Minute))
	proto, targetPort, err := routing.ReadRoutingHeader(stream)
	_ = stream.SetReadDeadline(time.Time{})

	e.idleWaiters.Add(-1)
	e.Stats.PoolIdleConnections.Add(-1)
	e.triggerReplenish()

	if err != nil {
		_ = stream.Close()
		return
	}

	switch proto {
	case routing.RouteProtoTCP:
		routing.HandleExitTCPForward(stream, e.cfg.TargetIP, targetPort, e.Stats)
	case routing.RouteProtoUDP:
		routing.HandleExitUDPForward(stream, e.cfg.TargetIP, targetPort, e.Stats)
	case routing.RouteProtoProbe:
		telemetry.HandleExitProbeStream(stream, e.Stats)
	default:
		_ = stream.Close()
	}
}

func (e *Engine) telemetryLoop() {
	defer e.wg.Done()

	fiveSecTicker := time.NewTicker(5 * time.Second)
	defer fiveSecTicker.Stop()

	probeInterval := time.Duration(e.cfg.ProbeIntervalMin) * time.Minute
	if probeInterval < time.Minute {
		probeInterval = 30 * time.Minute
	}
	probeTicker := time.NewTicker(probeInterval)
	defer probeTicker.Stop()

	for {
		select {
		case <-e.ctx.Done():
			return
		case <-fiveSecTicker.C:
			e.Stats.UpdateRollingThroughput()
			if e.cfg.Role == "entry" && e.Stats.PoolIdleConnections.Load() > 0 {
				_, _ = telemetry.MeasureLatency(e.ClaimReverseStream, e.Stats)
			}
		case <-probeTicker.C:
			if e.cfg.Role == "entry" && e.cfg.EnableProbe && e.Stats.PoolIdleConnections.Load() > 0 {
				if sample, err := telemetry.RunBandwidthProbe(e.ClaimReverseStream, e.Stats, 2*time.Second); err == nil && e.cfg.OnProbeSample != nil {
					e.cfg.OnProbeSample(e.cfg.TunnelID, sample)
				}
			}
		}
	}
}

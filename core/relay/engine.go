package relay

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
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
	Preset             string // "turbo" (default), "balance", "aggressive"
	Transport          string // "reverse-reality", "tls-reverse", etc.
	CarrierPort        int    // Default: 443
	ListenIP           string // Default: "0.0.0.0"
	DialSourceIP       string // Optional source IP to bind when dialing (e.g. multi-IP server)
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
	TCPNoDelay         *bool
	PCKFlags           []string
	EdgeIP             string
	WSPath             string
	SimpleAuth         bool
	KCPDataShards      int
	KCPParityShards    int
	KCPMTU             int
	L3LocalIP          string
	L3PeerIP           string
	L3Iface            string
	L3MTU              int
	SpoofSrcIP         string
	SpoofSrcPool       []string
	SpoofPeerSrcIP     string
	SpoofProfile       string
	SpoofUplink        string
	SpoofDownlink      string
	SpoofFakeTLS       bool
	SpoofTTLJitter     bool
	SpoofRandomDSCP    bool
	SpoofPortMin       int
	SpoofPortMax       int
	SpoofPadding       bool
	SpoofPaddingMax    int
	SpoofShufflePort   bool
	SpoofInterface     string
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
	dialSessMu    sync.Mutex
	carrierLn      net.Listener
	quicLn         *quic.Listener
	quicUDPConn    *net.UDPConn
	udpCarrierLn   *transport.UDPCarrierListener
	activeQuicConn   *quic.Conn
	activeMuxSess    *transport.MuxSession
	acceptedMuxSess  sync.Map // *transport.MuxSession -> struct{}{}
	acceptedQuicConn sync.Map // *quic.Conn -> struct{}{}
	tcpForwarderMap  sync.Map // int (listenPort) -> net.Listener
	udpForwarderMap  sync.Map // int (listenPort) -> *net.UDPConn
	l3TunDev         *transport.L3TUNDevice
	l3RawConn        net.PacketConn
	l3PeerAddr       atomic.Pointer[net.UDPAddr]
	tcpListeners   []net.Listener
	udpListeners  []*net.UDPConn
	hdMatcher     *transport.HalfDuplexMatcher
	tlsServerCfg  *tls.Config
	idlePool      chan pooledStream
	replenishCh   chan struct{}
	idleWaiters   atomic.Int64
	idleStreams   sync.Map // Tracks net.Conn -> struct{}{} currently waiting for routing header on Exit
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
	if cfg.Preset == "" {
		cfg.Preset = "turbo"
	}
	switch strings.ToLower(cfg.Preset) {
	case "balance":
		if cfg.MinHeldConnections <= 0 {
			cfg.MinHeldConnections = 4
		}
		if cfg.FisherConnections <= 0 {
			cfg.FisherConnections = 2
		}
	case "aggressive":
		if cfg.MinHeldConnections <= 0 {
			cfg.MinHeldConnections = 16
		}
		if cfg.FisherConnections <= 0 {
			cfg.FisherConnections = 4
		}
	default: // "turbo"
		if cfg.MinHeldConnections <= 0 {
			cfg.MinHeldConnections = 8
		}
		if cfg.FisherConnections <= 0 {
			cfg.FisherConnections = 3
		}
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
	e.alive.Store(true)

	if transport.GetTransportSpec(e.cfg.Transport).IsL3 {
		mtu := e.cfg.L3MTU
		if mtu <= 0 {
			mtu = transport.GetConfiguredMTU()
		}
		if tunDev, err := transport.OpenL3TUNWithSubnet(e.cfg.TunnelID, e.cfg.Role, e.cfg.Password, mtu, e.cfg.L3Iface, e.cfg.L3LocalIP, e.cfg.L3PeerIP); err == nil {
			e.mu.Lock()
			e.l3TunDev = tunDev
			e.mu.Unlock()
			e.logger.WithFields(log.Fields{
				"iface":   tunDev.Name(),
				"localIP": tunDev.LocalIP(),
				"peerIP":  tunDev.PeerIP(),
			}).Info("[Relay] Layer-3 TUN interface (GRE + ChaCha20-Poly1305) brought up")
			if e.isPacketTransport() {
				if pErr := e.startL3RawPump(); pErr != nil {
					e.logger.WithField("err", pErr).Warn("[Relay] Failed to open L3 raw packet pump")
				}
			}
		} else {
			e.logger.WithField("err", err).Debug("[Relay] Layer-3 TUN device skipped (running unprivileged or in sandbox)")
		}
	}

	if e.cfg.Role == "entry" {
		if err := e.startEntry(); err != nil {
			e.alive.Store(false)
			if e.l3RawConn != nil {
				_ = e.l3RawConn.Close()
				e.l3RawConn = nil
			}
			if e.l3TunDev != nil {
				_ = e.l3TunDev.Close()
				e.l3TunDev = nil
			}
			e.cancel()
			return err
		}
	} else if e.cfg.Role == "exit" {
		if err := e.startExit(); err != nil {
			e.alive.Store(false)
			if e.l3RawConn != nil {
				_ = e.l3RawConn.Close()
				e.l3RawConn = nil
			}
			if e.l3TunDev != nil {
				_ = e.l3TunDev.Close()
				e.l3TunDev = nil
			}
			e.cancel()
			return err
		}
	} else {
		e.alive.Store(false)
		if e.l3RawConn != nil {
			_ = e.l3RawConn.Close()
			e.l3RawConn = nil
		}
		if e.l3TunDev != nil {
			_ = e.l3TunDev.Close()
			e.l3TunDev = nil
		}
		e.cancel()
		return fmt.Errorf("unknown relay engine role: %q", e.cfg.Role)
	}

	if e.l3TunDev != nil && e.cfg.Role == "entry" && !e.isPacketTransport() && e.cfg.TunnelID < 1000 {
		e.wg.Add(1)
		go e.l3StreamInitiatorLoop()
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
	if e.cfg.CarrierPort > 0 {
		return net.JoinHostPort(e.cfg.ListenIP, strconv.Itoa(e.cfg.CarrierPort))
	}
	return ""
}

// IsAlive reports whether the engine is active.
func (e *Engine) IsAlive() bool {
	return e.alive.Load()
}

// Config returns the engine's configuration.
func (e *Engine) Config() Config {
	return e.cfg
}

func (e *Engine) isDirect() bool {
	return strings.ToLower(e.cfg.Direction) == "direct"
}

// Close gracefully stops all listeners, pooled connections, and active streams.
func (e *Engine) Close() error {
	e.alive.Store(false)
	e.cancel()

	// 1. Explicitly notify and close accepted server sessions (QUIC and Mux) so
	// remote dialers (Kharej) immediately receive the close and redial without waiting.
	e.acceptedQuicConn.Range(func(key, _ any) bool {
		if qc, ok := key.(*quic.Conn); ok && qc != nil {
			_ = qc.CloseWithError(0, "engine closed")
		}
		e.acceptedQuicConn.Delete(key)
		return true
	})
	e.acceptedMuxSess.Range(func(key, _ any) bool {
		if ms, ok := key.(*transport.MuxSession); ok && ms != nil {
			_ = ms.Close()
		}
		e.acceptedMuxSess.Delete(key)
		return true
	})

	UnregisterSharedCarrier(e.cfg.TunnelID, e.cfg.CarrierPort)

	e.mu.Lock()
	if e.activeQuicConn != nil {
		_ = e.activeQuicConn.CloseWithError(0, "engine closed")
		e.activeQuicConn = nil
	}
	if e.activeMuxSess != nil {
		_ = e.activeMuxSess.Close()
		e.activeMuxSess = nil
	}
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
	if e.l3RawConn != nil {
		_ = e.l3RawConn.Close()
		e.l3RawConn = nil
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
	e.tcpForwarderMap.Range(func(key, val any) bool {
		if ln, ok := val.(net.Listener); ok {
			_ = ln.Close()
		}
		e.tcpForwarderMap.Delete(key)
		return true
	})
	e.udpForwarderMap.Range(func(key, val any) bool {
		if uln, ok := val.(*net.UDPConn); ok {
			_ = uln.Close()
		}
		e.udpForwarderMap.Delete(key)
		return true
	})
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

	// Bounded wait: never block the process shutdown if an OS socket read hangs
	waitCh := make(chan struct{})
	go func() {
		e.wg.Wait()
		close(waitCh)
	}()
	select {
	case <-waitCh:
	case <-time.After(3 * time.Second):
		e.logger.Warn("[Relay] Engine Close WaitGroup timed out after 3s; proceeding with teardown")
	}

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

	isTCPCarrier := !e.isDirect() && !e.isQuicTransport() && !e.isPacketTransport()
	for _, rule := range e.cfg.Forwarders {
		pairs := routing.ExpandPortRange(rule)
		proto := strings.ToLower(strings.TrimSpace(rule.Protocol))
		for _, pair := range pairs {
			lPort, tPort := pair[0], pair[1]
			if isTCPCarrier && lPort == e.cfg.CarrierPort && (proto == "tcp" || proto == "tcp,udp" || proto == "both") {
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
				if !e.isDirect() && (e.isQuicTransport() || e.isPacketTransport()) && lPort == e.cfg.CarrierPort {
					e.logger.WithFields(log.Fields{
						"carrierPort": lPort,
						"transport":   e.cfg.Transport,
					}).Warn("[Relay] User UDP forwarder matches UDP carrier port; skipped duplicate socket bind on entry")
					continue
				}
				if err := e.startUDPForwarderListener(rule.ListenIP, lPort, tPort, rule.GamingMode); err != nil {
					e.logger.WithFields(log.Fields{"port": lPort, "err": err}).Warn("Failed to start UDP forwarder listener")
				}
			}
		}
	}

	return nil
}

func (e *Engine) isQuicTransport() bool {
	return transport.GetTransportSpec(e.cfg.Transport).IsQuic
}

func (e *Engine) isPacketTransport() bool {
	return transport.GetTransportSpec(e.cfg.Transport).IsPacket
}

func (e *Engine) isMuxTransport() bool {
	return transport.GetTransportSpec(e.cfg.Transport).IsMux
}

func (e *Engine) isL3DirectTUNMode() bool {
	return e.l3TunDev != nil && e.isPacketTransport() && e.l3RawConn != nil
}

func (e *Engine) startL3RawPump() error {
	spoofOpts := transport.SpoofOptions{
		SrcIP:       e.cfg.SpoofSrcIP,
		SrcPool:     e.cfg.SpoofSrcPool,
		PeerSrcIP:   e.cfg.SpoofPeerSrcIP,
		Profile:     e.cfg.SpoofProfile,
		Uplink:      e.cfg.SpoofUplink,
		Downlink:    e.cfg.SpoofDownlink,
		FakeTLS:     e.cfg.SpoofFakeTLS,
		TTLJitter:   e.cfg.SpoofTTLJitter,
		RandomDSCP:  e.cfg.SpoofRandomDSCP,
		ShufflePort: e.cfg.SpoofShufflePort,
		PortMin:     uint16(e.cfg.SpoofPortMin),
		PortMax:     uint16(e.cfg.SpoofPortMax),
		Padding:     e.cfg.SpoofPadding,
		PaddingMax:  uint8(e.cfg.SpoofPaddingMax),
		Interface:   e.cfg.SpoofInterface,
	}
	isServer := e.cfg.Role == "entry"
	rawConn, err := transport.OpenL3RawCarrier(e.cfg.Transport, e.cfg.ListenIP, e.cfg.Password, e.cfg.CarrierPort, isServer, spoofOpts)
	if err != nil {
		return err
	}
	e.mu.Lock()
	e.l3RawConn = rawConn
	e.mu.Unlock()

	peerIPStr := e.cfg.ExitServerIP
	if e.cfg.Role == "exit" {
		peerIPStr = e.cfg.EntryServerIP
	}
	if peerIPStr == "" && len(e.cfg.FloatingIPs) > 0 {
		peerIPStr = strings.TrimSpace(e.cfg.FloatingIPs[0])
	}
	if parsedPeer := net.ParseIP(peerIPStr); parsedPeer != nil {
		e.l3PeerAddr.Store(&net.UDPAddr{IP: parsedPeer, Port: e.cfg.CarrierPort})
	}

	e.l3TunDev.SetSender(func(wire []byte) error {
		dst := e.l3PeerAddr.Load()
		if dst == nil {
			return errors.New("l3: peer public IP not yet known")
		}
		e.Stats.AddUpload(int64(len(wire)))
		_, wErr := rawConn.WriteTo(wire, dst)
		return wErr
	})

	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		buf := make([]byte, 65535)
		for {
			n, from, rErr := rawConn.ReadFrom(buf)
			if rErr != nil {
				if !e.alive.Load() {
					return
				}
				continue
			}
			if e.l3TunDev != nil {
				if err := e.l3TunDev.InjectWirePacket(buf[:n]); err == nil {
					e.Stats.AddDownload(int64(n))
					if from != nil {
						switch a := from.(type) {
						case *net.UDPAddr:
							port := a.Port
							if port <= 0 {
								port = e.cfg.CarrierPort
							}
							e.l3PeerAddr.Store(&net.UDPAddr{IP: a.IP, Port: port})
						case *net.IPAddr:
							e.l3PeerAddr.Store(&net.UDPAddr{IP: a.IP, Port: e.cfg.CarrierPort})
						default:
							host, portStr, sErr := net.SplitHostPort(from.String())
							if sErr != nil {
								host = from.String()
							}
							port := e.cfg.CarrierPort
							if pNum, pErr := strconv.ParseUint(portStr, 10, 16); pErr == nil && pNum > 0 {
								port = int(pNum)
							}
							if ip := net.ParseIP(host); ip != nil {
								e.l3PeerAddr.Store(&net.UDPAddr{IP: ip, Port: port})
							}
						}
					}
				}
			}
		}
	}()
	return nil
}

func (e *Engine) startCarrierListener(listenIP string) error {
	if e.isL3DirectTUNMode() {
		tunLocalIP := strings.Split(e.l3TunDev.LocalIP(), "/")[0]
		privAddr := net.JoinHostPort(tunLocalIP, "1234")
		ln, err := net.Listen("tcp", privAddr)
		if err != nil {
			return fmt.Errorf("listen L3 private carrier on %s: %w", privAddr, err)
		}
		e.mu.Lock()
		e.carrierLn = ln
		e.mu.Unlock()
		e.logger.WithFields(log.Fields{
			"privateAddr": privAddr,
			"iface":       e.l3TunDev.Name(),
			"transport":   e.cfg.Transport,
		}).Info("[Relay] L3 TUN private carrier listener active")
		e.wg.Add(1)
		go func() {
			defer e.wg.Done()
			for {
				c, aErr := ln.Accept()
				if aErr != nil {
					return
				}
				go func(raw net.Conn) {
					action, inspected, iErr := transport.InspectTCPTraffic(raw, e.cfg.Password, false)
					if iErr != nil || action != transport.ActionReverseCarrier {
						_ = raw.Close()
						return
					}
					if e.isDirect() {
						e.wg.Add(1)
						go e.serveExitStream(inspected)
					} else {
						e.pushIdleStream(inspected)
					}
				}(c)
			}
		}()
		return nil
	}

	spec := transport.GetTransportSpec(e.cfg.Transport)
	if spec.NeedsTLSServerCfg {
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
			uLn, uConn, err = transport.ListenPCKCarrier(carrierAddr, e.cfg.Password, e.cfg.CarrierPort)
		case "l3-bip":
			uLn, uConn, err = transport.ListenBIPCarrier(carrierAddr, e.cfg.Password, e.cfg.CarrierPort)
		case "l3-ipip":
			uLn, uConn, err = transport.ListenIPIPCarrier(carrierAddr, e.cfg.Password, e.cfg.CarrierPort)
		case "l3-gre":
			uLn, uConn, err = transport.ListenGRECarrier(carrierAddr, e.cfg.Password, e.cfg.CarrierPort)
		case "spoof":
			spoofOpts := transport.SpoofOptions{
				SrcIP:       e.cfg.SpoofSrcIP,
				SrcPool:     e.cfg.SpoofSrcPool,
				PeerSrcIP:   e.cfg.SpoofPeerSrcIP,
				Profile:     e.cfg.SpoofProfile,
				Uplink:      e.cfg.SpoofUplink,
				Downlink:    e.cfg.SpoofDownlink,
				FakeTLS:     e.cfg.SpoofFakeTLS,
				TTLJitter:   e.cfg.SpoofTTLJitter,
				RandomDSCP:  e.cfg.SpoofRandomDSCP,
				ShufflePort: e.cfg.SpoofShufflePort,
				PortMin:     uint16(e.cfg.SpoofPortMin),
				PortMax:     uint16(e.cfg.SpoofPortMax),
				Padding:     e.cfg.SpoofPadding,
				PaddingMax:  uint8(e.cfg.SpoofPaddingMax),
				Interface:   e.cfg.SpoofInterface,
			}
			uLn, uConn, err = transport.ListenSpoofCarrier(carrierAddr, e.cfg.Password, spoofOpts, e.cfg.CarrierPort)
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

	err := RegisterSharedCarrier(
		e.ctx,
		listenIP,
		e.cfg,
		e.handleIncomingCarrier,
		func(c net.Conn, targetPort uint16) {
			go routing.HandleEntryTCPClient(c, targetPort, e.ClaimReverseStream, e.Stats)
		},
	)
	if err != nil {
		return err
	}

	e.logger.WithFields(log.Fields{
		"carrierPort": e.cfg.CarrierPort,
		"sni":         e.cfg.SNI,
		"transport":   e.cfg.Transport,
	}).Info("[Relay] Shared Carrier port demultiplexer active")

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
		e.acceptedQuicConn.Store(qConn, struct{}{})
		go func(conn *quic.Conn) {
			defer e.acceptedQuicConn.Delete(conn)
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

func (e *Engine) l3StreamInitiatorLoop() {
	defer e.wg.Done()
	for {
		select {
		case <-e.ctx.Done():
			return
		default:
		}
		for e.Stats.PoolIdleConnections.Load() < 2 {
			select {
			case <-e.ctx.Done():
				return
			case <-time.After(200 * time.Millisecond):
			}
		}
		stream, err := e.ClaimReverseStream(5 * time.Second)
		if err != nil {
			select {
			case <-e.ctx.Done():
				return
			case <-time.After(500 * time.Millisecond):
				continue
			}
		}
		_ = stream.SetWriteDeadline(time.Now().Add(3 * time.Second))
		if err := routing.WriteRoutingHeader(stream, routing.RouteProtoTUN, 0); err != nil {
			_ = stream.Close()
			continue
		}
		_ = stream.SetWriteDeadline(time.Time{})
		e.runL3StreamDuplex(stream)
	}
}

func (e *Engine) runL3StreamDuplex(conn net.Conn) {
	e.mu.Lock()
	tunDev := e.l3TunDev
	e.mu.Unlock()
	if tunDev == nil {
		_ = conn.Close()
		return
	}
	e.activeStreams.Store(conn, struct{}{})
	defer func() {
		_ = conn.Close()
		e.activeStreams.Delete(conn)
	}()

	var writeMu sync.Mutex
	tunDev.SetSender(func(wire []byte) error {
		if len(wire) > 65535 {
			return errors.New("l3-stream: packet exceeds max frame size")
		}
		frame := make([]byte, 2+len(wire))
		binary.BigEndian.PutUint16(frame[:2], uint16(len(wire)))
		copy(frame[2:], wire)
		e.Stats.AddUpload(int64(len(wire)))
		writeMu.Lock()
		_, err := conn.Write(frame)
		writeMu.Unlock()
		return err
	})

	var lenBuf [2]byte
	for {
		if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
			return
		}
		pktLen := int(binary.BigEndian.Uint16(lenBuf[:]))
		if pktLen <= 0 || pktLen > 65535 {
			return
		}
		wire := make([]byte, pktLen)
		if _, err := io.ReadFull(conn, wire); err != nil {
			return
		}
		e.Stats.AddDownload(int64(pktLen))
		_ = tunDev.InjectWirePacket(wire)
	}
}

func (e *Engine) serveMuxSession(rawConn net.Conn) {
	e.bindL3TUNDuplex(rawConn)
	muxSess := transport.NewMuxSession(rawConn, false)
	e.acceptedMuxSess.Store(muxSess, struct{}{})
	defer func() {
		e.acceptedMuxSess.Delete(muxSess)
		_ = muxSess.Close()
	}()
	for {
		stream, err := muxSess.AcceptStream()
		if err != nil {
			return
		}
		if !e.alive.Load() {
			_ = stream.Close()
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

	case "tcp", "tcpmux", "l3-tcp":
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
		isAllowedPeer := e.isAllowedCarrierPeer(rawConn.RemoteAddr())
		action, inspectedConn, err := transport.InspectRealityTraffic(rawConn, e.cfg.SNI, e.cfg.Password, hasUserFwd, isAllowedPeer)
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

	e.tcpForwarderMap.Store(listenPort, ln)

	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		defer func() {
			_ = ln.Close()
			e.tcpForwarderMap.Delete(listenPort)
		}()
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

func (e *Engine) startUDPForwarderListener(listenIP string, listenPort, targetPort int, gamingMode bool) error {
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

	e.udpForwarderMap.Store(listenPort, udpConn)

	routing.StartUDPListenerLoop(e.ctx, udpConn, targetPort, e.ClaimReverseStream, e.Stats, gamingMode)
	return nil
}

// UpdateForwarders updates active forwarder listeners in-place without restarting carrier listeners or pools.
func (e *Engine) UpdateForwarders(newRules []routing.ForwarderRule) error {
	if !e.alive.Load() {
		return errors.New("cannot update forwarders on stopped engine")
	}

	desiredTCP := make(map[int]int) // listenPort -> targetPort
	desiredUDP := make(map[int]struct {
		targetPort int
		gamingMode bool
		listenIP   string
	})

	for _, rule := range newRules {
		pairs := routing.ExpandPortRange(rule)
		for _, pair := range pairs {
			lPort := pair[0]
			tPort := pair[1]
			proto := strings.ToLower(rule.Protocol)
			if proto == "tcp" || proto == "tcp,udp" || proto == "both" || proto == "" {
				desiredTCP[lPort] = tPort
			}
			if proto == "udp" || proto == "tcp,udp" || proto == "both" {
				desiredUDP[lPort] = struct {
					targetPort int
					gamingMode bool
					listenIP   string
				}{
					targetPort: tPort,
					gamingMode: rule.GamingMode,
					listenIP:   rule.ListenIP,
				}
			}
		}
	}

	// 1. Reconcile TCP listeners
	e.tcpForwarderMap.Range(func(key, val any) bool {
		port := key.(int)
		ln := val.(net.Listener)
		if _, exists := desiredTCP[port]; !exists {
			e.logger.WithField("port", port).Info("[Relay] Closing removed TCP forwarder listener")
			_ = ln.Close()
			e.tcpForwarderMap.Delete(port)
		}
		return true
	})
	for lPort, tPort := range desiredTCP {
		if _, exists := e.tcpForwarderMap.Load(lPort); !exists {
			e.logger.WithFields(log.Fields{"listenPort": lPort, "targetPort": tPort}).Info("[Relay] Binding new TCP forwarder listener")
			_ = e.startTCPForwarderListener("0.0.0.0", lPort, tPort)
		}
	}

	// 2. Reconcile UDP listeners
	e.udpForwarderMap.Range(func(key, val any) bool {
		port := key.(int)
		uConn := val.(*net.UDPConn)
		if _, exists := desiredUDP[port]; !exists {
			e.logger.WithField("port", port).Info("[Relay] Closing removed UDP forwarder listener")
			_ = uConn.Close()
			e.udpForwarderMap.Delete(port)
		}
		return true
	})
	for lPort, cfg := range desiredUDP {
		if _, exists := e.udpForwarderMap.Load(lPort); !exists {
			e.logger.WithFields(log.Fields{"listenPort": lPort, "targetPort": cfg.targetPort, "gaming": cfg.gamingMode}).Info("[Relay] Binding new UDP forwarder listener")
			_ = e.startUDPForwarderListener(cfg.listenIP, lPort, cfg.targetPort, cfg.gamingMode)
		}
	}

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
	if e.cfg.TunnelID >= 1000 {
		return // Suppress benchmark candidate dial errors while waiting for Entry to open port
	}
	now := time.Now().Unix()
	last := e.lastDialLog.Load()
	if now-last >= 10 {
		if e.lastDialLog.CompareAndSwap(last, now) {
			if e.isL3DirectTUNMode() {
				e.logger.WithFields(log.Fields{
					"tunPeer":   net.JoinHostPort(e.l3TunDev.PeerIP(), "1234"),
					"transport": e.cfg.Transport,
					"entryIP":   e.cfg.EntryServerIP,
					"err":       err,
				}).Warn("[Relay] Exit node waiting for L3 TUN private IP response (check raw protocol connectivity)")
				return
			}
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
	tickDuration := 500 * time.Millisecond
	if e.cfg.TunnelID >= 1000 {
		// Benchmark sandbox instances: fast 250ms ticker so probe phases never starve
		tickDuration = 250 * time.Millisecond
	}
	ticker := time.NewTicker(tickDuration)
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
			if !e.alive.Load() {
				_ = stream.Close()
				return
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

		// Active stream liveness sweep & 30-minute anti-throttling rotation:
		// 1. Actively check if any idle reverse connection has died (closing it triggers redial immediately).
		// 2. Rotate connections older than 30 minutes so Iranian DPI firewalls never observe an
		// indefinitely long-lived flow and apply traffic-shaping or rate-limiting.
		if !e.isDirect() {
			now := time.Now()
			e.idleStreams.Range(func(key, val any) bool {
				conn, ok := key.(net.Conn)
				created, cOk := val.(time.Time)
				if ok {
					isDead := !transport.IsStreamAlive(conn)
					isAged := cOk && now.Sub(created) > 30*time.Minute
					if isDead || isAged {
						_ = conn.Close()
						e.idleStreams.Delete(key)
					}
				}
				return true
			})
		}

		minHeld := int64(e.cfg.MinHeldConnections)
		var current int64
		if e.isDirect() {
			current = e.Stats.PoolIdleConnections.Load() + dialingCount.Load()
		} else {
			current = e.idleWaiters.Load() + dialingCount.Load()
		}
		needed := minHeld - current
		if needed > 0 {
			for i := int64(0); i < needed; i++ {
				spawnDial()
			}
		}
	}
}

func (e *Engine) dialCarrierStream() (net.Conn, error) {
	if e.isL3DirectTUNMode() {
		privTarget := net.JoinHostPort(e.l3TunDev.PeerIP(), "1234")
		tunLocalIP := strings.Split(e.l3TunDev.LocalIP(), "/")[0]
		rawDial := func() (net.Conn, error) {
			return transport.DialTCPContextWithLocal(e.ctx, tunLocalIP, privTarget, 4*time.Second)
		}
		return transport.DialTCPCarrier(rawDial, e.cfg.Password)
	}
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
	e.dialSessMu.Lock()
	defer e.dialSessMu.Unlock()

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
		if e.activeMuxSess == muxSess {
			e.activeMuxSess = nil
		}
		e.mu.Unlock()
		baseConn, bErr := e.dialSingleCarrier()
		if bErr != nil {
			return nil, bErr
		}
		e.bindL3TUNDuplex(baseConn)
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

	e.dialSessMu.Lock()
	defer e.dialSessMu.Unlock()

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
		if e.activeQuicConn == qConn {
			e.activeQuicConn = nil
		}
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
			return transport.DialPCKCarrier(e.ctx, addr, e.cfg.Password, e.cfg.CarrierPort)
		case "l3-bip":
			return transport.DialBIPCarrier(e.ctx, addr, e.cfg.Password, e.cfg.CarrierPort)
		case "l3-ipip":
			return transport.DialIPIPCarrier(e.ctx, addr, e.cfg.Password, e.cfg.CarrierPort)
		case "l3-gre":
			return transport.DialGRECarrier(e.ctx, addr, e.cfg.Password, e.cfg.CarrierPort)
		case "spoof":
			spoofOpts := transport.SpoofOptions{
				SrcIP:       e.cfg.SpoofSrcIP,
				SrcPool:     e.cfg.SpoofSrcPool,
				PeerSrcIP:   e.cfg.SpoofPeerSrcIP,
				Profile:     e.cfg.SpoofProfile,
				Uplink:      e.cfg.SpoofUplink,
				Downlink:    e.cfg.SpoofDownlink,
				FakeTLS:     e.cfg.SpoofFakeTLS,
				TTLJitter:   e.cfg.SpoofTTLJitter,
				RandomDSCP:  e.cfg.SpoofRandomDSCP,
				ShufflePort: e.cfg.SpoofShufflePort,
				PortMin:     uint16(e.cfg.SpoofPortMin),
				PortMax:     uint16(e.cfg.SpoofPortMax),
				Padding:     e.cfg.SpoofPadding,
				PaddingMax:  uint8(e.cfg.SpoofPaddingMax),
				Interface:   e.cfg.SpoofInterface,
			}
			return transport.DialSpoofCarrier(e.ctx, addr, e.cfg.Password, spoofOpts, e.cfg.CarrierPort)
		default:
			useFEC := e.cfg.Transport == "kcp"
			return transport.DialUDPCarrier(e.ctx, addr, e.cfg.Password, useFEC)
		}
	}

	rawDial := func() (net.Conn, error) {
		dialTCP := func(ctx context.Context, idx int) (net.Conn, error) {
			ip := candidates[idx%len(candidates)]
			addr := net.JoinHostPort(ip, strconv.Itoa(e.cfg.CarrierPort))
			return transport.DialTCPContextWithLocal(ctx, e.cfg.DialSourceIP, addr, 4*time.Second)
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
	case "tcp", "tcpmux", "l3-tcp":
		return transport.DialTCPCarrier(rawDial, e.cfg.Password)
	case "stealth":
		return transport.DialStealthCarrier(rawDial, e.cfg.Password)
	case "ws-reverse", "wsmux":
		return transport.DialWSCarrier(rawDial, false, e.cfg.SNI, e.cfg.Password, e.cfg.WSPath)
	case "wss-reverse", "wssmux":
		return transport.DialWSCarrier(rawDial, true, e.cfg.SNI, e.cfg.Password, e.cfg.WSPath)
	default:
		return transport.DialRealityCarrier(rawDial, e.cfg.SNI, e.cfg.Password)
	}
}

func (e *Engine) targetDialIPs() []string {
	if e.cfg.EdgeIP != "" && (e.cfg.Transport == "ws-reverse" || e.cfg.Transport == "wss-reverse" || e.cfg.Transport == "wsmux" || e.cfg.Transport == "wssmux") {
		return []string{e.cfg.EdgeIP}
	}
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

// isAllowedCarrierPeer checks whether the connecting peer IP matches the authorized peer server.
// For Reverse mode (Entry listener), it ensures only the Kharej Exit node can authenticate into
// the reverse carrier pool; any other IP (active DPI scanner, probe) is deflected to the decoy origin.
func (e *Engine) isAllowedCarrierPeer(remoteAddr net.Addr) bool {
	if remoteAddr == nil {
		return false
	}
	host, _, err := net.SplitHostPort(remoteAddr.String())
	if err != nil {
		host = remoteAddr.String()
	}
	if parsedIP := net.ParseIP(host); parsedIP != nil {
		if v4 := parsedIP.To4(); v4 != nil {
			host = v4.String()
		}
	}
	if host == "127.0.0.1" || host == "::1" || host == "localhost" {
		return true
	}
	expectedIP := e.cfg.ExitServerIP
	if e.isDirect() {
		expectedIP = e.cfg.EntryServerIP
	}
	if expectedIP == "" && len(e.cfg.FloatingIPs) == 0 {
		return true
	}
	if expectedIP != "" && host == expectedIP {
		return true
	}
	for _, fip := range e.cfg.FloatingIPs {
		if strings.TrimSpace(fip) == host {
			return true
		}
	}
	return false
}

func (e *Engine) serveExitStream(stream net.Conn) {
	defer e.wg.Done()

	now := time.Now()
	e.activeStreams.Store(stream, struct{}{})
	e.idleStreams.Store(stream, now)
	defer e.activeStreams.Delete(stream)
	defer e.idleStreams.Delete(stream)

	e.idleWaiters.Add(1)
	idleCount := e.Stats.PoolIdleConnections.Add(1)
	if idleCount == 1 {
		e.logger.WithFields(log.Fields{
			"carrierPort": e.cfg.CarrierPort,
			"sni":         e.cfg.SNI,
		}).Info("[Relay] Exit reverse carrier connected and warm connections ready in pool")
	}

	_ = stream.SetReadDeadline(time.Now().Add(60 * time.Second))
	proto, targetPort, err := routing.ReadRoutingHeader(stream)
	_ = stream.SetReadDeadline(time.Time{})

	e.idleStreams.Delete(stream)
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
		routing.HandleExitUDPForward(stream, e.cfg.TargetIP, targetPort, e.Stats, false)
	case routing.RouteProtoUDPGaming:
		routing.HandleExitUDPForward(stream, e.cfg.TargetIP, targetPort, e.Stats, true)
	case routing.RouteProtoTUN:
		e.runL3StreamDuplex(stream)
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

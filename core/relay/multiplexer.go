package relay

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/archnets/node/core/relay/routing"
	"github.com/archnets/node/core/relay/telemetry"
	"github.com/archnets/node/core/relay/transport"
	log "github.com/sirupsen/logrus"
)

var (
	sharedMultiMu   sync.Mutex
	sharedListeners = make(map[int]*CarrierPortDemuxer)
)

// DemuxTarget holds registration info for a tunnel engine attached to a shared carrier port.
type DemuxTarget struct {
	TunnelID     int
	ExitServerIP string
	FloatingIPs  []string
	Transport    string
	Password     string
	SNI          string
	OriginIP     string
	WSPath       string
	TargetFwd    int64
	Handler      func(net.Conn)
	UserFwdFn    func(net.Conn, uint16)
}

func (t *DemuxTarget) matchesPeerIP(peerIP string) bool {
	if peerIP == "" {
		return false
	}
	if t.ExitServerIP != "" && t.ExitServerIP == peerIP {
		return true
	}
	for _, fip := range t.FloatingIPs {
		if strings.TrimSpace(fip) == peerIP {
			return true
		}
	}
	return false
}

// CarrierPortDemuxer manages a single master OS listener on a given port (e.g. 443)
// and multiplexes incoming carrier connections across multiple registered tunnel engines.
type CarrierPortDemuxer struct {
	port      int
	ln        net.Listener
	ctx       context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup
	mu        sync.RWMutex
	targets   map[int]*DemuxTarget // tunnelID -> target
	logger    *log.Entry
}

func newCarrierPortDemuxer(ctx context.Context, listenIP string, port int, logger *log.Entry) (*CarrierPortDemuxer, error) {
	if listenIP == "" {
		listenIP = "0.0.0.0"
	}
	addr := net.JoinHostPort(listenIP, strconv.Itoa(port))
	cCtx, cancel := context.WithCancel(ctx)

	ln, err := transport.ListenTCP(cCtx, addr)
	if err != nil {
		if transport.ReclaimPortIfOrphanedNode(port) {
			time.Sleep(300 * time.Millisecond)
			ln, err = transport.ListenTCP(cCtx, addr)
		}
	}
	if err != nil {
		cancel()
		return nil, transport.FormatPortConflictError(port, err)
	}

	d := &CarrierPortDemuxer{
		port:    port,
		ln:      ln,
		ctx:     cCtx,
		cancel:  cancel,
		targets: make(map[int]*DemuxTarget),
		logger:  logger.WithField("sharedCarrierPort", port),
	}

	d.logger.WithField("addr", addr).Info("[Relay] Shared Carrier Port Master Listener started")
	d.wg.Add(1)
	go d.acceptLoop()

	return d, nil
}

func (d *CarrierPortDemuxer) addTarget(t *DemuxTarget) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.targets[t.TunnelID] = t
	d.logger.WithFields(log.Fields{
		"tunnelID":     t.TunnelID,
		"exitServerIP": t.ExitServerIP,
		"totalTunnels": len(d.targets),
	}).Info("[Relay] Registered tunnel with shared carrier port demultiplexer")
}

func (d *CarrierPortDemuxer) removeTarget(tunnelID int) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.targets, tunnelID)
	count := len(d.targets)
	d.logger.WithFields(log.Fields{
		"tunnelID":     tunnelID,
		"totalTunnels": count,
	}).Info("[Relay] Unregistered tunnel from shared carrier port demultiplexer")
	return count
}

func (d *CarrierPortDemuxer) close() {
	d.cancel()
	_ = d.ln.Close()
	d.wg.Wait()
}

func (d *CarrierPortDemuxer) acceptLoop() {
	defer d.wg.Done()
	for {
		conn, err := d.ln.Accept()
		if err != nil {
			select {
			case <-d.ctx.Done():
				return
			default:
				continue
			}
		}
		go d.dispatchConnection(conn)
	}
}

func extractPeerIPv4(remoteAddr net.Addr) string {
	if remoteAddr == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(remoteAddr.String())
	if err != nil {
		host = remoteAddr.String()
	}
	if parsed := net.ParseIP(host); parsed != nil {
		if v4 := parsed.To4(); v4 != nil {
			return v4.String()
		}
		return parsed.String()
	}
	return host
}

func (d *CarrierPortDemuxer) dispatchConnection(conn net.Conn) {
	peerIP := extractPeerIPv4(conn.RemoteAddr())

	d.mu.RLock()
	// Fast path: if only one tunnel is registered on this port, dispatch directly with zero overhead
	if len(d.targets) == 1 {
		for _, target := range d.targets {
			d.mu.RUnlock()
			target.Handler(conn)
			return
		}
	}

	// ─── Tier 1: L4 Fast Path (Instant Peer IP Match across multiple tunnels) ─
	// In under 1 microsecond without reading any payload bytes:
	for _, target := range d.targets {
		if target.matchesPeerIP(peerIP) {
			d.mu.RUnlock()
			target.Handler(conn)
			return
		}
	}

	// Capture targets snapshot for Tier 2 inspection
	snapshot := make([]*DemuxTarget, 0, len(d.targets))
	for _, t := range d.targets {
		snapshot = append(snapshot, t)
	}
	d.mu.RUnlock()

	// ─── Tier 2: L7 Deep Inspection (For Dynamic / Floating IPs) ───────────
	transport.TuneTCPConn(conn)
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	var hdr [5]byte
	nHdr, err := io.ReadFull(conn, hdr[:])
	if err != nil {
		_ = conn.Close()
		return
	}

	recLen := int(binary.BigEndian.Uint16(hdr[3:5]))
	var captured []byte

	// 1. Check if TLS Record (0x16 Handshake)
	if hdr[0] == 0x16 && recLen >= 42 && recLen <= 16384 {
		body := make([]byte, recLen)
		nBody, bErr := io.ReadFull(conn, body)
		if bErr != nil {
			_ = conn.Close()
			return
		}
		captured = make([]byte, 5+recLen)
		copy(captured[0:5], hdr[:])
		copy(captured[5:], body[:nBody])

		// Reality ClientHello inspection: body[0] == 0x01 (ClientHello), body[6:38] is ClientRandom token
		if body[0] == 0x01 && len(body) >= 38 {
			token := body[6:38]
			for _, target := range snapshot {
				if target.Transport == "reverse-reality" || target.Transport == "" {
					key, keyErr := transport.DeriveRealityKey(target.Password, target.SNI)
					if keyErr == nil && transport.VerifyRealityToken(key, token, "ARRT") {
						// Matched Reality tunnel by authentication secret!
						_ = conn.SetDeadline(time.Time{})
						pConn := transport.NewPrefixConn(conn, captured)
						target.Handler(pConn)
						return
					}
				}
			}
		}
	} else {
		// Not TLS (could be HTTP/WebSocket: "GET /...", "POST", Socks, etc.)
		captured = make([]byte, nHdr)
		copy(captured, hdr[:nHdr])

		// Check for WebSocket Path match
		peekBuf := make([]byte, 1024)
		nPeek, _ := conn.Read(peekBuf)
		if nPeek > 0 {
			fullCaptured := append(captured, peekBuf[:nPeek]...)
			reqStr := string(fullCaptured)
			for _, target := range snapshot {
				if target.WSPath != "" && strings.Contains(reqStr, target.WSPath) {
					_ = conn.SetDeadline(time.Time{})
					pConn := transport.NewPrefixConn(conn, fullCaptured)
					target.Handler(pConn)
					return
				}
			}
			captured = fullCaptured
		}
	}

	_ = conn.SetDeadline(time.Time{})
	prefixConn := transport.NewPrefixConn(conn, captured)

	// ─── Fallback: User Forwarder or Camouflage Deflection ─────────────────
	for _, target := range snapshot {
		if target.TargetFwd > 0 && target.UserFwdFn != nil {
			target.UserFwdFn(prefixConn, uint16(target.TargetFwd))
			return
		}
	}

	// Active DPI Probe / unknown scanner: splice to first camouflage origin
	originAddr := ""
	for _, target := range snapshot {
		if target.OriginIP != "" {
			originAddr = target.OriginIP
			break
		}
		if target.SNI != "" {
			if resolved, rErr := telemetry.ResolveOriginIP(target.SNI, ""); rErr == nil {
				originAddr = resolved
				break
			}
		}
	}
	if originAddr != "" {
		go transport.SpliceToOrigin(prefixConn, originAddr)
	} else {
		_ = prefixConn.Close()
	}
}

// RegisterSharedCarrier attaches a tunnel engine to a shared carrier port master listener.
func RegisterSharedCarrier(ctx context.Context, listenIP string, cfg Config, handler func(net.Conn), userFwdFn func(net.Conn, uint16)) error {
	sharedMultiMu.Lock()
	defer sharedMultiMu.Unlock()

	demuxer, exists := sharedListeners[cfg.CarrierPort]
	if !exists {
		var err error
		demuxer, err = newCarrierPortDemuxer(ctx, listenIP, cfg.CarrierPort, cfg.Logger)
		if err != nil {
			return err
		}
		sharedListeners[cfg.CarrierPort] = demuxer
	}

	var targetFwd int64
	for _, rule := range cfg.Forwarders {
		pairs := routing.ExpandPortRange(rule)
		proto := strings.ToLower(strings.TrimSpace(rule.Protocol))
		for _, pair := range pairs {
			if pair[0] == cfg.CarrierPort && (proto == "tcp" || proto == "tcp,udp" || proto == "both") {
				targetFwd = int64(pair[1])
				break
			}
		}
	}

	target := &DemuxTarget{
		TunnelID:     cfg.TunnelID,
		ExitServerIP: cfg.ExitServerIP,
		FloatingIPs:  cfg.FloatingIPs,
		Transport:    cfg.Transport,
		Password:     cfg.Password,
		SNI:          cfg.SNI,
		OriginIP:     cfg.OriginIP,
		WSPath:       cfg.WSPath,
		TargetFwd:    targetFwd,
		Handler:      handler,
		UserFwdFn:    userFwdFn,
	}

	demuxer.addTarget(target)
	return nil
}

// UnregisterSharedCarrier removes a tunnel engine from a shared carrier port.
// If no tunnels remain on that port, the master listener is cleanly closed.
func UnregisterSharedCarrier(tunnelID, carrierPort int) {
	sharedMultiMu.Lock()
	defer sharedMultiMu.Unlock()

	demuxer, exists := sharedListeners[carrierPort]
	if !exists {
		return
	}

	remaining := demuxer.removeTarget(tunnelID)
	if remaining == 0 {
		demuxer.close()
		delete(sharedListeners, carrierPort)
	}
}

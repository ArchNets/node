package routing

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/archnets/node/core/relay/telemetry"
	"github.com/archnets/node/core/relay/transport"
	log "github.com/sirupsen/logrus"
)

// udpFramePool manages reusable buffers (up to 2048 bytes) for low-latency game packets,
// preventing garbage collector pauses during high-frequency 128-tick game traffic.
var udpFramePool = sync.Pool{
	New: func() any {
		b := make([]byte, 2048)
		return &b
	},
}

func getUDPFrameBuffer(needed int) []byte {
	if needed <= 2048 {
		bufPtr := udpFramePool.Get().(*[]byte)
		return (*bufPtr)[:needed]
	}
	return make([]byte, needed)
}

func putUDPFrameBuffer(b []byte) {
	if cap(b) >= 2048 {
		b = b[:2048]
		udpFramePool.Put(&b)
	}
}

const (
	UDPSessionIdleTime       = 60 * time.Second
	UDPGamingSessionIdleTime = 5 * time.Minute
	UDPLongSessionIdleTime   = 5 * time.Minute
)

func isLongIdleUDPPort(targetPort int) bool {
	return targetPort == 500 || targetPort == 4500 || targetPort == 1701
}

func udpSessionIdleTimeout(gamingMode bool, targetPort int) time.Duration {
	if gamingMode || isLongIdleUDPPort(targetPort) {
		return UDPGamingSessionIdleTime
	}
	return UDPSessionIdleTime
}

type UDPSession struct {
	Stream     net.Conn
	StreamTwin net.Conn
	ClientAddr *net.UDPAddr
	lastActive atomic.Int64
	WriteMu    sync.Mutex
	gamingSeq  atomic.Uint32
	rxDedup    udpSeqDeduplicator
	gate       *FlowGate
}

// udpSeqDeduplicator prevents duplicate packet delivery when twin streams receive the same packet.
type udpSeqDeduplicator struct {
	mu      sync.Mutex
	highest uint32
	window  [16]uint64
	init    bool
}

func (d *udpSeqDeduplicator) checkAndRecord(seq uint32) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.init {
		d.highest = seq
		d.window[0] = 1
		d.init = true
		return true
	}
	diff := int32(seq - d.highest)
	if diff > 0 {
		uDiff := uint32(diff)
		if uDiff >= 1024 {
			clear(d.window[:])
		} else {
			shiftWords := int(uDiff / 64)
			shiftBits := uint(uDiff % 64)
			for i := len(d.window) - 1; i >= 0; i-- {
				var next uint64
				if i >= shiftWords {
					next = d.window[i-shiftWords] << shiftBits
					if shiftBits > 0 && i > shiftWords {
						next |= d.window[i-shiftWords-1] >> (64 - shiftBits)
					}
				}
				d.window[i] = next
			}
		}
		d.highest = seq
		d.window[0] |= 1
		return true
	}
	gap := uint32(-diff)
	if gap >= 1024 {
		return false
	}
	word := gap / 64
	bit := uint(gap % 64)
	if (d.window[word] & (uint64(1) << bit)) != 0 {
		return false
	}
	d.window[word] |= (uint64(1) << bit)
	return true
}

// StartL3DirectUDPForwarder forwards client UDP datagrams directly over the virtual L3 TUN interface
// to tunPeerIP:targetPort without claiming any reverse pool TCP streams.
// This completely isolates game UDP traffic from port 443 web proxy congestion and eliminates TCP HOL blocking.
func StartL3DirectUDPForwarder(
	ctx context.Context,
	udpConn *net.UDPConn,
	tunLocalIP, tunPeerIP string,
	targetPort int,
	stats *telemetry.Stats,
	gamingMode bool,
	ruleOpt ...*ForwarderRule,
) {
	if gamingMode {
		_ = udpConn.SetReadBuffer(8 * 1024 * 1024)
		_ = udpConn.SetWriteBuffer(8 * 1024 * 1024)
		transport.SetSocketQoS(udpConn)
	}

	var rule *ForwarderRule
	if len(ruleOpt) > 0 {
		rule = ruleOpt[0]
	}

	type directSess struct {
		tunConn    *net.UDPConn
		clientAddr *net.UDPAddr
		lastActive atomic.Int64
		gate       *FlowGate
	}

	var sessions sync.Map // key: string, value: *directSess

	loopCtx, loopCancel := context.WithCancel(ctx)
	const l3DirectIdleTimeout = 10 * time.Minute
	raddr := &net.UDPAddr{IP: net.ParseIP(tunPeerIP), Port: targetPort}
	laddr := &net.UDPAddr{IP: net.ParseIP(tunLocalIP), Port: 0}

	// Session idle reaper (10-minute timeout for stable gaming sessions)
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-loopCtx.Done():
				sessions.Range(func(k, v any) bool {
					_ = v.(*directSess).tunConn.Close()
					sessions.Delete(k)
					return true
				})
				return
			case <-ticker.C:
				now := time.Now().Unix()
				sessions.Range(func(k, v any) bool {
					s := v.(*directSess)
					if now-s.lastActive.Load() > int64(l3DirectIdleTimeout/time.Second) {
						_ = s.tunConn.Close()
						sessions.Delete(k)
					}
					return true
				})
			}
		}
	}()

	go func() {
		defer loopCancel()
		buf := make([]byte, 65536)
		for {
			n, clientAddr, err := udpConn.ReadFromUDP(buf)
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					return
				}
				select {
				case <-loopCtx.Done():
					return
				default:
					time.Sleep(5 * time.Millisecond)
					continue
				}
			}
			if n <= 0 || n > MaxUDPFrameSize {
				continue
			}

			key := clientAddr.String()
			val, exists := sessions.Load(key)
			var sess *directSess
			if exists {
				sess = val.(*directSess)
			} else {
				tunUDP, dErr := net.DialUDP("udp", laddr, raddr)
				if dErr != nil {
					log.WithFields(log.Fields{
						"target": raddr.String(),
						"err":    dErr,
					}).Warn("[Relay] Direct L3 UDP dial to peer failed")
					continue
				}
				_ = tunUDP.SetReadBuffer(8 * 1024 * 1024)
				_ = tunUDP.SetWriteBuffer(8 * 1024 * 1024)
				if gamingMode {
					transport.SetSocketQoS(tunUDP)
				}

				addrCopy := *clientAddr
				var gate *FlowGate
				if rule != nil && rule.FlowMode != "" && rule.FlowMode != "bidirectional" {
					gate = NewFlowGate(*rule)
					logGateActivationOnce(targetPort, rule.FlowMode)
				}
				sess = &directSess{
					tunConn:    tunUDP,
					clientAddr: &addrCopy,
					gate:       gate,
				}
				sess.lastActive.Store(time.Now().Unix())

				actual, loaded := sessions.LoadOrStore(key, sess)
				if loaded {
					_ = tunUDP.Close()
					sess = actual.(*directSess)
				} else {
					// Downlink reader: from peer on TUN interface -> back to client
					go func(k string, s *directSess) {
						if stats != nil {
							stats.ActiveConnections.Add(1)
							defer stats.ActiveConnections.Add(-1)
						}
						defer func() {
							_ = s.tunConn.Close()
							sessions.Delete(k)
						}()

						downBuf := make([]byte, 65536)
						for {
							_ = s.tunConn.SetReadDeadline(time.Now().Add(l3DirectIdleTimeout))
							nr, rErr := s.tunConn.Read(downBuf)
							if rErr != nil {
								if netErr, ok := rErr.(net.Error); ok && netErr.Timeout() {
									if time.Now().Unix()-s.lastActive.Load() > int64(l3DirectIdleTimeout/time.Second) {
										return
									}
									continue
								}
								return
							}
							if nr <= 0 {
								continue
							}
							if s.gate != nil {
								if rule.FlowMode == "upload_only" {
									allowed, closeS := s.gate.CheckUDPReverse(nr)
									if !allowed {
										if closeS {
											return
										}
										continue
									}
								} else if rule.FlowMode == "download_only" {
									s.gate.AddAllowed(nr)
								}
							}
							s.lastActive.Store(time.Now().Unix())
							if nw, wErr := udpConn.WriteToUDP(downBuf[:nr], s.clientAddr); wErr == nil && nw > 0 && stats != nil {
								stats.AddDownload(int64(nw))
							}
						}
					}(key, sess)
				}
			}

			if sess.gate != nil {
				if rule.FlowMode == "download_only" {
					allowed, closeS := sess.gate.CheckUDPReverse(n)
					if !allowed {
						if closeS {
							_ = sess.tunConn.Close()
						}
						continue
					}
				} else if rule.FlowMode == "upload_only" {
					sess.gate.AddAllowed(n)
				}
			}
			sess.lastActive.Store(time.Now().Unix())
			if nw, wErr := sess.tunConn.Write(buf[:n]); wErr == nil && nw > 0 && stats != nil {
				stats.AddUpload(int64(nw))
			}
		}
	}()
}

// StartUDPListenerLoop binds UDP listener on Entry and frames datagrams over claimed streams.
func StartUDPListenerLoop(
	ctx context.Context,
	udpConn *net.UDPConn,
	targetPort int,
	claimStreamFn func(timeout time.Duration) (net.Conn, error),
	stats *telemetry.Stats,
	gamingMode bool,
	ruleOpt ...*ForwarderRule,
) {
	if gamingMode {
		_ = udpConn.SetReadBuffer(4 * 1024 * 1024)
		_ = udpConn.SetWriteBuffer(4 * 1024 * 1024)
		transport.SetSocketQoS(udpConn)
	}
	var rule *ForwarderRule
	if len(ruleOpt) > 0 {
		rule = ruleOpt[0]
	}
	var sessionsMu sync.Mutex
	sessions := make(map[string]*UDPSession)
	inflight := make(map[string]struct{})
	loopCtx, loopCancel := context.WithCancel(ctx)

	idleTimeout := udpSessionIdleTimeout(gamingMode, targetPort)
	// Session idle reaper
	go func() {
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-loopCtx.Done():
				sessionsMu.Lock()
				for k, s := range sessions {
					s.WriteMu.Lock()
					if s.Stream != nil {
						_ = s.Stream.Close()
					}
					if s.StreamTwin != nil {
						_ = s.StreamTwin.Close()
					}
					s.WriteMu.Unlock()
					delete(sessions, k)
				}
				sessionsMu.Unlock()
				return
			case <-ticker.C:
				now := time.Now()
				sessionsMu.Lock()
				for k, s := range sessions {
					if now.Unix()-s.lastActive.Load() > int64(idleTimeout/time.Second) {
						s.WriteMu.Lock()
						if s.Stream != nil {
							_ = s.Stream.Close()
						}
						if s.StreamTwin != nil {
							_ = s.StreamTwin.Close()
						}
						s.WriteMu.Unlock()
						delete(sessions, k)
					}
				}
				sessionsMu.Unlock()
			}
		}
	}()

	// Read loop
	go func() {
		defer loopCancel()
		buf := make([]byte, 65536)
		for {
			n, clientAddr, err := udpConn.ReadFromUDP(buf)
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					return
				}
				select {
				case <-loopCtx.Done():
					return
				default:
					time.Sleep(5 * time.Millisecond)
					continue
				}
			}
			if n <= 0 || n > MaxUDPFrameSize {
				continue
			}

			key := clientAddr.String()
			sessionsMu.Lock()
			sess, exists := sessions[key]
			_, claiming := inflight[key]
			if !exists && !claiming {
				inflight[key] = struct{}{}
			}
			sessionsMu.Unlock()

			if !exists {
				if claiming {
					// Another goroutine is already claiming a stream for this clientAddr; skip duplicate claim
					continue
				}
				stream, claimErr := claimStreamFn(3 * time.Second)
				if claimErr != nil {
					sessionsMu.Lock()
					delete(inflight, key)
					sessionsMu.Unlock()
					log.WithFields(log.Fields{
						"targetPort": targetPort,
						"client":     clientAddr.String(),
						"err":        claimErr,
					}).Warn("[Relay] Client UDP packet dropped: reverse pool is empty (waiting for Exit server to connect)")
					continue
				}
				transport.TuneTCPConn(stream)
				if gamingMode {
					transport.SetSocketQoS(stream)
				}
				_ = stream.SetWriteDeadline(time.Now().Add(3 * time.Second))
				proto := RouteProtoUDP
				if gamingMode {
					proto = RouteProtoUDPGaming
				}
				if err := WriteRoutingHeader(stream, proto, uint16(targetPort)); err != nil {
					sessionsMu.Lock()
					delete(inflight, key)
					sessionsMu.Unlock()
					_ = stream.Close()
					continue
				}
				var sessKey [8]byte
				if gamingMode {
					_, _ = rand.Read(sessKey[:])
					if _, err := stream.Write(sessKey[:]); err != nil {
						sessionsMu.Lock()
						delete(inflight, key)
						sessionsMu.Unlock()
						_ = stream.Close()
						continue
					}
				}
				_ = stream.SetWriteDeadline(time.Time{})

				addrCopy := *clientAddr
				var gate *FlowGate
				if rule != nil && rule.FlowMode == "download_only" {
					gate = NewFlowGate(*rule)
					logGateActivationOnce(targetPort, rule.FlowMode)
				}
				sess = &UDPSession{
					Stream:     stream,
					ClientAddr: &addrCopy,
					gate:       gate,
				}
				sess.lastActive.Store(time.Now().Unix())

				if gamingMode {
					// Attempt to claim twin stream for multi-path anti-jitter replication
					if twin, tErr := claimStreamFn(500 * time.Millisecond); tErr == nil && twin != nil {
						transport.TuneTCPConn(twin)
						transport.SetSocketQoS(twin)
						_ = twin.SetWriteDeadline(time.Now().Add(2 * time.Second))
						if err := WriteRoutingHeader(twin, RouteProtoUDPGaming, uint16(targetPort)); err == nil {
							if _, kErr := twin.Write(sessKey[:]); kErr == nil {
								_ = twin.SetWriteDeadline(time.Time{})
								sess.StreamTwin = twin
							} else {
								_ = twin.Close()
							}
						} else {
							_ = twin.Close()
						}
					}
				}

				primary := sess.Stream
				twin := sess.StreamTwin

				sessionsMu.Lock()
				delete(inflight, key)
				sessions[key] = sess
				sessionsMu.Unlock()

				pumpStream := func(st net.Conn) {
					if st == nil {
						return
					}
					var lenBuf [2]byte
					frameBuf := make([]byte, 65536)
					for {
						_ = st.SetReadDeadline(time.Now().Add(idleTimeout))
						if _, err := io.ReadFull(st, lenBuf[:]); err != nil {
							return
						}
						frameLen := int(binary.BigEndian.Uint16(lenBuf[:]))
						if frameLen == 0 || frameLen > MaxUDPFrameSize {
							return
						}
						if _, err := io.ReadFull(st, frameBuf[:frameLen]); err != nil {
							return
						}
						sess.lastActive.Store(time.Now().Unix())

						payload := frameBuf[:frameLen]
						if gamingMode && frameLen >= 4 {
							seq := binary.BigEndian.Uint32(payload[:4])
							if !sess.rxDedup.checkAndRecord(seq) {
								continue // Duplicate dropped; first arrival won!
							}
							payload = payload[4:]
						}

						if sess.gate != nil && rule.FlowMode == "download_only" {
							sess.gate.AddAllowed(len(payload))
						}

						if nw, err := udpConn.WriteToUDP(payload, sess.ClientAddr); err == nil && nw > 0 && stats != nil {
							stats.AddDownload(int64(nw))
						}
					}
				}

				go func(k string, s *UDPSession, primaryConn, twinConn net.Conn) {
					if stats != nil {
						stats.ActiveConnections.Add(1)
						defer stats.ActiveConnections.Add(-1)
					}
					defer func() {
						s.WriteMu.Lock()
						if s.Stream != nil {
							_ = s.Stream.Close()
						}
						if s.StreamTwin != nil {
							_ = s.StreamTwin.Close()
						}
						s.WriteMu.Unlock()
						sessionsMu.Lock()
						if sessions[k] == s {
							delete(sessions, k)
						}
						sessionsMu.Unlock()
					}()

					var pumpWG sync.WaitGroup
					if twinConn != nil {
						pumpWG.Add(1)
						go func() {
							defer pumpWG.Done()
							pumpStream(twinConn)
							_ = twinConn.Close()
						}()
					}
					pumpStream(primaryConn)
					if primaryConn != nil {
						_ = primaryConn.Close()
					}
					pumpWG.Wait()
				}(key, sess, primary, twin)
			}

			var frame []byte
			if gamingMode {
				seq := sess.gamingSeq.Add(1)
				frame = getUDPFrameBuffer(2 + 4 + n)
				binary.BigEndian.PutUint16(frame[0:2], uint16(4+n))
				binary.BigEndian.PutUint32(frame[2:6], seq)
				copy(frame[6:], buf[:n])
			} else {
				frame = getUDPFrameBuffer(2 + n)
				binary.BigEndian.PutUint16(frame[0:2], uint16(n))
				copy(frame[2:], buf[:n])
			}

			if sess.gate != nil && rule.FlowMode == "download_only" {
				allowed, closeS := sess.gate.CheckUDPReverse(n)
				if !allowed {
					if closeS {
						sess.WriteMu.Lock()
						if sess.Stream != nil {
							_ = sess.Stream.Close()
							sess.Stream = nil
						}
						if sess.StreamTwin != nil {
							_ = sess.StreamTwin.Close()
							sess.StreamTwin = nil
						}
						sess.WriteMu.Unlock()
					}
					putUDPFrameBuffer(frame)
					continue
				}
			}

			sess.WriteMu.Lock()
			sess.lastActive.Store(time.Now().Unix())
			writeTimeout := 2 * time.Second
			var wErr error
			wroteAny := false

			if sess.Stream != nil {
				_ = sess.Stream.SetWriteDeadline(time.Now().Add(writeTimeout))
				_, wErr = sess.Stream.Write(frame)
				_ = sess.Stream.SetWriteDeadline(time.Time{})
				if wErr != nil {
					_ = sess.Stream.Close()
					sess.Stream = nil
				} else {
					wroteAny = true
				}
			}

			if sess.StreamTwin != nil {
				_ = sess.StreamTwin.SetWriteDeadline(time.Now().Add(writeTimeout))
				_, twinErr := sess.StreamTwin.Write(frame)
				_ = sess.StreamTwin.SetWriteDeadline(time.Time{})
				if twinErr != nil {
					_ = sess.StreamTwin.Close()
					sess.StreamTwin = nil
				} else {
					wroteAny = true
				}
			}

			if sess.Stream == nil && sess.StreamTwin != nil {
				sess.Stream = sess.StreamTwin
				sess.StreamTwin = nil
			}
			allDead := sess.Stream == nil && sess.StreamTwin == nil
			sess.WriteMu.Unlock()
			putUDPFrameBuffer(frame)

			if allDead {
				sessionsMu.Lock()
				if sessions[key] == sess {
					delete(sessions, key)
				}
				sessionsMu.Unlock()
			} else if wroteAny && stats != nil {
				stats.AddUpload(int64(n))
			}
		}
	}()
}

type exitGamingSession struct {
	key       [8]byte
	udpConn   *net.UDPConn
	dedup     udpSeqDeduplicator
	txSeq     atomic.Uint32
	mu        sync.Mutex
	streams   []net.Conn
	closeOnce sync.Once
	gate      *FlowGate
}

var exitGamingSessMap sync.Map // [8]byte -> *exitGamingSession

func handleExitGamingUDPForward(stream net.Conn, targetIP string, targetPort uint16, stats *telemetry.Stats, ruleOpt ...*ForwarderRule) {
	defer stream.Close()

	var rule *ForwarderRule
	if len(ruleOpt) > 0 {
		rule = ruleOpt[0]
	}

	transport.TuneTCPConn(stream)
	transport.SetSocketQoS(stream)
	var sessKey [8]byte
	_ = stream.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(stream, sessKey[:]); err != nil {
		return
	}
	_ = stream.SetReadDeadline(time.Time{})

	var sess *exitGamingSession
	if val, ok := exitGamingSessMap.Load(sessKey); ok {
		sess = val.(*exitGamingSession)
		sess.mu.Lock()
		sess.streams = append(sess.streams, stream)
		sess.mu.Unlock()
	} else {
		if targetIP == "" {
			targetIP = "127.0.0.1"
		}
		raddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(targetIP, strconv.Itoa(int(targetPort))))
		if err != nil {
			return
		}
		udpConn, err := net.DialUDP("udp", nil, raddr)
		if err != nil {
			return
		}
		_ = udpConn.SetReadBuffer(4 * 1024 * 1024)
		_ = udpConn.SetWriteBuffer(4 * 1024 * 1024)
		transport.SetSocketQoS(udpConn)

		var gate *FlowGate
		if rule != nil && rule.FlowMode == "upload_only" {
			gate = NewFlowGate(*rule)
			logGateActivationOnce(int(targetPort), rule.FlowMode)
		}

		newSess := &exitGamingSession{
			key:     sessKey,
			udpConn: udpConn,
			streams: []net.Conn{stream},
			gate:    gate,
		}
		actual, loaded := exitGamingSessMap.LoadOrStore(sessKey, newSess)
		if loaded {
			_ = udpConn.Close()
			if gate != nil {
				gate.Close()
			}
			sess = actual.(*exitGamingSession)
			sess.mu.Lock()
			sess.streams = append(sess.streams, stream)
			sess.mu.Unlock()
		} else {
			sess = newSess
			// Start single downlink reader from target UDP service -> replicate to all active twin streams
			go func(gs *exitGamingSession) {
				defer func() {
					exitGamingSessMap.Delete(gs.key)
					_ = gs.udpConn.Close()
					if gs.gate != nil {
						gs.gate.Close()
					}
					gs.mu.Lock()
					for _, st := range gs.streams {
						_ = st.Close()
					}
					gs.mu.Unlock()
				}()
				buf := make([]byte, 65536)
				for {
					_ = gs.udpConn.SetReadDeadline(time.Now().Add(UDPGamingSessionIdleTime))
					n, rErr := gs.udpConn.Read(buf[6:])
					if rErr != nil {
						return
					}
					if n <= 0 || n > MaxUDPFrameSize {
						continue
					}
					if gs.gate != nil && rule.FlowMode == "upload_only" {
						allowed, closeS := gs.gate.CheckUDPReverse(n)
						if !allowed {
							if closeS {
								return
							}
							continue
						}
					}
					seq := gs.txSeq.Add(1)
					frame := getUDPFrameBuffer(6 + n)
					binary.BigEndian.PutUint16(frame[0:2], uint16(4+n))
					binary.BigEndian.PutUint32(frame[2:6], seq)
					copy(frame[6:], buf[6:6+n])

					gs.mu.Lock()
					activeCount := len(gs.streams)
					streamList := make([]net.Conn, activeCount)
					copy(streamList, gs.streams)
					gs.mu.Unlock()

					for _, st := range streamList {
						_ = st.SetWriteDeadline(time.Now().Add(2 * time.Second))
						_, wErr := st.Write(frame)
						_ = st.SetWriteDeadline(time.Time{})
						if wErr != nil {
							_ = st.Close()
						}
					}
					putUDPFrameBuffer(frame)

					if activeCount == 0 {
						return
					}
					if stats != nil {
						stats.AddDownload(int64(n))
					}
				}
			}(sess)
		}
	}

	if stats != nil {
		stats.ActiveConnections.Add(1)
		defer stats.ActiveConnections.Add(-1)
	}

	defer func() {
		sess.mu.Lock()
		for i, st := range sess.streams {
			if st == stream {
				sess.streams = append(sess.streams[:i], sess.streams[i+1:]...)
				break
			}
		}
		remaining := len(sess.streams)
		sess.mu.Unlock()
		if remaining == 0 {
			exitGamingSessMap.Delete(sess.key)
			_ = sess.udpConn.Close()
		}
	}()

	var lenBuf [2]byte
	payload := make([]byte, 65536)
	for {
		_ = stream.SetReadDeadline(time.Now().Add(UDPGamingSessionIdleTime))
		if _, err := io.ReadFull(stream, lenBuf[:]); err != nil {
			return
		}
		frameLen := int(binary.BigEndian.Uint16(lenBuf[:]))
		if frameLen < 4 || frameLen > MaxUDPFrameSize {
			return
		}
		if _, err := io.ReadFull(stream, payload[:frameLen]); err != nil {
			return
		}
		seq := binary.BigEndian.Uint32(payload[:4])
		if !sess.dedup.checkAndRecord(seq) {
			continue // Duplicate dropped; twin stream already delivered this packet!
		}
		data := payload[4:frameLen]
		if sess.gate != nil && rule != nil && rule.FlowMode == "upload_only" {
			sess.gate.AddAllowed(len(data))
		}
		_ = sess.udpConn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if n, err := sess.udpConn.Write(data); err == nil && n > 0 && stats != nil {
			stats.AddUpload(int64(n))
		}
	}
}

// HandleExitUDPForward handles exit UDP stream by un-framing datagrams to target UDP socket.
func HandleExitUDPForward(stream net.Conn, targetIP string, targetPort uint16, stats *telemetry.Stats, gamingMode bool, ruleOpt ...*ForwarderRule) {
	if gamingMode {
		handleExitGamingUDPForward(stream, targetIP, targetPort, stats, ruleOpt...)
		return
	}
	defer stream.Close()

	var rule *ForwarderRule
	if len(ruleOpt) > 0 {
		rule = ruleOpt[0]
	}

	var gate *FlowGate
	if rule != nil && rule.FlowMode == "upload_only" {
		gate = NewFlowGate(*rule)
		defer gate.Close()
		logGateActivationOnce(int(targetPort), rule.FlowMode)
	}

	if targetIP == "" {
		targetIP = "127.0.0.1"
	}
	raddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(targetIP, strconv.Itoa(int(targetPort))))
	if err != nil {
		return
	}
	udpConn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return
	}
	defer udpConn.Close()

	if gamingMode {
		_ = udpConn.SetReadBuffer(4 * 1024 * 1024)
		_ = udpConn.SetWriteBuffer(4 * 1024 * 1024)
		transport.SetSocketQoS(udpConn)
	}

	if stats != nil {
		stats.ActiveConnections.Add(1)
		defer stats.ActiveConnections.Add(-1)
	}

	var exitDedup udpSeqDeduplicator
	var exitSeq atomic.Uint32
	idleTimeout := udpSessionIdleTimeout(gamingMode, int(targetPort))
	done := make(chan struct{}, 2)

	go func() {
		defer func() { done <- struct{}{} }()
		var lenBuf [2]byte
		payload := make([]byte, 65536)
		for {
			_ = stream.SetReadDeadline(time.Now().Add(idleTimeout))
			if _, err := io.ReadFull(stream, lenBuf[:]); err != nil {
				return
			}
			frameLen := int(binary.BigEndian.Uint16(lenBuf[:]))
			if frameLen == 0 || frameLen > MaxUDPFrameSize {
				return
			}
			if _, err := io.ReadFull(stream, payload[:frameLen]); err != nil {
				return
			}

			data := payload[:frameLen]
			if gamingMode && frameLen >= 4 {
				seq := binary.BigEndian.Uint32(data[:4])
				if !exitDedup.checkAndRecord(seq) {
					continue // Duplicate dropped
				}
				data = data[4:]
			}

			_ = udpConn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			if gate != nil && rule.FlowMode == "upload_only" {
				gate.AddAllowed(len(data))
			}
			if n, err := udpConn.Write(data); err == nil && n > 0 && stats != nil {
				stats.AddUpload(int64(n))
			}
		}
	}()

	go func() {
		defer func() { done <- struct{}{} }()
		buf := make([]byte, 65536)
		for {
			_ = udpConn.SetReadDeadline(time.Now().Add(idleTimeout))
			readOffset := 2
			if gamingMode {
				readOffset = 6 // [2B length][4B seq]
			}
			n, err := udpConn.Read(buf[readOffset:])
			if err != nil {
				return
			}
			if n <= 0 || n > MaxUDPFrameSize {
				continue
			}

			var frame []byte
			if gamingMode {
				seq := exitSeq.Add(1)
				frame = getUDPFrameBuffer(2 + 4 + n)
				binary.BigEndian.PutUint16(frame[0:2], uint16(4+n))
				binary.BigEndian.PutUint32(frame[2:6], seq)
				copy(frame[6:], buf[readOffset:readOffset+n])
			} else {
				frame = getUDPFrameBuffer(2 + n)
				binary.BigEndian.PutUint16(frame[0:2], uint16(n))
				copy(frame[2:], buf[readOffset:readOffset+n])
			}

			_ = stream.SetWriteDeadline(time.Now().Add(5 * time.Second))
			_, wErr := stream.Write(frame)
			putUDPFrameBuffer(frame)
			if wErr != nil {
				return
			}
			if stats != nil {
				stats.AddDownload(int64(n))
			}
		}
	}()

	<-done
}

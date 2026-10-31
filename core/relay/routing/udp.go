package routing

import (
	"context"
	"encoding/binary"
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
	UDPSessionIdleTime = 60 * time.Second
)

type UDPSession struct {
	Stream     net.Conn
	StreamTwin net.Conn
	ClientAddr *net.UDPAddr
	LastActive time.Time
	WriteMu    sync.Mutex
	gamingSeq  atomic.Uint32
	rxDedup    udpSeqDeduplicator
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

// StartUDPListenerLoop binds UDP listener on Entry and frames datagrams over claimed streams.
func StartUDPListenerLoop(
	ctx context.Context,
	udpConn *net.UDPConn,
	targetPort int,
	claimStreamFn func(timeout time.Duration) (net.Conn, error),
	stats *telemetry.Stats,
	gamingMode bool,
) {
	if gamingMode {
		_ = udpConn.SetReadBuffer(4 * 1024 * 1024)
		_ = udpConn.SetWriteBuffer(4 * 1024 * 1024)
		transport.SetSocketQoS(udpConn)
	}
	var sessionsMu sync.Mutex
	sessions := make(map[string]*UDPSession)

	// Session idle reaper
	go func() {
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				sessionsMu.Lock()
				for k, s := range sessions {
					_ = s.Stream.Close()
					delete(sessions, k)
				}
				sessionsMu.Unlock()
				return
			case <-ticker.C:
				now := time.Now()
				sessionsMu.Lock()
				for k, s := range sessions {
					if now.Sub(s.LastActive) > UDPSessionIdleTime {
						_ = s.Stream.Close()
						delete(sessions, k)
					}
				}
				sessionsMu.Unlock()
			}
		}
	}()

	// Read loop
	go func() {
		buf := make([]byte, 65536)
		for {
			n, clientAddr, err := udpConn.ReadFromUDP(buf)
			if err != nil {
				select {
				case <-ctx.Done():
					return
				default:
					continue
				}
			}
			if n <= 0 || n > MaxUDPFrameSize {
				continue
			}

			key := clientAddr.String()
			sessionsMu.Lock()
			sess, exists := sessions[key]
			sessionsMu.Unlock()

			if !exists {
				stream, claimErr := claimStreamFn(3 * time.Second)
				if claimErr != nil {
					log.WithFields(log.Fields{
						"targetPort": targetPort,
						"client":     clientAddr.String(),
						"err":        claimErr,
					}).Warn("[Relay] Client UDP packet dropped: reverse pool is empty (waiting for Exit server to connect)")
					continue
				}
				_ = stream.SetWriteDeadline(time.Now().Add(3 * time.Second))
				proto := RouteProtoUDP
				if gamingMode {
					proto = RouteProtoUDPGaming
				}
				if err := WriteRoutingHeader(stream, proto, uint16(targetPort)); err != nil {
					_ = stream.Close()
					continue
				}
				_ = stream.SetWriteDeadline(time.Time{})

				addrCopy := *clientAddr
				sess = &UDPSession{
					Stream:     stream,
					ClientAddr: &addrCopy,
					LastActive: time.Now(),
				}

				if gamingMode {
					// Attempt to claim twin stream for multi-path anti-jitter replication
					if twin, tErr := claimStreamFn(150 * time.Millisecond); tErr == nil && twin != nil {
						_ = twin.SetWriteDeadline(time.Now().Add(2 * time.Second))
						if err := WriteRoutingHeader(twin, RouteProtoUDPGaming, uint16(targetPort)); err == nil {
							_ = twin.SetWriteDeadline(time.Time{})
							sess.StreamTwin = twin
						} else {
							_ = twin.Close()
						}
					}
				}

				sessionsMu.Lock()
				sessions[key] = sess
				sessionsMu.Unlock()

				pumpStream := func(st net.Conn) {
					var lenBuf [2]byte
					frameBuf := make([]byte, 65536)
					for {
						_ = st.SetReadDeadline(time.Now().Add(UDPSessionIdleTime))
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
						sess.LastActive = time.Now()

						payload := frameBuf[:frameLen]
						if gamingMode && frameLen >= 4 {
							seq := binary.BigEndian.Uint32(payload[:4])
							if !sess.rxDedup.checkAndRecord(seq) {
								continue // Duplicate dropped; first arrival won!
							}
							payload = payload[4:]
						}

						if nw, err := udpConn.WriteToUDP(payload, sess.ClientAddr); err == nil && nw > 0 && stats != nil {
							stats.AddDownload(int64(nw))
						}
					}
				}

				go func(k string, s *UDPSession) {
					if stats != nil {
						stats.ActiveConnections.Add(1)
						defer stats.ActiveConnections.Add(-1)
					}
					defer func() {
						_ = s.Stream.Close()
						if s.StreamTwin != nil {
							_ = s.StreamTwin.Close()
						}
						sessionsMu.Lock()
						if sessions[k] == s {
							delete(sessions, k)
						}
						sessionsMu.Unlock()
					}()

					if s.StreamTwin != nil {
						go pumpStream(s.StreamTwin)
					}
					pumpStream(s.Stream)
				}(key, sess)
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

			sess.WriteMu.Lock()
			sess.LastActive = time.Now()
			_ = sess.Stream.SetWriteDeadline(time.Now().Add(5 * time.Second))
			_, wErr := sess.Stream.Write(frame)
			_ = sess.Stream.SetWriteDeadline(time.Time{})

			if sess.StreamTwin != nil {
				_ = sess.StreamTwin.SetWriteDeadline(time.Now().Add(2 * time.Second))
				_, _ = sess.StreamTwin.Write(frame)
				_ = sess.StreamTwin.SetWriteDeadline(time.Time{})
			}
			sess.WriteMu.Unlock()
			putUDPFrameBuffer(frame)

			if wErr != nil {
				_ = sess.Stream.Close()
				sessionsMu.Lock()
				if sessions[key] == sess {
					delete(sessions, key)
				}
				sessionsMu.Unlock()
			} else if stats != nil {
				stats.AddUpload(int64(n))
			}
		}
	}()
}

// HandleExitUDPForward handles exit UDP stream by un-framing datagrams to target UDP socket.
func HandleExitUDPForward(stream net.Conn, targetIP string, targetPort uint16, stats *telemetry.Stats, gamingMode bool) {
	defer stream.Close()

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
	done := make(chan struct{}, 2)

	go func() {
		defer func() { done <- struct{}{} }()
		var lenBuf [2]byte
		payload := make([]byte, 65536)
		for {
			_ = stream.SetReadDeadline(time.Now().Add(UDPSessionIdleTime))
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
			if n, err := udpConn.Write(data); err == nil && n > 0 && stats != nil {
				stats.AddUpload(int64(n))
			}
		}
	}()

	go func() {
		defer func() { done <- struct{}{} }()
		buf := make([]byte, 65536)
		for {
			_ = udpConn.SetReadDeadline(time.Now().Add(UDPSessionIdleTime))
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

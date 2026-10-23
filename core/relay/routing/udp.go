package routing

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/archnets/node/core/relay/telemetry"
	log "github.com/sirupsen/logrus"
)

const (
	UDPSessionIdleTime = 60 * time.Second
)

type UDPSession struct {
	Stream     net.Conn
	ClientAddr *net.UDPAddr
	LastActive time.Time
	WriteMu    sync.Mutex
}

// StartUDPListenerLoop binds UDP listener on Entry and frames datagrams over claimed streams.
func StartUDPListenerLoop(
	ctx context.Context,
	udpConn *net.UDPConn,
	targetPort int,
	claimStreamFn func(timeout time.Duration) (net.Conn, error),
	stats *telemetry.Stats,
) {
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
				if err := WriteRoutingHeader(stream, RouteProtoUDP, uint16(targetPort)); err != nil {
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
				sessionsMu.Lock()
				sessions[key] = sess
				sessionsMu.Unlock()

				go func(k string, s *UDPSession) {
					if stats != nil {
						stats.ActiveConnections.Add(1)
						defer stats.ActiveConnections.Add(-1)
					}
					defer func() {
						_ = s.Stream.Close()
						sessionsMu.Lock()
						if sessions[k] == s {
							delete(sessions, k)
						}
						sessionsMu.Unlock()
					}()

					var lenBuf [2]byte
					frameBuf := make([]byte, 65536)
					for {
						_ = s.Stream.SetReadDeadline(time.Now().Add(UDPSessionIdleTime))
						if _, err := io.ReadFull(s.Stream, lenBuf[:]); err != nil {
							return
						}
						frameLen := int(binary.BigEndian.Uint16(lenBuf[:]))
						if frameLen == 0 || frameLen > MaxUDPFrameSize {
							return
						}
						if _, err := io.ReadFull(s.Stream, frameBuf[:frameLen]); err != nil {
							return
						}
						s.LastActive = time.Now()
						if nw, err := udpConn.WriteToUDP(frameBuf[:frameLen], s.ClientAddr); err == nil && nw > 0 && stats != nil {
							stats.AddDownload(int64(nw))
						}
					}
				}(key, sess)
			}

			frame := make([]byte, 2+n)
			binary.BigEndian.PutUint16(frame[0:2], uint16(n))
			copy(frame[2:], buf[:n])

			sess.WriteMu.Lock()
			sess.LastActive = time.Now()
			_ = sess.Stream.SetWriteDeadline(time.Now().Add(5 * time.Second))
			_, wErr := sess.Stream.Write(frame)
			_ = sess.Stream.SetWriteDeadline(time.Time{})
			sess.WriteMu.Unlock()

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
func HandleExitUDPForward(stream net.Conn, targetIP string, targetPort uint16, stats *telemetry.Stats) {
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

	if stats != nil {
		stats.ActiveConnections.Add(1)
		defer stats.ActiveConnections.Add(-1)
	}

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
			_ = udpConn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			if n, err := udpConn.Write(payload[:frameLen]); err == nil && n > 0 && stats != nil {
				stats.AddUpload(int64(n))
			}
		}
	}()

	go func() {
		defer func() { done <- struct{}{} }()
		buf := make([]byte, 65536)
		for {
			_ = udpConn.SetReadDeadline(time.Now().Add(UDPSessionIdleTime))
			n, err := udpConn.Read(buf[2:])
			if err != nil {
				return
			}
			if n <= 0 || n > MaxUDPFrameSize {
				continue
			}
			binary.BigEndian.PutUint16(buf[0:2], uint16(n))
			_ = stream.SetWriteDeadline(time.Now().Add(5 * time.Second))
			if _, err := stream.Write(buf[:2+n]); err != nil {
				return
			}
			if stats != nil {
				stats.AddDownload(int64(n))
			}
		}
	}()

	<-done
}

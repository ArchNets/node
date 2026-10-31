package transport

import (
	"errors"
	"io"
	"net"
	"time"

	"github.com/xtaci/smux"
)

const (
	tcpAuthMagic   = "ARTP"
	tcpAuthAckByte = 0xA5
)

// DialTCPCarrier dials a raw TCP carrier connection with 32-byte PoolNonce / HMAC token authentication.
// Once authenticated, the raw *net.TCPConn is returned directly for Linux kernel splice(2) zero-copy.
func DialTCPCarrier(dialCtx CarrierDialer, password string) (net.Conn, error) {
	key, err := DeriveRealityKey(password, "archnet-tcp-pool")
	if err != nil {
		return nil, err
	}
	token, err := GenerateRealityToken(key, tcpAuthMagic)
	if err != nil {
		return nil, err
	}

	conn, err := dialCtx()
	if err != nil {
		return nil, err
	}
	TuneTCPConn(conn)
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	if _, err := conn.Write(token[:]); err != nil {
		_ = conn.Close()
		return nil, err
	}
	var ack [1]byte
	if _, err := io.ReadFull(conn, ack[:]); err != nil || ack[0] != tcpAuthAckByte {
		_ = conn.Close()
		return nil, errors.New("tcp carrier authentication rejected")
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

// InspectTCPTraffic inspects the initial 32 bytes on Entry for a valid TCP PoolNonce token.
func InspectTCPTraffic(conn net.Conn, password string, hasUserForwarder bool) (InspectAction, net.Conn, error) {
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	var token [32]byte
	n, err := io.ReadFull(conn, token[:])
	if err != nil {
		if hasUserForwarder && n > 0 {
			_ = conn.SetReadDeadline(time.Time{})
			return ActionUserClient, NewPrefixConn(conn, token[:n]), nil
		}
		_ = conn.Close()
		return ActionDPIProbe, nil, err
	}

	if key, kErr := DeriveRealityKey(password, "archnet-tcp-pool"); kErr == nil {
		if VerifyRealityToken(key, token[:], tcpAuthMagic) {
			_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			if _, wErr := conn.Write([]byte{tcpAuthAckByte}); wErr != nil {
				_ = conn.Close()
				return ActionDPIProbe, nil, wErr
			}
			_ = conn.SetDeadline(time.Time{})
			return ActionReverseCarrier, conn, nil
		}
	}

	if hasUserForwarder {
		_ = conn.SetDeadline(time.Time{})
		return ActionUserClient, NewPrefixConn(conn, token[:]), nil
	}

	_ = conn.Close()
	return ActionDPIProbe, nil, errors.New("unauthenticated tcp probe dropped")
}

// MuxSession multiplexes multiple virtual net.Conn streams over a single underlying net.Conn
// using xtaci/smux v2 with per-stream sliding-window flow control (used by tcpmux, wsmux, and wssmux).
type MuxSession struct {
	sess *smux.Session
	raw  net.Conn
}

func DefaultSmuxConfig() *smux.Config {
	cfg := smux.DefaultConfig()
	cfg.Version = 2 // Sliding window per-stream flow control
	cfg.KeepAliveInterval = 10 * time.Second
	cfg.KeepAliveTimeout = 30 * time.Second
	cfg.MaxFrameSize = 32768
	cfg.MaxReceiveBuffer = 4 * 1024 * 1024
	cfg.MaxStreamBuffer = 2 * 1024 * 1024
	return cfg
}

// NewMuxSession wraps an authenticated carrier connection into a multiplexed session.
func NewMuxSession(conn net.Conn, isClient bool) *MuxSession {
	cfg := DefaultSmuxConfig()
	var sess *smux.Session
	var err error
	if isClient {
		sess, err = smux.Client(conn, cfg)
	} else {
		sess, err = smux.Server(conn, cfg)
	}
	if err != nil {
		_ = conn.Close()
		return nil
	}
	return &MuxSession{sess: sess, raw: conn}
}

// IsClosed reports whether the session has been closed.
func (s *MuxSession) IsClosed() bool {
	if s == nil || s.sess == nil {
		return true
	}
	return s.sess.IsClosed()
}

func (s *MuxSession) Close() error {
	if s == nil {
		return nil
	}
	var err error
	if s.sess != nil {
		err = s.sess.Close()
	}
	if s.raw != nil {
		_ = s.raw.Close()
	}
	return err
}

// OpenStream opens a new multiplexed virtual stream on the session.
func (s *MuxSession) OpenStream() (net.Conn, error) {
	if s == nil || s.sess == nil || s.sess.IsClosed() {
		return nil, io.ErrClosedPipe
	}
	st, err := s.sess.OpenStream()
	if err != nil {
		return nil, err
	}
	return &MuxStreamConn{Stream: st, sess: s.sess, raw: s.raw}, nil
}

// AcceptStream waits for the peer to open a new multiplexed stream.
func (s *MuxSession) AcceptStream() (net.Conn, error) {
	if s == nil || s.sess == nil || s.sess.IsClosed() {
		return nil, io.EOF
	}
	st, err := s.sess.AcceptStream()
	if err != nil {
		return nil, err
	}
	return &MuxStreamConn{Stream: st, sess: s.sess, raw: s.raw}, nil
}

// MuxStreamConn wraps a single virtual *smux.Stream implementing net.Conn and StreamAliveChecker.
type MuxStreamConn struct {
	*smux.Stream
	sess *smux.Session
	raw  net.Conn
}

func (m *MuxStreamConn) IsAlive() bool {
	if m == nil || m.Stream == nil {
		return false
	}
	if m.sess != nil && m.sess.IsClosed() {
		return false
	}
	select {
	case <-m.Stream.GetDieCh():
		return false
	default:
		return true
	}
}

func (m *MuxStreamConn) LocalAddr() net.Addr {
	if m.raw != nil {
		return m.raw.LocalAddr()
	}
	return m.Stream.LocalAddr()
}

func (m *MuxStreamConn) RemoteAddr() net.Addr {
	if m.raw != nil {
		return m.raw.RemoteAddr()
	}
	return m.Stream.RemoteAddr()
}

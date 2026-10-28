package transport

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	quic "github.com/apernet/quic-go"
)

const (
	quicAuthMagic = "ARQC"
	quicALPN      = "h3"
)

// QuicStreamConn adapts a *quic.Stream into a full net.Conn with directional CloseWrite() support.
type QuicStreamConn struct {
	*quic.Stream
	parentConn *quic.Conn
	localAddr  net.Addr
	remoteAddr net.Addr
}

func NewQuicStreamConn(stream *quic.Stream, conn *quic.Conn) *QuicStreamConn {
	return &QuicStreamConn{
		Stream:     stream,
		parentConn: conn,
		localAddr:  conn.LocalAddr(),
		remoteAddr: conn.RemoteAddr(),
	}
}

// IsAlive reports whether the underlying QUIC connection is still healthy.
func (q *QuicStreamConn) IsAlive() bool {
	if q.parentConn == nil {
		return false
	}
	return q.parentConn.Context().Err() == nil
}

func (q *QuicStreamConn) LocalAddr() net.Addr  { return q.localAddr }
func (q *QuicStreamConn) RemoteAddr() net.Addr { return q.remoteAddr }

// CloseWrite sends a QUIC stream FIN on the send half while keeping the receive half open.
func (q *QuicStreamConn) CloseWrite() error {
	return q.Stream.Close()
}

// CloseRead cancels the receive half of the QUIC stream.
func (q *QuicStreamConn) CloseRead() error {
	q.Stream.CancelRead(0)
	return nil
}

// Close closes both the send and receive halves of the QUIC stream.
func (q *QuicStreamConn) Close() error {
	q.Stream.CancelRead(0)
	return q.Stream.Close()
}

func DefaultQuicConfig() *quic.Config {
	return &quic.Config{
		MaxIncomingStreams:         4096,
		MaxIncomingUniStreams:      1024,
		KeepAlivePeriod:            15 * time.Second,
		MaxIdleTimeout:             60 * time.Second,
		InitialStreamReceiveWindow: 4 * 1024 * 1024,
		MaxStreamReceiveWindow:     16 * 1024 * 1024,
		InitialConnectionReceiveWindow: 8 * 1024 * 1024,
		MaxConnectionReceiveWindow:     32 * 1024 * 1024,
	}
}

// ListenQuicCarrier starts a QUIC listener on the given UDP address using TLS 1.3 (ALPN "h3").
func ListenQuicCarrier(addr, sni, certMode, certFile, keyFile string) (*quic.Listener, *net.UDPConn, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, nil, err
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, nil, err
	}
	_ = udpConn.SetReadBuffer(8 * 1024 * 1024)
	_ = udpConn.SetWriteBuffer(8 * 1024 * 1024)

	tlsCfg, err := BuildRelayTLSConfig(sni, certMode, certFile, keyFile)
	if err != nil {
		_ = udpConn.Close()
		return nil, nil, err
	}
	tlsCfg.NextProtos = []string{quicALPN}

	ln, err := quic.Listen(udpConn, tlsCfg, DefaultQuicConfig())
	if err != nil {
		_ = udpConn.Close()
		return nil, nil, err
	}
	return ln, udpConn, nil
}

// buildSelfSignedQuicClientTLSConfig builds client TLS config allowing self-signed reverse carrier certs.
func buildSelfSignedQuicClientTLSConfig(sni string) *tls.Config {
	if sni == "" {
		sni = "localhost"
	}
	trustSelfSignedCert := true
	return &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: trustSelfSignedCert,
		NextProtos:         []string{quicALPN},
		MinVersion:         tls.VersionTLS13,
	}
}

// DialQuicSession dials a QUIC connection to addr with TLS 1.3 SNI and ALPN "h3".
func DialQuicSession(ctx context.Context, addr, sni string) (*quic.Conn, error) {
	tlsCfg := buildSelfSignedQuicClientTLSConfig(sni)
	dialCtx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	return quic.DialAddr(dialCtx, addr, tlsCfg, DefaultQuicConfig())
}

// OpenQuicCarrierStream opens a new stream on an active *quic.Conn and authenticates it with the tunnel password.
func OpenQuicCarrierStream(ctx context.Context, qConn *quic.Conn, sni, password string) (net.Conn, error) {
	key, err := DeriveRealityKey(password, "archnet-quic-auth")
	if err != nil {
		return nil, err
	}
	token, err := GenerateRealityToken(key, quicAuthMagic)
	if err != nil {
		return nil, err
	}

	openCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	stream, err := qConn.OpenStreamSync(openCtx)
	if err != nil {
		return nil, err
	}
	_ = stream.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := stream.Write(token[:]); err != nil {
		_ = stream.Close()
		return nil, fmt.Errorf("quic write auth token: %w", err)
	}
	var ack [1]byte
	if _, err := io.ReadFull(stream, ack[:]); err != nil || ack[0] != 0x01 {
		_ = stream.Close()
		return nil, errors.New("quic stream auth rejected")
	}
	_ = stream.SetDeadline(time.Time{})
	return NewQuicStreamConn(stream, qConn), nil
}

// AcceptQuicCarrierStream verifies the 32-byte HMAC auth token on an incoming QUIC stream.
func AcceptQuicCarrierStream(stream *quic.Stream, qConn *quic.Conn, sni, password string) (net.Conn, error) {
	_ = stream.SetDeadline(time.Now().Add(5 * time.Second))
	var token [32]byte
	if _, err := io.ReadFull(stream, token[:]); err != nil {
		stream.CancelRead(0)
		_ = stream.Close()
		return nil, err
	}
	key, err := DeriveRealityKey(password, "archnet-quic-auth")
	if err != nil || !VerifyRealityToken(key, token[:], quicAuthMagic) {
		stream.CancelRead(0)
		_ = stream.Close()
		return nil, errors.New("invalid quic stream token")
	}
	if _, err := stream.Write([]byte{0x01}); err != nil {
		stream.CancelRead(0)
		_ = stream.Close()
		return nil, err
	}
	_ = stream.SetDeadline(time.Time{})
	return NewQuicStreamConn(stream, qConn), nil
}

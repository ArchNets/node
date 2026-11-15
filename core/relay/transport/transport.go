package transport

import (
	"context"
	"net"
	"time"
)

// ExtractTCPConns extracts all underlying *net.TCPConn instances from a potentially wrapped net.Conn.
func ExtractTCPConns(c net.Conn) []*net.TCPConn {
	if c == nil {
		return nil
	}
	if tc, ok := c.(*net.TCPConn); ok {
		return []*net.TCPConn{tc}
	}
	if hd, ok := c.(*HalfDuplexConn); ok {
		var list []*net.TCPConn
		if r := hd.ReadTCPConn(); r != nil {
			list = append(list, r)
		}
		if w := hd.WriteTCPConn(); w != nil {
			list = append(list, w)
		}
		return list
	}
	if p, ok := c.(*PrefixConn); ok {
		return ExtractTCPConns(p.Conn)
	}
	type unwrapNetConn interface {
		NetConn() net.Conn
	}
	if unc, ok := c.(unwrapNetConn); ok {
		return ExtractTCPConns(unc.NetConn())
	}
	type unwrapConn interface {
		UnderlyingConn() net.Conn
	}
	if uc, ok := c.(unwrapConn); ok {
		return ExtractTCPConns(uc.UnderlyingConn())
	}
	return nil
}

// TuneTCPConn sets optimal TCP socket options for high-throughput zero-copy relaying.
func TuneTCPConn(c net.Conn) {
	for _, tc := range ExtractTCPConns(c) {
		_ = tc.SetNoDelay(true)
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(10 * time.Second)
		_ = tc.SetReadBuffer(32 * 1024 * 1024)
		_ = tc.SetWriteBuffer(32 * 1024 * 1024)
		setPlatformTCPTune(tc)
	}
}

// ListenTCP binds a TCP listener with pre-handshake TCP_MAXSEG (MSS clamping) and BBR applied before listen(2).
// Setting TCP_MAXSEG before listen(2) guarantees the kernel advertises the clamped MSS in every SYN-ACK.
func ListenTCP(ctx context.Context, addr string) (net.Listener, error) {
	lc := net.ListenConfig{
		Control: socketPreHandshakeControl,
	}
	return lc.Listen(ctx, "tcp", addr)
}

// DialTCPContext dials a TCP connection with pre-handshake TCP_MAXSEG (MSS clamping) and BBR applied before connect(2).
// Setting TCP_MAXSEG before connect(2) guarantees the kernel advertises the clamped MSS in the outgoing SYN packet.
func DialTCPContext(ctx context.Context, addr string, timeout time.Duration) (net.Conn, error) {
	return DialTCPContextWithLocal(ctx, "", addr, timeout)
}

// DialTCPContextWithLocal dials a TCP connection with optional local source address binding.
func DialTCPContextWithLocal(ctx context.Context, localIP, addr string, timeout time.Duration) (net.Conn, error) {
	d := net.Dialer{
		Timeout: timeout,
		Control: socketPreHandshakeControl,
	}
	if localIP != "" {
		if ip := net.ParseIP(localIP); ip != nil {
			d.LocalAddr = &net.TCPAddr{IP: ip}
		}
	}
	return d.DialContext(ctx, "tcp", addr)
}

// CarrierDialer represents a function that connects a raw TCP connection to a carrier endpoint.
type CarrierDialer func() (net.Conn, error)

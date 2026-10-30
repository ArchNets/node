package transport

import (
	"context"
	"net"
	"time"
)

// TuneTCPConn sets optimal TCP socket options for high-throughput zero-copy relaying.
func TuneTCPConn(c net.Conn) {
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(15 * time.Second)
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

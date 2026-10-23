package transport

import (
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

// CarrierDialer represents a function that connects a raw TCP connection to a carrier endpoint.
type CarrierDialer func() (net.Conn, error)

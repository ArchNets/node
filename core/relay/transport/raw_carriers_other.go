//go:build !linux

package transport

import (
	"errors"
	"net"
)

type afPacketIPv4Conn struct {
	net.PacketConn
}

func (c *afPacketIPv4Conn) WriteToWithIPOpts(p []byte, addr net.Addr, srcIP net.IP, ttl byte, tos byte) (int, error) {
	return c.PacketConn.WriteTo(p, addr)
}

func openPlatformRawIPv4Conn(proto byte, bindHost string, ifaceHint string) (net.PacketConn, error) {
	return nil, errors.New("AF_PACKET raw sockets supported on Linux only")
}

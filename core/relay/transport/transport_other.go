//go:build !linux

package transport

import (
	"net"
	"syscall"
)

func setPlatformTCPTune(tc *net.TCPConn) {}

func SetConfiguredMTU(mtu int) {}

func GetConfiguredMTU() int { return 1500 }

func socketPreHandshakeControl(network, address string, c syscall.RawConn) error {
	return nil
}

func ConfigureDontFragmentProbe(c net.Conn, testMTU int) {}

func InspectKernelPMTU(c net.Conn) (int, int) { return 1500, 1460 }

type StreamAliveChecker interface {
	IsAlive() bool
}

func IsStreamAlive(c net.Conn) bool {
	if c == nil {
		return false
	}
	if ac, ok := c.(StreamAliveChecker); ok {
		return ac.IsAlive()
	}
	return true
}

func attachSocketBPFProtocolFilter(pc net.PacketConn, proto byte) error {
	return nil
}

func SetSocketQoS(conn any) {}

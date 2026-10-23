//go:build linux

package transport

import (
	"net"

	"golang.org/x/sys/unix"
)

func setPlatformTCPTune(tc *net.TCPConn) {
	if raw, err := tc.SyscallConn(); err == nil {
		_ = raw.Control(func(fd uintptr) {
			// Request BBR congestion control on Linux
			_ = unix.SetsockoptString(int(fd), unix.IPPROTO_TCP, unix.TCP_CONGESTION, "bbr")
		})
	}
}

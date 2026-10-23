//go:build !linux

package transport

import "net"

func setPlatformTCPTune(tc *net.TCPConn) {}

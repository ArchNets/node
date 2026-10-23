//go:build !linux

package telemetry

import "net"

func spliceRelay(dst, src *net.TCPConn, onChunk func(n int)) (handled bool, err error) {
	return false, nil
}

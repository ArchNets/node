package node

import (
	"fmt"
	"net"
	"sync/atomic"

	log "github.com/sirupsen/logrus"
)

// tproxyPortCounter hands out unique local ports for dokodemo-door TPROXY
// inbounds (WireGuard, AmneziaWG, IPsec, OpenVPN) that bridge tunnel traffic
// into Xray's routing engine.
//
// Why a counter instead of a formula like `10800 + info.Id`: that formula is
// unique per *node*, not per *protocol instance*. A single node can (and, per
// the panel's own routing config, does) run multiple WireGuard/AmneziaWG
// instances at once — e.g. "wg-40-443" and "wg-4-27015" as separate
// inbound_tags with different routing rules. Since info.Id is the same for
// all of them, the old formula produced the same TPROXY port for every
// instance on that node, so only one dokodemo-door inbound could actually
// bind it — the others silently lost their Xray routing.
//
// These ports are purely internal wiring, rebuilt from scratch every time
// the node process starts (the tunnel interfaces themselves are also
// recreated on each Start()), so there's no need for the allocation to be
// stable across restarts — only unique within one running process.
var tproxyPortCounter int32 = 19999

// nextTProxyPort returns a fresh local port for a new dokodemo-door TPROXY
// inbound.
//
// Uniqueness among our own inbounds is guaranteed by the atomic counter; on
// top of that, a bind probe skips ports already occupied by unrelated
// processes on the box, so we never hand Xray a port it cannot bind (which
// would leave TPROXY capture rules pointing at a dead port and blackhole
// client traffic).
func nextTProxyPort() int {
	for i := 0; i < 512; i++ {
		port := int(atomic.AddInt32(&tproxyPortCounter, 1))
		if port > 65535 {
			log.Error("TPROXY port allocator exhausted the valid port range")
			break
		}
		if portIsFree(port) {
			return port
		}
		log.WithField("port", port).Warn(
			"TPROXY port already in use by another process, trying the next one")
	}
	// Practically unreachable: 512 consecutive busy ports (or counter
	// exhaustion). Return the next counter value and let AddInbound surface
	// the bind error loudly instead of guessing further.
	return int(atomic.AddInt32(&tproxyPortCounter, 1))
}

// portIsFree reports whether the given port is currently bindable on all
// interfaces for both TCP and UDP.
func portIsFree(port int) bool {
	addr := fmt.Sprintf(":%d", port)
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return false
	}
	_ = l.Close()
	p, err := net.ListenPacket("udp", addr)
	if err != nil {
		return false
	}
	_ = p.Close()
	return true
}

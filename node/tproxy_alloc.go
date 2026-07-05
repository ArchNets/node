package node

import "sync/atomic"

// tproxyPortCounter hands out unique local ports for dokodemo-door TPROXY
// inbounds (WireGuard, AmneziaWG, IPsec) that bridge tunnel traffic into
// Xray's routing engine.
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
// the node process starts (the WireGuard/AmneziaWG/IPsec interfaces
// themselves are also recreated on each Start()), so there's no need for the
// allocation to be stable across restarts — only unique within one running
// process, which an atomic counter guarantees by construction.
var tproxyPortCounter int32 = 19999

// nextTProxyPort returns a fresh, guaranteed-unique local port for a new
// dokodemo-door TPROXY inbound.
func nextTProxyPort() int {
	return int(atomic.AddInt32(&tproxyPortCounter, 1))
}

package node

import (
	"encoding/json"
	"fmt"

	vCore "github.com/archnets/node/core"
	coreConf "github.com/xtls/xray-core/infra/conf"
)

// addTProxyInbound allocates a fresh TPROXY port (see tproxy_alloc.go) and
// registers the standard dokodemo-door inbound for it in Xray under the
// given tag. This is the single bridge between kernel-level tunnels
// (WireGuard, AmneziaWG, IPsec, OpenVPN) and Xray's routing engine; the
// corresponding iptables TPROXY rules are installed by the protocol core's
// setupNAT.
//
// The tag must be the panel-facing tag that panel routing rules reference in
// inbound_tags (e.g. "wg-40-443", "ikev2:28", "openvpn:28"). Registering
// under a tag no routing rule matches sends all client traffic to Xray's
// default outbound, which usually blackholes the tunnel.
//
// Callers must pass the returned port to the core's SetTProxyPort before
// starting it, and remove the inbound with the same tag on Close.
func addTProxyInbound(xrayCore *vCore.XrayCore, tag string, tproxyPort int) (int, error) {
	if tproxyPort < 1024 || tproxyPort > 65535 {
		return 0, fmt.Errorf("invalid tproxy port %d for %s (expected 1024-65535)", tproxyPort, tag)
	}
	if !portIsFree(tproxyPort) {
		return 0, fmt.Errorf("tproxy port %d for %s is already in use", tproxyPort, tag)
	}
	inboundJSON := fmt.Sprintf(`{
		"tag": "%s",
		"port": %d,
		"protocol": "dokodemo-door",
		"settings": {
			"network": "tcp,udp",
			"followRedirect": true
		},
		"sniffing": {
			"enabled": true,
			"destOverride": ["http", "tls", "quic"]
		},
		"streamSettings": {
			"sockopt": {
				"tproxy": "tproxy"
			}
		}
	}`, tag, tproxyPort)

	var inConf coreConf.InboundDetourConfig
	if err := json.Unmarshal([]byte(inboundJSON), &inConf); err != nil {
		return 0, fmt.Errorf("failed to parse tproxy inbound for %s: %v", tag, err)
	}
	inboundConfig, err := inConf.Build()
	if err != nil {
		return 0, fmt.Errorf("failed to build tproxy inbound for %s: %v", tag, err)
	}
	if err := xrayCore.AddInbound(inboundConfig); err != nil {
		return 0, fmt.Errorf("failed to add tproxy inbound for %s: %v", tag, err)
	}
	return tproxyPort, nil
}

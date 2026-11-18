package routing

import (
	"fmt"
	"strings"

	"github.com/archnets/node/core/relay/protocol"
)

const (
	RouteProtoTCP       = protocol.RouteProtoTCP
	RouteProtoUDP       = protocol.RouteProtoUDP
	RouteProtoUDPGaming = protocol.RouteProtoUDPGaming
	RouteProtoTUN       = protocol.RouteProtoTUN
	RouteProtoProbe     = protocol.RouteProtoProbe
	MaxUDPFrameSize     = protocol.MaxUDPFrameSize
)

var (
	WriteRoutingHeader = protocol.WriteRoutingHeader
	ReadRoutingHeader  = protocol.ReadRoutingHeader
)

// ForwarderRule defines a port or port-range routing configuration on the Entry server.
type ForwarderRule struct {
	ID               int64   `json:"id"`
	Protocol         string  `json:"protocol"` // "tcp", "udp", "tcp,udp"
	ListenIP         string  `json:"listen_ip"`
	ListenPort       int     `json:"listen_port"`
	TargetIP         string  `json:"target_ip"`
	TargetPort       int     `json:"target_port"`
	PortRange        string  `json:"port_range,omitempty"`
	GamingMode       bool    `json:"gaming_mode,omitempty"`
	FlowMode         string  `json:"flow_mode,omitempty"`          // "bidirectional" (default), "upload_only", "download_only"
	ReverseRatio     float64 `json:"reverse_ratio,omitempty"`      // reverse/allowed ratio (default: 0.04)
	ReverseBurstKB   int     `json:"reverse_burst_kb,omitempty"`    // burst budget in KB (default: 64)
	Strict           bool    `json:"strict,omitempty"`             // disconnect instead of throttle when over budget
	ThrottleStallSec int     `json:"throttle_stall_sec,omitempty"` // stall timeout before closing (default: 20s)
}

// ExpandPortRange expands a rule with optional "start-end" PortRange into concrete [listenPort, targetPort] pairs.
func ExpandPortRange(rule ForwarderRule) [][2]int {
	if rule.PortRange != "" {
		var startPort, endPort int
		if _, err := fmt.Sscanf(strings.TrimSpace(rule.PortRange), "%d-%d", &startPort, &endPort); err == nil {
			if startPort > 0 && endPort >= startPort && (endPort-startPort) <= 1000 {
				pairs := make([][2]int, 0, endPort-startPort+1)
				for p := startPort; p <= endPort; p++ {
					target := p
					if rule.TargetPort > 0 && rule.ListenPort > 0 && rule.TargetPort != rule.ListenPort {
						target = rule.TargetPort + (p - startPort)
					}
					pairs = append(pairs, [2]int{p, target})
				}
				return pairs
			}
		}
	}
	if rule.ListenPort <= 0 {
		return nil
	}
	targetPort := rule.TargetPort
	if targetPort <= 0 {
		targetPort = rule.ListenPort
	}
	return [][2]int{{rule.ListenPort, targetPort}}
}

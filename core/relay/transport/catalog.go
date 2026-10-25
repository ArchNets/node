package transport

import "strings"

// TransportSpec defines the capabilities and default parameters for a relay/L3 transport.
type TransportSpec struct {
	ID                string
	Label             string
	IsQuic            bool
	IsPacket          bool
	IsMux             bool
	IsL3              bool
	NeedsSNI          bool
	NeedsTLSServerCfg bool
	DefaultHalfDuplex bool
	DefaultFisher     bool
}

var transportCatalog = []TransportSpec{
	{ID: "stealth", Label: "Stealth (Noise NNpsk0)", DefaultHalfDuplex: true},
	{ID: "tcpmux", Label: "TCPMux (Multiplexed TCP)", IsMux: true},
	{ID: "tcp", Label: "Raw TCP", DefaultHalfDuplex: true},
	{ID: "ws-reverse", Label: "WebSocket (Nginx Decoy)", DefaultHalfDuplex: true},
	{ID: "wsmux", Label: "WSMux (Multiplexed WS)", IsMux: true},
	{ID: "wss-reverse", Label: "WSS (TLS 1.3 + Decoy)", NeedsTLSServerCfg: true, DefaultHalfDuplex: true},
	{ID: "wssmux", Label: "WSSMux (Multiplexed WSS)", IsMux: true, NeedsTLSServerCfg: true},
	{ID: "quic-reverse", Label: "QUIC (UDP Streams)", IsQuic: true},
	{ID: "quic", Label: "QUIC (UDP Streams)", IsQuic: true},
	{ID: "kcp", Label: "KCP (UDP + FEC)", IsPacket: true, IsMux: true},
	{ID: "udp", Label: "UDP Datagram Pool", IsPacket: true, IsMux: true},
	{ID: "pck", Label: "PCK (Stateless Packet TCP)", IsPacket: true, IsMux: true},
	{ID: "xdi", Label: "XDI (ICMP Echo Tunnel)", IsPacket: true, IsMux: true},
	{ID: "tls-reverse", Label: "TLS 1.3", NeedsTLSServerCfg: true, DefaultHalfDuplex: true},
	{ID: "reverse-reality", Label: "Reality (TLS 1.3 Camouflage)", NeedsSNI: true, DefaultHalfDuplex: true, DefaultFisher: true},
	{ID: "l3-udp", Label: "L3 TUN • UDP Datagram", IsPacket: true, IsMux: true, IsL3: true},
	{ID: "l3-quic", Label: "L3 TUN • QUIC Datagram", IsQuic: true, IsL3: true},
	{ID: "l3-pck", Label: "L3 TUN • PCK (Stateless Packet)", IsPacket: true, IsMux: true, IsL3: true},
	{ID: "l3-xdi", Label: "L3 TUN • XDI (ICMP Echo)", IsPacket: true, IsMux: true, IsL3: true},
	{ID: "l3-sni", Label: "L3 TUN • SNI Spoofed Packet", IsPacket: true, IsMux: true, IsL3: true, NeedsSNI: true},
	{ID: "spoof", Label: "IP Spoofing Carrier", IsPacket: true, IsMux: true, IsL3: true},
}

// GetTransportSpec returns the TransportSpec for a given transport ID (falling back to reverse-reality).
func GetTransportSpec(id string) TransportSpec {
	norm := strings.ToLower(strings.TrimSpace(id))
	for _, spec := range transportCatalog {
		if spec.ID == norm {
			return spec
		}
	}
	return TransportSpec{
		ID:                "reverse-reality",
		Label:             "Reality (TLS 1.3 Camouflage)",
		DefaultHalfDuplex: true,
		DefaultFisher:     true,
	}
}

// AllRelayDriverMethods returns all tunnel method strings handled by RelayDriver.
func AllRelayDriverMethods() []string {
	methods := make([]string, 0, len(transportCatalog)+3)
	for _, spec := range transportCatalog {
		methods = append(methods, spec.ID)
	}
	methods = append(methods, "relay", "waterwall", "")
	return methods
}

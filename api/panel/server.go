package panel

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

type ServerConfigResponse struct {
	Code int    `json:"code"`
	Msg  string `json:"msg"`
	Data *Data  `json:"data"`
}

type Data struct {
	TrafficReportThreshold int               `json:"traffic_report_threshold"`
	PushInterval           int               `json:"push_interval"`
	PullInterval           int               `json:"pull_interval"`
	IPStrategy             string            `json:"ip_strategy"`
	DNS                    *[]DNSItem        `json:"dns"`
	Block                  *[]string         `json:"block"`
	Outbound               *[]Outbound       `json:"outbound"`
	Routing                *[]RoutingRule    `json:"routing"`
	Balancers              *[]Balancer       `json:"balancers"`
	Observatory            *Observatory      `json:"observatory"`
	BurstObservatory       *BurstObservatory `json:"burst_observatory"`
	StatsPolicy            *StatsPolicy      `json:"stats_policy"`
	Protocols              *[]Protocol       `json:"protocols"`
	Total                  int               `json:"total"`
}

type DNSItem struct {
	Proto   string   `json:"proto"`
	Address string   `json:"address"`
	Domains []string `json:"domains"`
}

type Outbound struct {
	Name             string `json:"name"`
	Protocol         string `json:"protocol"`
	Address          string `json:"address"`
	Port             int    `json:"port"`
	Password         string `json:"password"`
	Transport        string `json:"transport,omitempty"`
	Host             string `json:"host,omitempty"`
	Path             string `json:"path,omitempty"`
	ServiceName      string `json:"service_name,omitempty"`
	TCPHeaderType    string `json:"tcp_header_type,omitempty"`
	TCPHeaderHost    string `json:"tcp_header_host,omitempty"`
	TCPHeaderPath    string `json:"tcp_header_path,omitempty"`
	Security         string `json:"security,omitempty"`
	SNI              string `json:"sni,omitempty"`
	AllowInsecure    bool   `json:"allow_insecure,omitempty"`
	Fingerprint      string `json:"fingerprint,omitempty"`
	RealityPublicKey string `json:"reality_public_key,omitempty"`
	RealityShortId   string `json:"reality_short_id,omitempty"`
	RealitySpiderX   string `json:"reality_spider_x,omitempty"`
	Flow             string `json:"flow,omitempty"`
	Cipher           string `json:"cipher,omitempty"`
	User             string `json:"user,omitempty"`
	Encryption       string `json:"encryption,omitempty"` // VLESS encryption: "none", "mlkem768x25519plus", etc.

	// WireGuard outbound extensions
	WireguardPrivateKey    string `json:"wireguard_private_key,omitempty"`
	WireguardAddress       string `json:"wireguard_address,omitempty"`
	WireguardMTU           int    `json:"wireguard_mtu,omitempty"`
	WireguardPeerPublicKey string `json:"wireguard_peer_public_key,omitempty"`
	WireguardPeerEndpoint  string `json:"wireguard_peer_endpoint,omitempty"`
	WireguardReserved      string `json:"wireguard_reserved,omitempty"`

	DialerProxy string `json:"dialer_proxy,omitempty"`
}

type Balancer struct {
	Tag         string   `json:"tag"`
	Selector    []string `json:"selector"`
	Strategy    string   `json:"strategy,omitempty"`
	FallbackTag string   `json:"fallback_tag,omitempty"`
}

type Observatory struct {
	SubjectSelector   []string `json:"subject_selector"`
	ProbeURL          string   `json:"probe_url,omitempty"`
	ProbeInterval     string   `json:"probe_interval,omitempty"`
	EnableConcurrency bool     `json:"enable_concurrency,omitempty"`
}

type BurstObservatory struct {
	SubjectSelector []string    `json:"subject_selector"`
	PingConfig      *PingConfig `json:"ping_config,omitempty"`
}

type PingConfig struct {
	Destination  string `json:"destination,omitempty"`
	Connectivity string `json:"connectivity,omitempty"`
	Interval     string `json:"interval,omitempty"`
	Timeout      string `json:"timeout,omitempty"`
	Sampling     int    `json:"sampling,omitempty"`
}

type RoutingRule struct {
	InboundTags []string `json:"inbound_tags,omitempty"`
	OutboundTag string   `json:"outbound_tag,omitempty"`
	BalancerTag string   `json:"balancer_tag,omitempty"`
	Network     string   `json:"network,omitempty"`
	Domain      []string `json:"domain,omitempty"`
	IP          []string `json:"ip,omitempty"`
	Port        string   `json:"port,omitempty"`
	SourceIP    []string `json:"source_ip,omitempty"`
	SourcePort  string   `json:"source_port,omitempty"`
	Protocol    []string `json:"protocol,omitempty"`
	User        []string `json:"user,omitempty"`
	Attrs       string   `json:"attrs,omitempty"`
}

type StatsPolicy struct {
	InboundUplink    bool `json:"inbound_uplink"`
	InboundDownlink  bool `json:"inbound_downlink"`
	OutboundUplink   bool `json:"outbound_uplink"`
	OutboundDownlink bool `json:"outbound_downlink"`
}

type Protocol struct {
	Type                    string `json:"type"`
	Port                    int    `json:"port"`
	ListenIP                string `json:"listen_ip"` // Listen IP (default: 0.0.0.0, use 127.0.0.1 for reverse proxy)
	Enable                  bool   `json:"enable"`
	Security                string `json:"security"`
	SNI                     string `json:"sni"`
	AllowInsecure           bool   `json:"allow_insecure"`
	Fingerprint             string `json:"fingerprint"`
	RealityServerAddr       string `json:"reality_server_addr"`
	RealityServerPort       int    `json:"reality_server_port"`
	RealityPrivateKey       string `json:"reality_private_key"`
	RealityPublicKey        string `json:"reality_public_key"`
	RealityShortID          string `json:"reality_short_id"`
	Transport               string `json:"transport"`
	Host                    string `json:"host"`
	Path                    string `json:"path"`
	ServiceName             string `json:"service_name"`
	Cipher                  string `json:"cipher"`
	ServerKey               string `json:"server_key"`
	Flow                    string `json:"flow"`
	HopPorts                string `json:"hop_ports"`
	HopInterval             int    `json:"hop_interval"`
	ObfsPassword            string `json:"obfs_password"`
	DisableSNI              bool   `json:"disable_sni"`
	ReduceRTT               bool   `json:"reduce_rtt"`
	UDPRelayMode            string `json:"udp_relay_mode"`
	CongestionController    string `json:"congestion_controller"`
	Multiplex               string `json:"multiplex"`
	PaddingScheme           string `json:"padding_scheme"`
	UpMbps                  int    `json:"up_mbps"`
	DownMbps                int    `json:"down_mbps"`
	Obfs                    string `json:"obfs"`
	ObfsHost                string `json:"obfs_host"`
	ObfsPath                string `json:"obfs_path"`
	XHTTPMode               string `json:"xhttp_mode"`
	XHTTPExtra              string `json:"xhttp_extra"`
	Encryption              string `json:"encryption"`
	EncryptionMode          string `json:"encryption_mode"`
	EncryptionRTT           string `json:"encryption_rtt"`
	EncryptionTicket        string `json:"encryption_ticket"`
	EncryptionServerPadding string `json:"encryption_server_padding"`
	EncryptionPrivateKey    string `json:"encryption_private_key"`
	EncryptionClientPadding string `json:"encryption_client_padding"`
	EncryptionPassword      string `json:"encryption_password"`
	CertMode                string `json:"cert_mode"`
	CertFile                string `json:"cert_file"`
	KeyFile                 string `json:"key_file"`
	CertDNSProvider         string `json:"cert_dns_provider"`
	CertDNSEnv              string `json:"cert_dns_env"`
	AcceptProxyProtocol     bool   `json:"accept_proxy_protocol"`

	// TCP HTTP Header obfuscation (for VMess/VLESS with tcp transport)
	TCPHeaderType string   `json:"tcp_header_type"` // "none" or "http"
	TCPHeaderHost []string `json:"tcp_header_host"` // Host header values (e.g., ["www.digikala.com", "example.com"])
	TCPHeaderPath string   `json:"tcp_header_path"` // Request path (e.g., "/incredible-offers")

	// SSH-specific fields
	SSHHostKeyPath string `json:"ssh_host_key_path"` // Path to SSH host key file
	SSHBanner      string `json:"ssh_banner"`        // Custom SSH banner message

	// ShadowTLS-specific fields
	ShadowTLSVersion    int    `json:"shadowtls_version"`     // 1, 2 or 3
	ShadowTLSHandshake  string `json:"shadowtls_handshake"`   // Handshake server (e.g., www.google.com:443)
	ShadowTLSStrictMode bool   `json:"shadowtls_strict_mode"` // Require TLS 1.3
	ShadowsocksPort     int    `json:"shadowsocks_port"`      // Local Shadowsocks port to forward to

	// WireGuard-specific fields
	WireguardInterface  string `json:"wireguard_interface"`   // Interface name (e.g., wg0)
	WireguardPrivateKey string `json:"wireguard_private_key"` // Server private key (auto-generated)
	WireguardPublicKey  string `json:"wireguard_public_key"`  // Server public key (auto-generated)
	WireguardAddress    string `json:"wireguard_address"`     // Server IP and subnet (e.g., 10.0.0.1/24)
	WireguardMTU        int    `json:"wireguard_mtu"`         // MTU size (default: 1420)
	WireguardDNS        string `json:"wireguard_dns"`         // DNS servers (e.g., 1.1.1.1,8.8.8.8)

	// AmneziaWG-specific fields
	AmneziaJc   int `json:"amnezia_jc"`
	AmneziaJmin int `json:"amnezia_jmin"`
	AmneziaJmax int `json:"amnezia_jmax"`
	AmneziaS1   int `json:"amnezia_s1"`
	AmneziaS2   int `json:"amnezia_s2"`
	AmneziaH1   int `json:"amnezia_h1"`
	AmneziaH2   int `json:"amnezia_h2"`
	AmneziaH3   int `json:"amnezia_h3"`
	AmneziaH4   int `json:"amnezia_h4"`

	// IPsec/IKEv2/L2TP fields
	IPsecPSK         string `json:"ipsec_psk"`          // Pre-Shared Key for IPsec
	L2TPSharedSecret string `json:"l2tp_shared_secret"` // L2TP shared secret
	IPsecAuthMethod  string `json:"ipsec_auth_method"`  // Authentication method: eap-mschapv2, psk
	IPsecDNS         string `json:"ipsec_dns"`          // DNS servers for VPN clients (e.g. "8.8.8.8,1.1.1.1")
	IPsecSubnet      string `json:"ipsec_subnet"`       // IP pool subnet (e.g. "10.10.0.0/16")
	IPsecMTU         int    `json:"ipsec_mtu"`          // MTU for L2TP PPP links (default: 1400)
}

func GetServerConfig(c *ClientV2) (*ServerConfigResponse, error) {
	client := c.Client
	path := fmt.Sprintf("/v2/server/%d", c.ServerId)
	r, err := client.
		R().
		SetHeader("If-None-Match", c.ServerConfigEtag).
		SetHeader("Cache-Control", "no-cache, no-store").
		SetHeader("Pragma", "no-cache").
		ForceContentType("application/json").
		Get(path)

	// Prioritize error checking to avoid processing invalid responses
	if err != nil {
		return nil, fmt.Errorf("failed to access %s: %v", client.BaseURL+path, err.Error())
	}

	// Check HTTP status code
	if r.StatusCode() == 304 {
		return nil, nil
	}
	if r.StatusCode() >= 400 {
		body := r.Body()
		return nil, fmt.Errorf("failed to access %s: %s", client.BaseURL+path, string(body))
	}

	// Only check hash on successful response
	hash := sha256.Sum256(r.Body())
	newBodyHash := hex.EncodeToString(hash[:])
	if c.responseBodyHash == newBodyHash {
		return nil, nil
	}
	c.responseBodyHash = newBodyHash
	c.ServerConfigEtag = r.Header().Get("ETag")
	if r != nil {
		defer func() {
			if r.RawBody() != nil {
				r.RawBody().Close()
			}
		}()
	} else {
		return nil, fmt.Errorf("server returned empty response")
	}
	resp := &ServerConfigResponse{}
	err = json.Unmarshal(r.Body(), resp)
	if err != nil {
		return nil, fmt.Errorf("failed to decode response body: %s", err)
	}
	if resp.Data.Protocols == nil {
		return nil, fmt.Errorf("protocol configuration is empty")
	}
	return resp, nil
}

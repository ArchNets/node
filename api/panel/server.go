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
	TrafficReportThreshold int         `json:"traffic_report_threshold"`
	PushInterval           int         `json:"push_interval"`
	PullInterval           int         `json:"pull_interval"`
	IPStrategy             string      `json:"ip_strategy"`
	DNS                    *[]DNSItem  `json:"dns"`
	Block                  *[]string   `json:"block"`
	Outbound               *[]Outbound `json:"outbound"`
	Protocols              *[]Protocol `json:"protocols"`
	Total                  int         `json:"total"`
}

type DNSItem struct {
	Proto   string   `json:"proto"`
	Address string   `json:"address"`
	Domains []string `json:"domains"`
}

type Outbound struct {
	Name     string   `json:"name"`
	Protocol string   `json:"protocol"`
	Address  string   `json:"address"`
	Port     int      `json:"port"`
	Password string   `json:"password"`
	Rules    []string `json:"rules"`
}

type Protocol struct {
	Type                    string `json:"type"`
	Port                    int    `json:"port"`
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
}

func GetServerConfig(c *ClientV2) (*ServerConfigResponse, error) {
	client := c.Client
	path := fmt.Sprintf("/v2/server/%d", c.ServerId)
	r, err := client.
		R().
		SetHeader("If-None-Match", c.ServerConfigEtag).
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

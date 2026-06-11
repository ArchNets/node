package panel

import (
	"encoding/json"
	"fmt"
)

// TunnelConfigResponse is the response from GET /v2/server/:server_id/tunnel
type TunnelConfigResponse struct {
	Code int         `json:"code"`
	Msg  string      `json:"msg"`
	Data *TunnelData `json:"data"`
}

// TunnelData contains the tunnel configuration from the backend
type TunnelData struct {
	CoreConfig *CoreConfig  `json:"core_config"`
	Tunnels    []TunnelInfo `json:"tunnels"`
	Total      int64        `json:"total"`
}

// CoreConfig contains WaterWall core.json settings
type CoreConfig struct {
	MTU        int    `json:"mtu"`
	LogLevel   string `json:"log_level"`
	Workers    int    `json:"workers"`
	RamProfile string `json:"ram_profile"`
}

// TunnelInfo represents a single tunnel configuration
type TunnelInfo struct {
	Id                int                 `json:"id"`
	Name              string              `json:"name"`
	Role              string              `json:"role"`      // "entry" or "exit"
	Method            string              `json:"method"`    // "waterwall" or "xray" (NEW)
	RemoteIP          string              `json:"remote_ip"` // Remote tunnel IP for health checks
	XrayConfig        *XrayTunnelProtocol `json:"xray_config,omitempty"`
	XrayReverseConfig string              `json:"xray_reverse_config,omitempty"`
	WaterwallConfig   string              `json:"waterwall_config,omitempty"`
	NipovpnConfig     *NipovpnConfig      `json:"nipovpn_config,omitempty"`
	ExitServerIP      string              `json:"exit_server_ip,omitempty"`
	ExitXrayPort      int                 `json:"exit_xray_port,omitempty"`
	ExitXrayUUID      string              `json:"exit_xray_uuid,omitempty"`
	Forwarders        []Forwarder         `json:"forwarders"`
	ScanCommand       *ScanCommand        `json:"scan_command,omitempty"`
	SniSpoofingConfig *SniSpoofingConfig  `json:"sni_spoofing_config,omitempty"`
	XrayStealthConfig string              `json:"xray_stealth_config,omitempty"`
}

// SniSpoofingConfig represents the sidecar config for SNI-Spoofing
type SniSpoofingConfig struct {
	ListenPort     int    `json:"listen_port"`
	ConnectIP      string `json:"connect_ip"`
	ConnectPort    int    `json:"connect_port"`
	FakeSNI        string `json:"fake_sni"`
	UTLS           string `json:"utls,omitempty"`
	FakeRepeat     int    `json:"fake_repeat,omitempty"`
	FakeDelay      string `json:"fake_delay,omitempty"`
	AckTimeout     string `json:"ack_timeout,omitempty"`
	Injector       string `json:"injector,omitempty"`
	EnableFragment bool   `json:"enable_fragment,omitempty"`
	FragmentDelay  string `json:"fragment_delay,omitempty"`
	SniChunk       int    `json:"sni_chunk,omitempty"`
}

type NipovpnConfig struct {
	Token            string   `json:"token"`
	FakeUrls         []string `json:"fake_urls"`
	Methods          []string `json:"methods"`
	Endpoints        []string `json:"endpoints"`
	AgentPort        int      `json:"agent_port"`
	ServerPort       int      `json:"server_port"`
	TlsEnable        bool     `json:"tls_enable"`
	TlsCertPath      string   `json:"tls_cert_path"` // Backwards compatibility
	TlsKeyPath       string   `json:"tls_key_path"`  // Backwards compatibility
	TunnelMode       string   `json:"tunnel_mode"`
	Timeout          int      `json:"timeout"`
	PullTimeout      int      `json:"pull_timeout"`
	ConnectionReuse  *bool    `json:"connection_reuse"`
	LogLevel         string   `json:"log_level"`
	ServerThreads    int      `json:"server_threads"`
	AgentThreads     int      `json:"agent_threads"`
	TlsCertFile      string   `json:"tls_cert_file"`
	TlsKeyFile       string   `json:"tls_key_file"`
	TlsCaFile        string   `json:"tls_ca_file"`
	HttpVersion      string   `json:"http_version"`
	UserAgent        string   `json:"user_agent"`
	Protocol         string   `json:"protocol"` // "socks5" or "http" (default: "http")
	NipoExitXrayPort int      `json:"nipo_exit_xray_port,omitempty"`
	NipoExitXrayUUID string   `json:"nipo_exit_xray_uuid,omitempty"`
}

// XrayTunnelProtocol matches the backend Protocol type with tunnel-specific fields
type XrayTunnelProtocol struct {
	// Tunnel-specific
	UUID    string `json:"uuid"`
	Address string `json:"address"` // Clean IP or CDN domain

	// Protocol fields
	Type              string `json:"type"` // vless, vmess, trojan, shadowsocks
	Port              uint16 `json:"port"`
	Security          string `json:"security"` // none, tls, reality
	SNI               string `json:"sni,omitempty"`
	Fingerprint       string `json:"fingerprint,omitempty"`
	AllowInsecure     bool   `json:"allow_insecure,omitempty"`
	Transport         string `json:"transport,omitempty"` // tcp, ws, grpc, xhttp
	Host              string `json:"host,omitempty"`
	Path              string `json:"path,omitempty"`
	ServiceName       string `json:"service_name,omitempty"`
	XhttpMode         string `json:"xhttp_mode,omitempty"`
	Flow              string `json:"flow,omitempty"`
	Encryption        string `json:"encryption,omitempty"`
	EncryptionMode    string `json:"encryption_mode,omitempty"`
	EncryptionRTT     string `json:"encryption_rtt,omitempty"`
	Cipher            string `json:"cipher,omitempty"`
	ServerKey         string `json:"server_key,omitempty"`
	CertFile          string `json:"cert_file,omitempty"`
	KeyFile           string `json:"key_file,omitempty"`
	ListenIP          string `json:"listen_ip,omitempty"`
	RealityServerAddr string `json:"reality_server_addr,omitempty"`
	RealityServerPort int    `json:"reality_server_port,omitempty"`
	RealityPrivateKey string `json:"reality_private_key,omitempty"`
	RealityPublicKey  string `json:"reality_public_key,omitempty"`
	RealityShortId    string `json:"reality_short_id,omitempty"`
}

// Forwarder represents a port forwarder configuration (gost/nodepass)
type Forwarder struct {
	Protocol      string `json:"protocol"` // "tcp" or "udp"
	ListenPort    int    `json:"listen_port"`
	TargetIP      string `json:"target_ip"`
	TargetPort    int    `json:"target_port"`
	ForwarderType string `json:"forwarder_type"` // "gost", "nodepass", "paqet"
	Config        string `json:"config"`         // Partial Paqet config
}

// ScanCommand is sent by the backend when a ProtoSwap scan is requested
type ScanCommand struct {
	Protocol    string `json:"protocol"` // tcp, udp, both
	TcpTestPort int    `json:"tcp_test_port"`
	UdpTestPort int    `json:"udp_test_port"`
	StartTime   int64  `json:"start_time"` // Unix timestamp for sync

	Signal      string `json:"signal,omitempty"`       // cancel, pause (empty = run)
	ResumeFrom  int    `json:"resume_from,omitempty"`  // protocol to resume from
	ResumePhase string `json:"resume_phase,omitempty"` // tcp or udp
}

// ScanResultItem represents a single protocol test result
type ScanResultItem struct {
	ProtocolNumber int    `json:"protocol_number"`
	Type           string `json:"type"` // tcp or udp
	LatencyMs      int    `json:"latency_ms"`
	UploadSpeed    int64  `json:"upload_speed"`
	DownloadSpeed  int64  `json:"download_speed"`
	PacketLoss     int    `json:"packet_loss"`
	Jitter         int    `json:"jitter"`
}

// ScanResultsRequest is the request body for reporting scan results
type ScanResultsRequest struct {
	TunnelId   int              `json:"tunnel_id"`
	Status     string           `json:"status"` // running, completed, failed, cancelled, paused
	Error      string           `json:"error,omitempty"`
	Progress   int              `json:"progress"`
	Results    []ScanResultItem `json:"results"`
	LastTested int              `json:"last_tested,omitempty"` // last protocol tested
	Phase      string           `json:"phase,omitempty"`       // tcp or udp
}

// TunnelStatusRequest is the request body for POST /v2/server/:server_id/tunnel/status
type TunnelStatusRequest struct {
	Tunnels []TunnelStatus `json:"tunnels"`
}

// TunnelStatus represents the status of a single tunnel
type TunnelStatus struct {
	TunnelId      int   `json:"tunnel_id"`
	Online        bool  `json:"online"`
	LatencyMs     int   `json:"latency_ms"`
	TotalUpload   int64 `json:"total_upload"`
	TotalDownload int64 `json:"total_download"`
}

// GetTunnelConfig fetches the tunnel configuration from the backend
func (c *ClientV2) GetTunnelConfig() (*TunnelConfigResponse, error) {
	path := fmt.Sprintf("/v2/server/%d/tunnel", c.ServerId)
	r, err := c.Client.
		R().
		ForceContentType("application/json").
		Get(path)

	if err != nil {
		return nil, fmt.Errorf("failed to access %s: %v", c.Client.BaseURL+path, err)
	}

	if r.StatusCode() >= 400 {
		return nil, fmt.Errorf("failed to access %s: %s", c.Client.BaseURL+path, string(r.Body()))
	}

	resp := &TunnelConfigResponse{}
	if err = json.Unmarshal(r.Body(), resp); err != nil {
		return nil, fmt.Errorf("failed to decode tunnel config response: %s", err)
	}

	return resp, nil
}

// ReportTunnelStatus reports the status of tunnels to the backend
func (c *ClientV2) ReportTunnelStatus(status *TunnelStatusRequest) error {
	path := fmt.Sprintf("/v2/server/%d/tunnel/status", c.ServerId)
	r, err := c.Client.
		R().
		SetBody(status).
		ForceContentType("application/json").
		Post(path)

	if err != nil {
		return fmt.Errorf("failed to report tunnel status: %v", err)
	}

	if r.StatusCode() >= 400 {
		return fmt.Errorf("failed to report tunnel status: %s", string(r.Body()))
	}

	return nil
}

// ReportScanResults reports ProtoSwap scan results to the backend
func (c *ClientV2) ReportScanResults(req *ScanResultsRequest) error {
	path := fmt.Sprintf("/v2/server/%d/tunnel/scan/results", c.ServerId)
	r, err := c.Client.
		R().
		SetBody(req).
		ForceContentType("application/json").
		Post(path)

	if err != nil {
		return fmt.Errorf("failed to report scan results: %v", err)
	}

	if r.StatusCode() >= 400 {
		return fmt.Errorf("failed to report scan results: %s", string(r.Body()))
	}

	return nil
}

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
	CoreConfig *CoreConfig       `json:"core_config"`
	Tunnels    []TunnelInfo      `json:"tunnels"`
	SNIOrigins []TunnelSNIOrigin `json:"sni_origins,omitempty"`
	Total      int64             `json:"total"`
}

// TunnelSNIOrigin represents an admin-managed camouflage SNI origin domain and IP
type TunnelSNIOrigin struct {
	Id        int64  `json:"id"`
	SNI       string `json:"sni"`
	Label     string `json:"label"`
	OriginIP  string `json:"origin_ip"`
	Category  string `json:"category"`
	Enabled   bool   `json:"enabled"`
	Sort      int    `json:"sort"`
	CreatedAt int64  `json:"created_at"`
	UpdatedAt int64  `json:"updated_at"`
}

// CoreConfig contains per-server tunnel core settings
type CoreConfig struct {
	MTU        int    `json:"mtu"`
	LogLevel   string `json:"log_level"`
	Workers    int    `json:"workers"`
	RamProfile string `json:"ram_profile"`
}

// RelayTunnelConfig configures the Native Go Relay Engine (reverse-reality / tls-reverse)
type RelayTunnelConfig struct {
	Transport          string   `json:"transport"`            // "reverse-reality", "tls-reverse"
	CarrierPort        int      `json:"carrier_port"`         // Default: 443
	SNI                string   `json:"sni"`                  // Default: "shariati.tums.ac.ir"
	OriginIP           string   `json:"origin_ip,omitempty"`  // Auto-resolved from KnownIranOriginIPs if empty
	Password           string   `json:"password"`             // Shared secret
	UseHalfDuplex      bool     `json:"use_halfduplex"`       // Default: true
	UseFisher          bool     `json:"use_fisher"`           // Default: true
	FisherConnections  int      `json:"fisher_connections"`   // Default: 3
	MinHeldConnections int      `json:"min_held_connections"` // Default: 8
	FloatingIPs        []string `json:"floating_ips,omitempty"`
	EnableProbe        bool     `json:"enable_probe"`       // Default: true
	ProbeIntervalMin   int      `json:"probe_interval_min"` // Default: 30
}

// TunnelInfo represents a single tunnel configuration
type TunnelInfo struct {
	Id                int                      `json:"id"`
	Name              string                   `json:"name"`
	Role              string                   `json:"role"`      // "entry" or "exit"
	Method            string                   `json:"method"`    // "reverse-reality", "tls-reverse", "xray", "xray-reverse", "xray-stealth", "nipovpn"
	LocalIP           string                   `json:"local_ip"`  // Local server IP
	RemoteIP          string                   `json:"remote_ip"` // Remote server IP
	Config            string                   `json:"config,omitempty"`
	RelayConfig       *RelayTunnelConfig       `json:"relay_config,omitempty"`
	XrayConfig        *XrayTunnelProtocol      `json:"xray_config,omitempty"`
	XrayReverseConfig *XrayReverseTunnelConfig `json:"xray_reverse_config,omitempty"`
	NipovpnConfig     *NipovpnConfig           `json:"nipovpn_config,omitempty"`
	ExitServerIP      string                   `json:"exit_server_ip,omitempty"`
	ExitXrayPort      int                      `json:"exit_xray_port,omitempty"`
	ExitXrayUUID      string                   `json:"exit_xray_uuid,omitempty"`
	Forwarders        []Forwarder              `json:"forwarders"`
	ScanCommand       *ScanCommand             `json:"scan_command,omitempty"`
	SniSpoofingConfig *SniSpoofingConfig       `json:"sni_spoofing_config,omitempty"`
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

type XrayReverseTunnelConfig struct {
	UUID             string `json:"uuid"`
	PortalPort       int    `json:"portal_port"`
	Transport        string `json:"transport"`
	Path             string `json:"path,omitempty"`
	Host             string `json:"host,omitempty"`
	Security         string `json:"security,omitempty"`
	ServerName       string `json:"server_name,omitempty"`
	Fingerprint      string `json:"fingerprint,omitempty"`
	RealityPublicKey string `json:"reality_public_key,omitempty"`
	RealityShortId   string `json:"reality_short_id,omitempty"`
	RealitySpiderX   string `json:"reality_spider_x,omitempty"`
	PortalAddress    string `json:"portal_address"`
	PortalPublicPort int    `json:"portal_public_port"`
	XhttpMode        string `json:"xhttp_mode,omitempty"`
	XhttpExtra       string `json:"xhttp_extra,omitempty"`
}

type NipovpnConfig struct {
	Token            string   `json:"token"`
	FakeUrls         []string `json:"fake_urls"`
	Methods          []string `json:"methods"`
	Endpoints        []string `json:"endpoints"`
	AgentPort        int      `json:"agent_port"`
	ServerPort       int      `json:"server_port"`
	TlsEnable        bool     `json:"tls_enable"`
	TlsCertPath      string   `json:"tls_cert_path"`
	TlsKeyPath       string   `json:"tls_key_path"`
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
	Protocol         string   `json:"protocol"`
	NipoExitXrayPort int      `json:"nipo_exit_xray_port,omitempty"`
	NipoExitXrayUUID string   `json:"nipo_exit_xray_uuid,omitempty"`
}

// XrayTunnelProtocol matches the backend Protocol type with tunnel-specific fields
type XrayTunnelProtocol struct {
	UUID              string `json:"uuid"`
	Address           string `json:"address"`
	Type              string `json:"type"`
	Port              uint16 `json:"port"`
	Security          string `json:"security"`
	SNI               string `json:"sni,omitempty"`
	Fingerprint       string `json:"fingerprint,omitempty"`
	AllowInsecure     bool   `json:"allow_insecure,omitempty"`
	Transport         string `json:"transport,omitempty"`
	Host              string `json:"host,omitempty"`
	Path              string `json:"path,omitempty"`
	ServiceName       string `json:"service_name,omitempty"`
	XhttpMode         string `json:"xhttp_mode,omitempty"`
	XhttpExtra        string `json:"xhttp_extra,omitempty"`
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

// Forwarder represents a port forwarder configuration
type Forwarder struct {
	Id            int64  `json:"id"`
	Protocol      string `json:"protocol"` // "tcp" or "udp"
	ListenPort    int    `json:"listen_port"`
	ListenIP      string `json:"listen_ip"`
	TargetIP      string `json:"target_ip"`
	TargetPort    int    `json:"target_port"`
	PortRange     string `json:"port_range,omitempty"`
	ForwarderType string `json:"forwarder_type"` // "relay", "waterwall", "gost", "nodepass", "paqet", "xray"
	Config        string `json:"config"`
}

// ScanCommand is sent by the backend when an SNI/Method benchmark sweep or instant probe is requested
type ScanCommand struct {
	ScanMode    string   `json:"scan_mode,omitempty"`   // "hospital", "sni", "methods"
	CustomSNIs  []string `json:"custom_snis,omitempty"` // Optional custom SNI list
	ProbeNow    bool     `json:"probe_now,omitempty"`   // Trigger immediate bandwidth probe
	Protocol    string   `json:"protocol"`              // Legacy / transport filter
	TcpTestPort int      `json:"tcp_test_port"`
	UdpTestPort int      `json:"udp_test_port"`
	StartTime   int64    `json:"start_time"`
	Signal      string   `json:"signal,omitempty"` // cancel, pause (empty = run)
	ResumeFrom  int      `json:"resume_from,omitempty"`
	ResumePhase string   `json:"resume_phase,omitempty"`
}

// ScanResultItem represents a single SNI or method benchmark result
type ScanResultItem struct {
	ProtocolNumber int     `json:"protocol_number"`
	Type           string  `json:"type"`
	SNI            string  `json:"sni,omitempty"`
	MethodLabel    string  `json:"method_label,omitempty"`
	UseHalfDuplex  bool    `json:"use_halfduplex,omitempty"`
	UseFisher      bool    `json:"use_fisher,omitempty"`
	LatencyMs      int     `json:"latency_ms"`
	UploadSpeed    int64   `json:"upload_speed"`
	DownloadSpeed  int64   `json:"download_speed"`
	PacketLoss     int     `json:"packet_loss"`
	Jitter         int     `json:"jitter"`
	Score          float64 `json:"score,omitempty"`
}

// ScanResultsRequest is the request body for reporting scan results
type ScanResultsRequest struct {
	TunnelId   int              `json:"tunnel_id"`
	Status     string           `json:"status"` // running, completed, failed, cancelled, paused
	ScanMode   string           `json:"scan_mode,omitempty"`
	Error      string           `json:"error,omitempty"`
	Progress   int              `json:"progress"`
	Results    []ScanResultItem `json:"results"`
	LastTested int              `json:"last_tested,omitempty"`
	Phase      string           `json:"phase,omitempty"`
}

// BandwidthSamplePayload represents a bandwidth probe sample reported by the Entry node
type BandwidthSamplePayload struct {
	Timestamp    int64   `json:"timestamp"`
	UploadMbps   float64 `json:"upload_mbps"`
	DownloadMbps float64 `json:"download_mbps"`
	RttMs        int     `json:"rtt_ms"`
	JitterMs     int     `json:"jitter_ms,omitempty"`
	PacketLoss   int     `json:"packet_loss"`
	Status       string  `json:"status"` // "OPTIMAL", "DEGRADED", "THROTTLED"
}

// TunnelStatusRequest is the request body for POST /v2/server/:server_id/tunnel/status
type TunnelStatusRequest struct {
	Tunnels []TunnelStatus `json:"tunnels"`
}

// TunnelStatus represents the status of a single tunnel
type TunnelStatus struct {
	TunnelId              int                     `json:"tunnel_id"`
	Online                bool                    `json:"online"`
	LatencyMs             int                     `json:"latency_ms"`
	TotalUpload           int64                   `json:"total_upload"`
	TotalDownload         int64                   `json:"total_download"`
	CurrentUploadBps      int64                   `json:"current_upload_bps,omitempty"`
	CurrentDownloadBps    int64                   `json:"current_download_bps,omitempty"`
	LastProbeUploadMbps   float64                 `json:"last_probe_upload_mbps,omitempty"`
	LastProbeDownloadMbps float64                 `json:"last_probe_download_mbps,omitempty"`
	ProbeStatus           string                  `json:"probe_status,omitempty"`
	ProbeSample           *BandwidthSamplePayload `json:"probe_sample,omitempty"`
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

// ReportScanResults reports benchmark scan results to the backend
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

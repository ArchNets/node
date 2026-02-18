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
	Id          int          `json:"id"`
	Name        string       `json:"name"`
	Role        string       `json:"role"`        // "entry" or "exit"
	ConfigJSON  string       `json:"config_json"` // Raw WaterWall tunnel config
	RemoteIP    string       `json:"remote_ip"`   // Remote tunnel IP for health checks
	Forwarders  []Forwarder  `json:"forwarders"`
	ScanCommand *ScanCommand `json:"scan_command,omitempty"`
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

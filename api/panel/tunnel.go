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
	Id         int         `json:"id"`
	Name       string      `json:"name"`
	Role       string      `json:"role"`        // "entry" or "exit"
	ConfigJSON string      `json:"config_json"` // Raw WaterWall tunnel config
	RemoteIP   string      `json:"remote_ip"`   // Remote tunnel IP for health checks
	Forwarders []Forwarder `json:"forwarders"`
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

// TunnelStatusRequest is the request body for POST /v2/server/:server_id/tunnel/status
type TunnelStatusRequest struct {
	Tunnels []TunnelStatus `json:"tunnels"`
}

// TunnelStatus represents the status of a single tunnel
type TunnelStatus struct {
	TunnelId  int  `json:"tunnel_id"`
	Online    bool `json:"online"`
	LatencyMs int  `json:"latency_ms"`
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

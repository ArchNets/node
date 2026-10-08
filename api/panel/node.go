package panel

import (
	"fmt"
	"path"
	"time"
)

// What changed: Added Users []UserInfo field to NodeInfo.
// Why: Enables passing panel user credentials to inbound builders (such as SOCKS and HTTP static accounts).
type NodeInfo struct {
	Id                     int
	Type                   string
	PushInterval           int
	PullInterval           int
	TrafficReportThreshold int
	Protocol               *Protocol
	Users                  []UserInfo
}

type ServerPushStatusRequest struct {
	Cpu       float64 `json:"cpu"`
	Mem       float64 `json:"mem"`
	Disk      float64 `json:"disk"`
	UpdatedAt int64   `json:"updated_at"`
}

type NodeStatus struct {
	CPU    float64
	Mem    float64
	Disk   float64
	Uptime uint64
}

func (c *ClientV1) ReportNodeStatus(nodeStatus *NodeStatus) (err error) {
	p := "/v1/server/status"
	status := ServerPushStatusRequest{
		Cpu:       nodeStatus.CPU,
		Mem:       nodeStatus.Mem,
		Disk:      nodeStatus.Disk,
		UpdatedAt: time.Now().UnixMilli(),
	}
	r, err := c.Client.R().SetBody(status).ForceContentType("application/json").Post(p)
	if err != nil {
		return fmt.Errorf("failed to access %s: %v", path.Join(c.APIHost+p), err.Error())
	}
	if r.StatusCode() >= 400 {
		return fmt.Errorf("failed to access %s: status %d, body: %s", path.Join(c.APIHost+p), r.StatusCode(), string(r.Body()))
	}
	return nil
}

type NodeServiceProbeTarget struct {
	Key            string   `json:"key"`
	Label          string   `json:"label"`
	TestUrl        string   `json:"test_url"`
	Domains        []string `json:"domains"`
	ExpectedStatus string   `json:"expected_status"`
}

type GetServicesToProbeResponse struct {
	Targets []NodeServiceProbeTarget `json:"targets"`
}

type NodeServiceProbeItem struct {
	OutboundTag string `json:"outbound_tag"`
	ServiceKey  string `json:"service_key"`
	Status      string `json:"status"`
	LatencyMs   int    `json:"latency_ms"`
	HttpCode    int    `json:"http_code"`
	Message     string `json:"message,omitempty"`
}

type ReportServiceProbesRequest struct {
	ServerId int                    `json:"server_id"`
	Probes   []NodeServiceProbeItem `json:"probes"`
}

func (c *ClientV1) GetServicesToProbe() ([]NodeServiceProbeTarget, error) {
	p := "/v1/server/service_probe/targets"
	resp := &struct {
		Code int                         `json:"code"`
		Msg  string                      `json:"msg"`
		Data *GetServicesToProbeResponse `json:"data"`
	}{}
	r, err := c.Client.R().SetResult(resp).Get(p)
	if err != nil {
		return nil, fmt.Errorf("failed to access %s: %v", path.Join(c.APIHost+p), err.Error())
	}
	if r.StatusCode() >= 400 {
		return nil, fmt.Errorf("failed to access %s: status %d", path.Join(c.APIHost+p), r.StatusCode())
	}
	if resp.Data == nil {
		return nil, nil
	}
	return resp.Data.Targets, nil
}

func (c *ClientV1) ReportServiceProbes(serverId int, probes []NodeServiceProbeItem) error {
	p := "/v1/server/service_probe"
	body := ReportServiceProbesRequest{
		ServerId: serverId,
		Probes:   probes,
	}
	r, err := c.Client.R().SetBody(body).ForceContentType("application/json").Post(p)
	if err != nil {
		return fmt.Errorf("failed to access %s: %v", path.Join(c.APIHost+p), err.Error())
	}
	if r.StatusCode() >= 400 {
		return fmt.Errorf("failed to access %s: status %d, body: %s", path.Join(c.APIHost+p), r.StatusCode(), string(r.Body()))
	}
	return nil
}


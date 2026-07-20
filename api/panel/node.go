package panel

import (
	"fmt"
	"path"
	"time"
)

type NodeInfo struct {
	Id                     int
	Type                   string
	PushInterval           int
	PullInterval           int
	TrafficReportThreshold int
	Protocol               *Protocol
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

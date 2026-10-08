package core

import (
	"context"
	"net"
	"net/http"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
)

type ProbeResult struct {
	OutboundTag string
	ServiceKey  string
	Status      string // ok, degraded, blocked, unknown
	LatencyMs   int
	HttpCode    int
	Message     string
}

func (c *XrayCore) GetConfiguredOutboundTags() []string {
	tags := []string{"direct"}
	if c == nil {
		return tags
	}
	c.wgMutex.Lock()
	defer c.wgMutex.Unlock()
	for tag := range c.wgOutbounds {
		if tag != "" && tag != "direct" && tag != "block" {
			tags = append(tags, tag)
		}
	}
	return tags
}

func (c *XrayCore) ProbeServiceOutbound(ctx context.Context, tag string, serviceKey string, testUrl string) ProbeResult {
	start := time.Now()
	res := ProbeResult{
		OutboundTag: tag,
		ServiceKey:  serviceKey,
		Status:      "unknown",
	}

	dialer := func(ctx context.Context, network, addr string) (net.Conn, error) {
		dest, err := xnet.ParseDestination(network + ":" + addr)
		if err != nil {
			return nil, err
		}
		return c.DialOutbound(ctx, tag, dest)
	}

	transport := &http.Transport{
		DialContext:         dialer,
		DisableKeepAlives:   true,
		TLSHandshakeTimeout: 5 * time.Second,
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   6 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	req, err := http.NewRequestWithContext(ctx, "GET", testUrl, nil)
	if err != nil {
		res.Status = "blocked"
		res.Message = err.Error()
		return res
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "*/*")

	resp, err := client.Do(req)
	res.LatencyMs = int(time.Since(start).Milliseconds())

	if err != nil {
		res.Status = "blocked"
		res.Message = err.Error()
		return res
	}
	defer resp.Body.Close()

	res.HttpCode = resp.StatusCode

	// Status classification
	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		res.Status = "ok"
	} else if resp.StatusCode == 403 || resp.StatusCode == 429 {
		// Might be Cloudflare challenge or captcha
		res.Status = "degraded"
		res.Message = "Challenge / Captcha"
	} else if resp.StatusCode == 451 || resp.StatusCode >= 500 {
		res.Status = "blocked"
		res.Message = "Geo-blocked or service error"
	} else {
		res.Status = "ok" // 400 or 401 is normal for api endpoints without auth tokens
	}

	return res
}

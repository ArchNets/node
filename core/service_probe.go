package core

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"golang.org/x/net/http2"
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

	parsedURL, parseErr := url.Parse(testUrl)
	var sniHost string
	if parseErr == nil {
		sniHost = parsedURL.Hostname()
	}

	dialer := func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, splitErr := net.SplitHostPort(addr)
		targetAddr := addr
		if splitErr == nil {
			// If target is a hostname, resolve to IPv4 first to avoid IPv6 gateway blackholes on VPS nodes
			if net.ParseIP(host) == nil {
				if ips, err := net.DefaultResolver.LookupIP(ctx, "ip4", host); err == nil && len(ips) > 0 {
					targetAddr = net.JoinHostPort(ips[0].String(), port)
				}
			}
		}

		dest, err := xnet.ParseDestination(network + ":" + targetAddr)
		if err != nil {
			return nil, err
		}
		return c.DialOutbound(ctx, tag, dest)
	}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: false,
		MinVersion:         tls.VersionTLS12,
		ServerName:         sniHost,
	}

	transport := &http.Transport{
		DialContext:         dialer,
		DisableKeepAlives:   true,
		TLSHandshakeTimeout: 5 * time.Second,
		TLSClientConfig:     tlsConfig,
	}
	_ = http2.ConfigureTransport(transport)

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
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")

	resp, err := client.Do(req)
	res.LatencyMs = int(time.Since(start).Milliseconds())

	if err != nil {
		res.Status = "blocked"
		errStr := err.Error()
		if strings.Contains(errStr, "version 7469") || strings.Contains(errStr, "error decoding message") {
			res.Message = "TLS Intercepted / Middlebox Blocked"
		} else if strings.Contains(errStr, "handshake timeout") {
			res.Message = "TLS Handshake Timeout (DPI Blocked or IPv6 Blackhole)"
		} else {
			res.Message = errStr
		}
		return res
	}
	defer resp.Body.Close()

	res.HttpCode = resp.StatusCode

	// Status classification
	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		res.Status = "ok"
	} else if resp.StatusCode == 403 || resp.StatusCode == 429 {
		// Challenge / Captcha - reachable but subject to anti-bot challenge
		res.Status = "degraded"
		res.Message = "Challenge / Captcha"
	} else if resp.StatusCode == 451 || resp.StatusCode >= 500 {
		res.Status = "blocked"
		res.Message = "Geo-blocked or service error"
	} else {
		res.Status = "ok" // 400, 401, 404 normal for api endpoints without auth tokens
	}

	return res
}

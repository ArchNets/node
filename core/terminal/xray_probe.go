package terminal

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	confserial "github.com/xtls/xray-core/infra/conf/serial"
	"golang.org/x/net/http2"
)

// XrayProbeOutcome holds timings and HTTP result from an in-memory xray-core E2E probe.
type XrayProbeOutcome struct {
	Success   bool
	HTTPCode  int
	ConnectMs int64
	TTFBMs    int64
	TotalMs   int64
	Error     string
}

// RunXrayProbe boots an isolated in-memory xray-core instance from configJSON (removing inbounds
// so no local ports are bound) and executes an HTTP GET to testURL through core.Dial.
func RunXrayProbe(ctx context.Context, configJSON string, testURL string) XrayProbeOutcome {
	if strings.TrimSpace(testURL) == "" {
		testURL = "https://www.gstatic.com/generate_204"
	}

	parsedURL, err := url.Parse(testURL)
	if err != nil {
		return XrayProbeOutcome{Error: fmt.Sprintf("invalid test_url: %v", err)}
	}

	confCfg, err := confserial.DecodeJSONConfig(strings.NewReader(configJSON))
	if err != nil {
		return XrayProbeOutcome{Error: fmt.Sprintf("decode xray config failed: %v", err)}
	}
	// Clear inbounds so we never conflict with local ports; we dial directly via core.Dial
	confCfg.InboundConfigs = nil

	pbCfg, err := confCfg.Build()
	if err != nil {
		return XrayProbeOutcome{Error: fmt.Sprintf("build xray config failed: %v", err)}
	}

	inst, err := core.New(pbCfg)
	if err != nil {
		return XrayProbeOutcome{Error: fmt.Sprintf("init xray instance failed: %v", err)}
	}
	if err := inst.Start(); err != nil {
		_ = inst.Close()
		return XrayProbeOutcome{Error: fmt.Sprintf("start xray instance failed: %v", err)}
	}
	defer func() {
		_ = inst.Close()
	}()

	var connectMs int64
	start := time.Now()

	dialer := func(dCtx context.Context, network, addr string) (net.Conn, error) {
		dest, pErr := xnet.ParseDestination(network + ":" + addr)
		if pErr != nil {
			return nil, pErr
		}
		conn, dErr := core.Dial(dCtx, inst, dest)
		if dErr == nil && connectMs == 0 {
			connectMs = time.Since(start).Milliseconds()
		}
		return conn, dErr
	}

	transport := &http.Transport{
		DialContext:         dialer,
		DisableKeepAlives:   true,
		TLSHandshakeTimeout: 8 * time.Second,
		TLSClientConfig: &tls.Config{
			ServerName: parsedURL.Hostname(),
			MinVersion: tls.VersionTLS12,
		},
	}
	_ = http2.ConfigureTransport(transport)

	client := &http.Client{
		Transport: transport,
		Timeout:   15 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, testURL, nil)
	if err != nil {
		return XrayProbeOutcome{Error: err.Error()}
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36")

	resp, err := client.Do(req)
	ttfbMs := time.Since(start).Milliseconds()
	if err != nil {
		return XrayProbeOutcome{
			ConnectMs: connectMs,
			TTFBMs:    ttfbMs,
			TotalMs:   ttfbMs,
			Error:     err.Error(),
		}
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64*1024))
	totalMs := time.Since(start).Milliseconds()

	ok := resp.StatusCode >= 200 && resp.StatusCode < 400
	return XrayProbeOutcome{
		Success:   ok,
		HTTPCode:  resp.StatusCode,
		ConnectMs: connectMs,
		TTFBMs:    ttfbMs,
		TotalMs:   totalMs,
	}
}

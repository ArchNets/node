package core

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/outbound"
)

type dummyAddr struct{}

func (dummyAddr) Network() string { return "tcp" }
func (dummyAddr) String() string  { return "127.0.0.1:12345" }

type linkReader struct {
	reader   buf.Reader
	leftover buf.MultiBuffer
}

func (r *linkReader) Read(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	if r.leftover.IsEmpty() {
		mb, err := r.reader.ReadMultiBuffer()
		if err != nil {
			return 0, err
		}
		r.leftover = mb
	}
	var n int
	r.leftover, n = buf.SplitFirstBytes(r.leftover, b)
	return n, nil
}

type linkWriter struct {
	writer buf.Writer
}

func (w *linkWriter) Write(b []byte) (int, error) {
	if len(b) == 0 {
		return 0, nil
	}
	mb := buf.MergeBytes(nil, b)
	err := w.writer.WriteMultiBuffer(mb)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

type xrayConn struct {
	r      *linkReader
	w      *linkWriter
	closer func() error
}

func (c *xrayConn) Read(b []byte) (int, error) {
	return c.r.Read(b)
}

func (c *xrayConn) Write(b []byte) (int, error) {
	return c.w.Write(b)
}

func (c *xrayConn) Close() error {
	if c.closer != nil {
		return c.closer()
	}
	return nil
}

func (c *xrayConn) LocalAddr() net.Addr            { return dummyAddr{} }
func (c *xrayConn) RemoteAddr() net.Addr           { return dummyAddr{} }
func (c *xrayConn) SetDeadline(t time.Time) error  { return nil }
func (c *xrayConn) SetReadDeadline(t time.Time) error { return nil }
func (c *xrayConn) SetWriteDeadline(t time.Time) error { return nil }

var fallbackEndpoints = []string{
	"162.159.192.1:2408",
	"162.159.192.1:500",
	"162.159.192.1:1701",
	"162.159.192.1:4500",
	"188.114.97.1:2408",
	"188.114.97.1:500",
	"188.114.97.1:1701",
	"188.114.97.1:4500",
}

func (c *XrayCore) getNextEndpoint(tag string, originalEndpoint string) string {
	if c.wgEndpointIndex == nil {
		c.wgEndpointIndex = make(map[string]int)
	}
	idx := c.wgEndpointIndex[tag]
	// Increment index for the next call
	c.wgEndpointIndex[tag] = (idx + 1) % (len(fallbackEndpoints) + 1)

	if idx == 0 {
		// Try dynamic re-resolution of original endpoint
		endpoint := originalEndpoint
		if endpoint != "" {
			host, port, err := net.SplitHostPort(endpoint)
			if err == nil {
				if ip := net.ParseIP(host); ip == nil {
					ctx, cancel := context.WithTimeout(c.watchdogCtx, 2*time.Second)
					ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
					cancel()
					if err == nil && len(ips) > 0 {
						var targetIP net.IP
						for _, ip := range ips {
							if ip.To4() != nil {
								targetIP = ip
								break
							}
						}
						if targetIP == nil {
							targetIP = ips[0]
						}
						return net.JoinHostPort(targetIP.String(), port)
					}
				} else {
					return endpoint
				}
			}
		}
		// If original endpoint resolution fails, fall back to first pool endpoint
		idx = 1
		c.wgEndpointIndex[tag] = 2
	}

	return fallbackEndpoints[idx-1]
}

// DialOutbound dials a connection forced through a specific outbound tag.
func (v *XrayCore) DialOutbound(ctx context.Context, tag string, dest xnet.Destination) (net.Conn, error) {
	// Force outbound tag
	ctx = session.SetForcedOutboundTagToContext(ctx, tag)

	outbounds := session.OutboundsFromContext(ctx)
	if len(outbounds) == 0 {
		outbounds = []*session.Outbound{{}}
		ctx = session.ContextWithOutbounds(ctx, outbounds)
	}
	ob := outbounds[len(outbounds)-1]
	ob.OriginalTarget = dest
	ob.Target = dest

	link, err := v.dispatcher.Dispatch(ctx, dest)
	if err != nil {
		return nil, err
	}

	conn := &xrayConn{
		r: &linkReader{reader: link.Reader},
		w: &linkWriter{writer: link.Writer},
		closer: func() error {
			common.Close(link.Writer)
			common.Interrupt(link.Reader)
			return nil
		},
	}
	return conn, nil
}

func (v *XrayCore) RemoveOutbound(tag string) error {
	ctx, cancel := context.WithTimeout(v.watchdogCtx, 10*time.Second)
	defer cancel()
	return v.ohm.RemoveHandler(ctx, tag)
}

func (v *XrayCore) AddOutbound(config *core.OutboundHandlerConfig) error {
	rawHandler, err := core.CreateObject(v.Server, config)
	if err != nil {
		return err
	}
	handler, ok := rawHandler.(outbound.Handler)
	if !ok {
		return fmt.Errorf("not an OutboundHandler")
	}
	ctx, cancel := context.WithTimeout(v.watchdogCtx, 10*time.Second)
	defer cancel()
	if err := v.ohm.AddHandler(ctx, handler); err != nil {
		return err
	}
	return nil
}

func (c *XrayCore) testWireguardConnection(ctx context.Context, tag string) error {
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
		Timeout:   8 * time.Second,
	}

	req, err := http.NewRequestWithContext(ctx, "GET", "http://cp.cloudflare.com/generate_204", nil)
	if err != nil {
		return err
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 204 && resp.StatusCode != 200 {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
	return nil
}

func (c *XrayCore) WireguardWatchdog() error {
	if c.wgHandlerMissing == nil {
		c.wgHandlerMissing = make(map[string]bool)
	}
	for tag, config := range c.wgOutbounds {
		var err error
		if c.wgHandlerMissing[tag] {
			err = fmt.Errorf("handler is missing from previous cycle")
		} else {
			ctx, cancel := context.WithTimeout(c.watchdogCtx, 10*time.Second)
			err = c.testWireguardConnection(ctx, tag)
			cancel()
		}

		if err != nil {
			if c.wgHandlerMissing[tag] {
				log.WithField("tag", tag).Warn("WireGuard handler is missing, attempting recovery...")
			} else {
				c.wgFailures[tag]++
				log.WithFields(log.Fields{
					"tag":      tag,
					"err":      err,
					"failures": c.wgFailures[tag],
				}).Warn("WireGuard connection test failed")
			}

			if c.wgHandlerMissing[tag] || c.wgFailures[tag] >= 3 {
				c.wgFailures[tag] = 0

				// Resolve next endpoint and rebuild the config
				origEndpoint := config.Outbound.WireguardPeerEndpoint
				newEndpoint := c.getNextEndpoint(tag, origEndpoint)
				log.WithFields(log.Fields{
					"tag":             tag,
					"new_endpoint":    newEndpoint,
					"endpoint_index":  c.wgEndpointIndex[tag],
				}).Info("Rebuilding WireGuard config with rotated/re-resolved endpoint")

				newConfig, err := BuildWireguardOutbound(config.Outbound, newEndpoint)
				if err != nil {
					log.WithFields(log.Fields{
						"tag": tag,
						"err": err,
					}).Error("Failed to rebuild wireguard outbound config")
					continue
				}

				// If it wasn't already missing, remove it first
				if !c.wgHandlerMissing[tag] {
					if err := c.RemoveOutbound(tag); err != nil {
						log.WithFields(log.Fields{
							"tag": tag,
							"err": err,
						}).Error("Failed to remove wireguard outbound handler")
					}
				}

				var addErr error
				for attempt := 1; attempt <= 3; attempt++ {
					addErr = c.AddOutbound(newConfig)
					if addErr == nil {
						break
					}
					log.WithFields(log.Fields{
						"tag":     tag,
						"attempt": attempt,
						"err":     addErr,
					}).Error("Failed to add wireguard outbound handler, retrying in 2s...")

					select {
					case <-time.After(2 * time.Second):
					case <-c.watchdogCtx.Done():
						return nil // abort recovery, shutting down
					}
				}

				if addErr != nil {
					log.WithFields(log.Fields{
						"tag": tag,
						"err": addErr,
					}).Error("Failed to add wireguard outbound handler after retries")
					c.wgHandlerMissing[tag] = true
				} else {
					// Update the stored config in wgOutbounds
					config.Config = newConfig
					c.wgHandlerMissing[tag] = false
					log.WithField("tag", tag).Info("Successfully recreated wireguard outbound handler")
				}
			}
		} else {
			if c.wgFailures[tag] > 0 {
				log.WithFields(log.Fields{
					"tag":          tag,
					"old_failures": c.wgFailures[tag],
				}).Info("WireGuard connection recovered")
				c.wgFailures[tag] = 0
			}
		}
	}
	return nil
}

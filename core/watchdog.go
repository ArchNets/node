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
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
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
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
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
	for tag, config := range c.wgOutbounds {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		err := c.testWireguardConnection(ctx, tag)
		cancel()

		if err != nil {
			c.wgFailures[tag]++
			log.WithFields(log.Fields{
				"tag":      tag,
				"err":      err,
				"failures": c.wgFailures[tag],
			}).Warn("WireGuard connection test failed")

			if c.wgFailures[tag] >= 3 {
				log.WithField("tag", tag).Warn("WireGuard outbound failed 3 consecutive times, recreating...")
				c.wgFailures[tag] = 0

				// Recreate the outbound handler
				if err := c.RemoveOutbound(tag); err != nil {
					log.WithFields(log.Fields{
						"tag": tag,
						"err": err,
					}).Error("Failed to remove wireguard outbound handler")
				}
				if err := c.AddOutbound(config); err != nil {
					log.WithFields(log.Fields{
						"tag": tag,
						"err": err,
					}).Error("Failed to add wireguard outbound handler")
				} else {
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

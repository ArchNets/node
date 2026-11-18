package routing

import (
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/archnets/node/core/relay/telemetry"
	"github.com/archnets/node/core/relay/transport"
	log "github.com/sirupsen/logrus"
)

type halfCloser interface {
	CloseWrite() error
}

func closeHalf(c net.Conn) {
	if hc, ok := c.(halfCloser); ok {
		_ = hc.CloseWrite()
	} else {
		_ = c.Close()
	}
}

var gateActivatedLog sync.Map

func logGateActivationOnce(port int, flowMode string) {
	if _, loaded := gateActivatedLog.LoadOrStore(port, struct{}{}); !loaded {
		log.WithFields(log.Fields{
			"port":     port,
			"flowMode": flowMode,
		}).Info("[Relay] L4 Flow Direction Gate active on forwarder")
	}
}

// HandleEntryTCPClient handles a client connection on Entry by claiming a reverse stream,
// writing the 3-byte routing header, and running zero-copy SpliceCopy bidirectionally.
func HandleEntryTCPClient(clientConn net.Conn, targetPort uint16, claimStreamFn func(timeout time.Duration) (net.Conn, error), stats *telemetry.Stats, ruleOpt ...*ForwarderRule) {
	defer clientConn.Close()

	stream, err := claimStreamFn(10 * time.Second)
	if err != nil {
		log.WithFields(log.Fields{
			"targetPort": targetPort,
			"client":     clientConn.RemoteAddr().String(),
			"err":        err,
		}).Warn("[Relay] Client TCP connection dropped: reverse pool is empty (waiting for Exit server to connect)")
		return
	}
	defer stream.Close()

	log.WithFields(log.Fields{
		"targetPort": targetPort,
		"client":     clientConn.RemoteAddr().String(),
	}).Info("[Relay] Splicing client connection to Exit target port")

	_ = stream.SetWriteDeadline(time.Now().Add(3 * time.Second))
	if err := WriteRoutingHeader(stream, RouteProtoTCP, targetPort); err != nil {
		return
	}
	_ = stream.SetWriteDeadline(time.Time{})

	if stats != nil {
		stats.ActiveConnections.Add(1)
		defer stats.ActiveConnections.Add(-1)
	}

	var rule *ForwarderRule
	if len(ruleOpt) > 0 {
		rule = ruleOpt[0]
	}

	var gate *FlowGate
	if rule != nil && rule.FlowMode == "download_only" {
		gate = NewFlowGate(*rule)
		defer gate.Close()
		logGateActivationOnce(int(targetPort), rule.FlowMode)
	}

	done := make(chan error, 2)
	go func() {
		var err error
		defer func() {
			closeHalf(stream)
			done <- err
		}()
		var counter *atomic.Int64
		if stats != nil {
			counter = &stats.TotalUploadBytes
		}
		if gate != nil {
			// download_only: Upload is restricted
			_, err = telemetry.SpliceCopy(stream, gate.WrapReader(clientConn), counter)
		} else {
			_, err = telemetry.SpliceCopy(stream, clientConn, counter)
		}
	}()
	go func() {
		var err error
		defer func() {
			closeHalf(clientConn)
			done <- err
		}()
		var counter *atomic.Int64
		if stats != nil {
			counter = &stats.TotalDownloadBytes
		}
		if gate != nil {
			// download_only: Download is allowed; feeds gate
			_, err = telemetry.SpliceCopyWithCallback(clientConn, stream, counter, func(n int) {
				gate.AddAllowed(n)
			})
		} else {
			_, err = telemetry.SpliceCopy(clientConn, stream, counter)
		}
	}()
	isGated := (rule != nil && rule.FlowMode != "" && rule.FlowMode != "bidirectional") || gate != nil
	if !isGated {
		// Bidirectional: preserve original behavior and force-close both ends on first completion
		<-done
		_ = stream.Close()
		_ = clientConn.Close()
		<-done
		return
	}
	// Gated: allow half-close with bounded 10s linger
	err1 := <-done
	if err1 != nil {
		_ = stream.Close()
		_ = clientConn.Close()
		<-done
		return
	}
	select {
	case <-done:
	case <-time.After(10 * time.Second):
	}
	_ = stream.Close()
	_ = clientConn.Close()
}

// HandleExitTCPForward connects to the local target port on Exit and splices bytes to stream.
func HandleExitTCPForward(stream net.Conn, targetIP string, targetPort uint16, stats *telemetry.Stats, ruleOpt ...*ForwarderRule) {
	defer stream.Close()

	if targetIP == "" {
		targetIP = "127.0.0.1"
	}
	targetAddr := net.JoinHostPort(targetIP, strconv.Itoa(int(targetPort)))
	targetConn, err := net.DialTimeout("tcp", targetAddr, 3*time.Second)
	if err != nil {
		time.Sleep(50 * time.Millisecond)
		targetConn, err = net.DialTimeout("tcp", targetAddr, 3*time.Second)
	}
	if err != nil {
		log.WithFields(log.Fields{
			"targetAddr": targetAddr,
			"err":        err,
		}).Warn("[Relay] Exit failed to connect to local target service (is service listening on target port?)")
		return
	}
	defer targetConn.Close()
	transport.TuneTCPConn(targetConn)

	log.WithFields(log.Fields{
		"targetAddr": targetAddr,
	}).Info("[Relay] Exit successfully connected to local target service")

	if stats != nil {
		stats.ActiveConnections.Add(1)
		defer stats.ActiveConnections.Add(-1)
	}

	var rule *ForwarderRule
	if len(ruleOpt) > 0 {
		rule = ruleOpt[0]
	}

	var gate *FlowGate
	if rule != nil && rule.FlowMode == "upload_only" {
		gate = NewFlowGate(*rule)
		defer gate.Close()
		logGateActivationOnce(int(targetPort), rule.FlowMode)
	}

	done := make(chan error, 2)
	go func() {
		var err error
		defer func() {
			closeHalf(targetConn)
			done <- err
		}()
		var counter *atomic.Int64
		if stats != nil {
			counter = &stats.TotalUploadBytes
		}
		if gate != nil {
			// upload_only: Upload is allowed; feeds gate
			_, err = telemetry.SpliceCopyWithCallback(targetConn, stream, counter, func(n int) {
				gate.AddAllowed(n)
			})
		} else {
			_, err = telemetry.SpliceCopy(targetConn, stream, counter)
		}
	}()
	go func() {
		var err error
		defer func() {
			closeHalf(stream)
			done <- err
		}()
		var counter *atomic.Int64
		if stats != nil {
			counter = &stats.TotalDownloadBytes
		}
		if gate != nil {
			// upload_only: Download is restricted
			_, err = telemetry.SpliceCopy(stream, gate.WrapReader(targetConn), counter)
		} else {
			_, err = telemetry.SpliceCopy(stream, targetConn, counter)
		}
	}()
	isGated := (rule != nil && rule.FlowMode != "" && rule.FlowMode != "bidirectional") || gate != nil
	if !isGated {
		// Bidirectional: preserve original behavior and force-close both ends on first completion
		<-done
		_ = stream.Close()
		_ = targetConn.Close()
		<-done
		return
	}
	// Gated: allow half-close (e.g. final HTTP 200 after upload EOF) with bounded 10s linger
	err1 := <-done
	if err1 != nil {
		_ = stream.Close()
		_ = targetConn.Close()
		<-done
		return
	}
	select {
	case <-done:
	case <-time.After(10 * time.Second):
	}
	_ = stream.Close()
	_ = targetConn.Close()
}

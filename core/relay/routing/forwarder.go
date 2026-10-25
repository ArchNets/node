package routing

import (
	"net"
	"strconv"
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

// HandleEntryTCPClient handles a client connection on Entry by claiming a reverse stream,
// writing the 3-byte routing header, and running zero-copy SpliceCopy bidirectionally.
func HandleEntryTCPClient(clientConn net.Conn, targetPort uint16, claimStreamFn func(timeout time.Duration) (net.Conn, error), stats *telemetry.Stats) {
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

	done := make(chan struct{}, 2)
	go func() {
		defer func() {
			closeHalf(stream)
			done <- struct{}{}
		}()
		var counter *atomic.Int64
		if stats != nil {
			counter = &stats.TotalUploadBytes
		}
		_, _ = telemetry.SpliceCopy(stream, clientConn, counter)
	}()
	go func() {
		defer func() {
			closeHalf(clientConn)
			done <- struct{}{}
		}()
		var counter *atomic.Int64
		if stats != nil {
			counter = &stats.TotalDownloadBytes
		}
		_, _ = telemetry.SpliceCopy(clientConn, stream, counter)
	}()
	<-done
	<-done
}

// HandleExitTCPForward connects to the local target port on Exit and splices bytes to stream.
func HandleExitTCPForward(stream net.Conn, targetIP string, targetPort uint16, stats *telemetry.Stats) {
	defer stream.Close()

	if targetIP == "" {
		targetIP = "127.0.0.1"
	}
	targetAddr := net.JoinHostPort(targetIP, strconv.Itoa(int(targetPort)))
	targetConn, err := net.DialTimeout("tcp", targetAddr, 5*time.Second)
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

	done := make(chan struct{}, 2)
	go func() {
		defer func() {
			closeHalf(targetConn)
			done <- struct{}{}
		}()
		var counter *atomic.Int64
		if stats != nil {
			counter = &stats.TotalUploadBytes
		}
		_, _ = telemetry.SpliceCopy(targetConn, stream, counter)
	}()
	go func() {
		defer func() {
			closeHalf(stream)
			done <- struct{}{}
		}()
		var counter *atomic.Int64
		if stats != nil {
			counter = &stats.TotalDownloadBytes
		}
		_, _ = telemetry.SpliceCopy(stream, targetConn, counter)
	}()
	<-done
	<-done
}

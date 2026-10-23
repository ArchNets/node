package telemetry

import (
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/archnets/node/core/relay/protocol"
)

const (
	ProbeChunkSize = 1300
)

// BandwidthSample represents a point-in-time bandwidth and health measurement over stream 0xFF.
type BandwidthSample struct {
	Timestamp    int64   `json:"timestamp"`
	UploadMbps   float64 `json:"upload_mbps"`
	DownloadMbps float64 `json:"download_mbps"`
	RttMs        int     `json:"rtt_ms"`
	JitterMs     int     `json:"jitter_ms"`
	PacketLoss   int     `json:"packet_loss"`
	Status       string  `json:"status"` // "OPTIMAL", "DEGRADED", "THROTTLED"
}

func ClassifyProbeStatus(uploadMbps, downloadMbps float64, rttMs, packetLoss int) string {
	if (uploadMbps == 0 && downloadMbps == 0) || packetLoss >= 50 {
		return "THROTTLED"
	}
	if downloadMbps < 10 || uploadMbps < 5 || packetLoss > 20 {
		return "THROTTLED"
	}
	if downloadMbps < 50 || uploadMbps < 25 || rttMs > 250 || packetLoss > 5 {
		return "DEGRADED"
	}
	return "OPTIMAL"
}

// HandleExitProbeStream processes stream 0xFF on the Exit server.
func HandleExitProbeStream(stream net.Conn, stats *Stats) {
	defer stream.Close()
	_ = stream.SetDeadline(time.Now().Add(30 * time.Second))

	var prefix [7]byte
	if _, err := io.ReadFull(stream, prefix[:]); err != nil {
		return
	}

	cmdPrefix := string(prefix[:])
	switch {
	case strings.HasPrefix(cmdPrefix, "PING000"):
		var b [1]byte
		if _, err := io.ReadFull(stream, b[:]); err != nil {
			return
		}
		if _, err := stream.Write([]byte("PONG0000")); err != nil {
			return
		}
		var pingBuf [8]byte
		for {
			_ = stream.SetReadDeadline(time.Now().Add(3 * time.Second))
			if _, err := io.ReadFull(stream, pingBuf[:]); err != nil {
				return
			}
			if string(pingBuf[:]) != "PING0000" {
				return
			}
			_ = stream.SetWriteDeadline(time.Now().Add(3 * time.Second))
			if _, err := stream.Write([]byte("PONG0000")); err != nil {
				return
			}
		}

	case cmdPrefix == "UPLOAD:":
		durSec := readDurationLine(stream)
		if durSec <= 0 {
			durSec = 2
		}
		if durSec > 15 {
			durSec = 15
		}
		_ = stream.SetReadDeadline(time.Now().Add(time.Duration(durSec+3) * time.Second))
		buf := make([]byte, 32*1024)
		var totalReceived uint64
		for {
			n, err := stream.Read(buf)
			if n > 0 {
				if idx := indexUploadDone(buf[:n]); idx >= 0 {
					totalReceived += uint64(idx)
					break
				}
				totalReceived += uint64(n)
			}
			if err != nil {
				break
			}
		}
		if stats != nil {
			stats.AddUpload(int64(totalReceived))
		}
		var resp [8]byte
		binary.BigEndian.PutUint64(resp[:], totalReceived)
		_ = stream.SetWriteDeadline(time.Now().Add(3 * time.Second))
		_, _ = stream.Write(resp[:])

	case cmdPrefix == "DNLOAD:":
		durSec := readDurationLine(stream)
		if durSec <= 0 {
			durSec = 2
		}
		if durSec > 15 {
			durSec = 15
		}
		chunk := make([]byte, ProbeChunkSize*24)
		for i := range chunk {
			chunk[i] = byte(i & 0xFF)
		}
		deadline := time.Now().Add(time.Duration(durSec) * time.Second)
		_ = stream.SetWriteDeadline(deadline.Add(2 * time.Second))
		var totalSent int64
		for time.Now().Before(deadline) {
			n, err := stream.Write(chunk)
			if n > 0 {
				totalSent += int64(n)
			}
			if err != nil {
				break
			}
		}
		if stats != nil {
			stats.AddDownload(totalSent)
		}
	}
}

var uploadDoneMarker = []byte("__ARCHNET_UP_EOF__")

func indexUploadDone(b []byte) int {
	return strings.Index(string(b), string(uploadDoneMarker))
}

func readDurationLine(r io.Reader) int {
	var line []byte
	var b [1]byte
	for len(line) < 8 {
		if _, err := r.Read(b[:]); err != nil {
			break
		}
		if b[0] == '\n' {
			break
		}
		line = append(line, b[0])
	}
	v, _ := strconv.Atoi(strings.TrimSpace(string(line)))
	return v
}

// MeasureLatency measures control control/probe RTT over stream 0xFF.
func MeasureLatency(claimStreamFn func(timeout time.Duration) (net.Conn, error), stats *Stats) (int, error) {
	stream, err := claimStreamFn(2 * time.Second)
	if err != nil {
		return 0, err
	}
	defer stream.Close()

	_ = stream.SetDeadline(time.Now().Add(3 * time.Second))
	if err := protocol.WriteRoutingHeader(stream, protocol.RouteProtoProbe, 0); err != nil {
		return 0, err
	}

	start := time.Now()
	if _, err := stream.Write([]byte("PING0000")); err != nil {
		return 0, err
	}
	var pong [8]byte
	if _, err := io.ReadFull(stream, pong[:]); err != nil {
		return 0, err
	}
	if string(pong[:]) != "PONG0000" {
		return 0, fmt.Errorf("unexpected pong response: %q", string(pong[:]))
	}
	rtt := int(time.Since(start).Milliseconds())
	if rtt <= 0 {
		rtt = 1
	}
	if stats != nil {
		stats.LatencyMs.Store(int64(rtt))
	}
	return rtt, nil
}

// RunBandwidthProbe executes a full PING + UPLOAD + DNLOAD burst over stream 0xFF.
func RunBandwidthProbe(claimStreamFn func(timeout time.Duration) (net.Conn, error), stats *Stats, duration time.Duration) (*BandwidthSample, error) {
	if duration <= 0 {
		duration = 2 * time.Second
	}
	durSec := int(math.Ceil(duration.Seconds()))
	if durSec < 1 {
		durSec = 1
	}

	rttMs, jitterMs, packetLoss := measurePingSeries(claimStreamFn, 5)

	uploadBps, err := measureUploadBurst(claimStreamFn, stats, duration, durSec)
	if err != nil {
		return nil, fmt.Errorf("upload probe failed: %w", err)
	}

	downloadBps, err := measureDownloadBurst(claimStreamFn, stats, duration, durSec)
	if err != nil {
		return nil, fmt.Errorf("download probe failed: %w", err)
	}

	uploadMbps := math.Round((float64(uploadBps)*8.0/1_000_000.0)*100) / 100
	downloadMbps := math.Round((float64(downloadBps)*8.0/1_000_000.0)*100) / 100
	status := ClassifyProbeStatus(uploadMbps, downloadMbps, rttMs, packetLoss)

	if rttMs > 0 && stats != nil {
		stats.LatencyMs.Store(int64(rttMs))
	}
	if stats != nil {
		stats.SetLastProbeResult(uploadMbps, downloadMbps, status)
	}

	sample := &BandwidthSample{
		Timestamp:    time.Now().Unix(),
		UploadMbps:   uploadMbps,
		DownloadMbps: downloadMbps,
		RttMs:        rttMs,
		JitterMs:     jitterMs,
		PacketLoss:   packetLoss,
		Status:       status,
	}
	return sample, nil
}

func measurePingSeries(claimStreamFn func(timeout time.Duration) (net.Conn, error), count int) (avgRttMs, jitterMs, lossPct int) {
	stream, err := claimStreamFn(3 * time.Second)
	if err != nil {
		return 0, 0, 100
	}
	defer stream.Close()

	_ = stream.SetDeadline(time.Now().Add(5 * time.Second))
	if err := protocol.WriteRoutingHeader(stream, protocol.RouteProtoProbe, 0); err != nil {
		return 0, 0, 100
	}

	var rtts []int64
	var pong [8]byte
	for i := 0; i < count; i++ {
		start := time.Now()
		if _, err := stream.Write([]byte("PING0000")); err != nil {
			break
		}
		if _, err := io.ReadFull(stream, pong[:]); err != nil || string(pong[:]) != "PONG0000" {
			break
		}
		ms := time.Since(start).Milliseconds()
		if ms <= 0 {
			ms = 1
		}
		rtts = append(rtts, ms)
	}

	if len(rtts) == 0 {
		return 0, 0, 100
	}

	var sum int64
	for _, r := range rtts {
		sum += r
	}
	avg := sum / int64(len(rtts))

	var dev float64
	for _, r := range rtts {
		dev += math.Abs(float64(r - avg))
	}
	jitter := int(dev / float64(len(rtts)))
	loss := int(float64(count-len(rtts)) / float64(count) * 100)

	return int(avg), jitter, loss
}

func measureUploadBurst(claimStreamFn func(timeout time.Duration) (net.Conn, error), stats *Stats, duration time.Duration, durSec int) (int64, error) {
	stream, err := claimStreamFn(4 * time.Second)
	if err != nil {
		return 0, err
	}
	defer stream.Close()

	_ = stream.SetDeadline(time.Now().Add(duration + 5*time.Second))
	if err := protocol.WriteRoutingHeader(stream, protocol.RouteProtoProbe, 0); err != nil {
		return 0, err
	}

	cmd := fmt.Sprintf("UPLOAD:%d\n", durSec)
	if _, err := stream.Write([]byte(cmd)); err != nil {
		return 0, err
	}

	chunk := make([]byte, ProbeChunkSize*16)
	for i := range chunk {
		chunk[i] = byte((i + 1) & 0x7F)
	}

	start := time.Now()
	deadline := start.Add(duration)
	var sentBytes int64
	for time.Now().Before(deadline) {
		n, wErr := stream.Write(chunk)
		if n > 0 {
			sentBytes += int64(n)
		}
		if wErr != nil {
			break
		}
	}
	_, _ = stream.Write(uploadDoneMarker)

	var resp [8]byte
	if _, err := io.ReadFull(stream, resp[:]); err == nil {
		srvBytes := int64(binary.BigEndian.Uint64(resp[:]))
		if srvBytes > 0 {
			sentBytes = srvBytes
		}
	}

	elapsed := time.Since(start).Seconds()
	if elapsed <= 0 {
		elapsed = duration.Seconds()
	}
	if stats != nil {
		stats.AddUpload(sentBytes)
	}
	return int64(float64(sentBytes) / elapsed), nil
}

func measureDownloadBurst(claimStreamFn func(timeout time.Duration) (net.Conn, error), stats *Stats, duration time.Duration, durSec int) (int64, error) {
	stream, err := claimStreamFn(4 * time.Second)
	if err != nil {
		return 0, err
	}
	defer stream.Close()

	_ = stream.SetDeadline(time.Now().Add(duration + 5*time.Second))
	if err := protocol.WriteRoutingHeader(stream, protocol.RouteProtoProbe, 0); err != nil {
		return 0, err
	}

	cmd := fmt.Sprintf("DNLOAD:%d\n", durSec)
	if _, err := stream.Write([]byte(cmd)); err != nil {
		return 0, err
	}

	buf := make([]byte, 32*1024)
	start := time.Now()
	deadline := start.Add(duration)
	var receivedBytes int64
	for time.Now().Before(deadline) {
		n, rErr := stream.Read(buf)
		if n > 0 {
			receivedBytes += int64(n)
		}
		if rErr != nil {
			break
		}
	}
	elapsed := time.Since(start).Seconds()
	if elapsed <= 0 {
		elapsed = duration.Seconds()
	}
	if stats != nil {
		stats.AddDownload(receivedBytes)
	}
	return int64(float64(receivedBytes) / elapsed), nil
}

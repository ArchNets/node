package telemetry

import (
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/archnets/node/core/relay/protocol"
)

const (
	ProbeChunkSize        = 1300
	ProbeHighThroughputSz = 128 * 1024 // 128 KiB matching WaterWall SpeedTestClient payload-size
	ProbeParallelStreams  = 4          // 4 parallel streams matching WaterWall SpeedTestClient connection-count
)

// probeHighEntropyChunk is pre-initialized once with TLS 1.3 ApplicationData headers (0x17 0x03 0x03)
// and deterministic xorshift pseudo-random bytes so DPI entropy filters see genuine TLS 1.3 records.
var probeHighEntropyChunk = func() []byte {
	b := make([]byte, ProbeHighThroughputSz)
	seed := uint32(0xA5A55A5A)
	for i := 0; i < len(b); i++ {
		v := seed + uint32(i)
		v ^= v >> 13
		v *= 0x85EBCA6B
		v ^= v >> 16
		b[i] = byte(v)
	}
	// Stamp TLS 1.3 ApplicationData headers every 16 KiB boundary
	for off := 0; off+16384 <= len(b); off += 16384 {
		b[off+0] = 0x17
		b[off+1] = 0x03
		b[off+2] = 0x03
		b[off+3] = 0x3F
		b[off+4] = 0xFB
	}
	return b
}()

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
		_ = stream.SetReadDeadline(time.Now().Add(time.Duration(durSec+4) * time.Second))
		buf := make([]byte, ProbeHighThroughputSz)
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
		deadline := time.Now().Add(time.Duration(durSec) * time.Second)
		_ = stream.SetWriteDeadline(deadline.Add(2 * time.Second))
		var totalSent int64
		for time.Now().Before(deadline) {
			n, err := stream.Write(probeHighEntropyChunk)
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

// claimProbeStreams claims 1 primary stream (up to 4s) and up to n-1 extra warm streams (15ms each)
// for multi-stream bandwidth measurement matching WaterWall's SpeedTestClient.
func claimProbeStreams(claimStreamFn func(timeout time.Duration) (net.Conn, error), maxStreams int) ([]net.Conn, error) {
	first, err := claimStreamFn(4 * time.Second)
	if err != nil {
		return nil, err
	}
	streams := make([]net.Conn, 0, maxStreams)
	streams = append(streams, first)
	for i := 1; i < maxStreams; i++ {
		s, err := claimStreamFn(15 * time.Millisecond)
		if err != nil || s == nil {
			break
		}
		streams = append(streams, s)
	}
	return streams, nil
}

func measureUploadBurst(claimStreamFn func(timeout time.Duration) (net.Conn, error), stats *Stats, duration time.Duration, durSec int) (int64, error) {
	streams, err := claimProbeStreams(claimStreamFn, ProbeParallelStreams)
	if err != nil {
		return 0, err
	}
	defer func() {
		for _, s := range streams {
			_ = s.Close()
		}
	}()

	// Coalesce 3-byte routing header + UPLOAD command into a single write
	cmdStr := fmt.Sprintf("UPLOAD:%d\n", durSec)
	initPkt := make([]byte, 3+len(cmdStr))
	initPkt[0] = protocol.RouteProtoProbe
	initPkt[1] = 0
	initPkt[2] = 0
	copy(initPkt[3:], cmdStr)

	var totalBytes atomic.Int64
	var wg sync.WaitGroup
	start := time.Now()
	deadline := start.Add(duration)

	for _, stream := range streams {
		wg.Add(1)
		go func(s net.Conn) {
			defer wg.Done()
			_ = s.SetDeadline(time.Now().Add(duration + 5*time.Second))
			if _, err := s.Write(initPkt); err != nil {
				return
			}
			var sent int64
			for time.Now().Before(deadline) {
				n, wErr := s.Write(probeHighEntropyChunk)
				if n > 0 {
					sent += int64(n)
				}
				if wErr != nil {
					break
				}
			}
			_, _ = s.Write(uploadDoneMarker)

			var resp [8]byte
			if _, err := io.ReadFull(s, resp[:]); err == nil {
				srvBytes := int64(binary.BigEndian.Uint64(resp[:]))
				if srvBytes > 0 {
					sent = srvBytes
				}
			}
			totalBytes.Add(sent)
		}(stream)
	}
	wg.Wait()

	sentBytes := totalBytes.Load()
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
	streams, err := claimProbeStreams(claimStreamFn, ProbeParallelStreams)
	if err != nil {
		return 0, err
	}
	defer func() {
		for _, s := range streams {
			_ = s.Close()
		}
	}()

	// Coalesce 3-byte routing header + DNLOAD command into a single write
	cmdStr := fmt.Sprintf("DNLOAD:%d\n", durSec)
	initPkt := make([]byte, 3+len(cmdStr))
	initPkt[0] = protocol.RouteProtoProbe
	initPkt[1] = 0
	initPkt[2] = 0
	copy(initPkt[3:], cmdStr)

	var totalBytes atomic.Int64
	var firstByteOnce sync.Once
	var measureStart time.Time
	var wg sync.WaitGroup

	for _, stream := range streams {
		wg.Add(1)
		go func(s net.Conn) {
			defer wg.Done()
			_ = s.SetDeadline(time.Now().Add(duration + 5*time.Second))
			if _, err := s.Write(initPkt); err != nil {
				return
			}

			buf := make([]byte, ProbeHighThroughputSz)
			// Read first chunk to exclude command RTT from download throughput window
			nFirst, rErr := s.Read(buf)
			if nFirst > 0 {
				firstByteOnce.Do(func() {
					measureStart = time.Now()
				})
				totalBytes.Add(int64(nFirst))
			}
			if rErr != nil {
				return
			}

			streamDeadline := time.Now().Add(duration)
			for time.Now().Before(streamDeadline) {
				n, err := s.Read(buf)
				if n > 0 {
					totalBytes.Add(int64(n))
				}
				if err != nil {
					break
				}
			}
		}(stream)
	}
	wg.Wait()

	receivedBytes := totalBytes.Load()
	var elapsed float64
	if !measureStart.IsZero() {
		elapsed = time.Since(measureStart).Seconds()
	}
	if elapsed <= 0.05 {
		elapsed = duration.Seconds()
	}
	if stats != nil {
		stats.AddDownload(receivedBytes)
	}
	return int64(float64(receivedBytes) / elapsed), nil
}

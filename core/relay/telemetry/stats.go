package telemetry

import (
	"io"
	"math"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Stats holds lock-free atomic telemetry counters for a single relay tunnel instance.
type Stats struct {
	TotalUploadBytes    atomic.Int64
	TotalDownloadBytes  atomic.Int64
	CurrentUploadBps    atomic.Int64
	CurrentDownloadBps  atomic.Int64
	ActiveConnections   atomic.Int64
	PoolIdleConnections atomic.Int64
	LatencyMs           atomic.Int64

	// Last reported values for computing delta on status push
	lastReportedUpload   atomic.Int64
	lastReportedDownload atomic.Int64

	// Rolling throughput window state
	lastWindowUpload   atomic.Int64
	lastWindowDownload atomic.Int64
	lastWindowUnixNano atomic.Int64

	// Latest bandwidth probe metrics
	lastProbeUploadBits   atomic.Uint64
	lastProbeDownloadBits atomic.Uint64
	lastProbeStatus       atomic.Value // string: "OPTIMAL", "DEGRADED", "THROTTLED"
}

// NewStats initializes a new Stats tracker.
func NewStats() *Stats {
	s := &Stats{}
	s.lastWindowUnixNano.Store(time.Now().UnixNano())
	s.lastProbeStatus.Store("OPTIMAL")
	return s
}

// AddUpload increments total uploaded bytes.
func (s *Stats) AddUpload(n int64) {
	if n > 0 {
		s.TotalUploadBytes.Add(n)
	}
}

// AddDownload increments total downloaded bytes.
func (s *Stats) AddDownload(n int64) {
	if n > 0 {
		s.TotalDownloadBytes.Add(n)
	}
}

// SnapshotDelta returns the upload and download byte deltas since the last SnapshotDelta call.
func (s *Stats) SnapshotDelta() (deltaUp, deltaDown int64) {
	curUp := s.TotalUploadBytes.Load()
	curDown := s.TotalDownloadBytes.Load()

	prevUp := s.lastReportedUpload.Swap(curUp)
	prevDown := s.lastReportedDownload.Swap(curDown)

	if curUp >= prevUp {
		deltaUp = curUp - prevUp
	} else {
		deltaUp = curUp
	}
	if curDown >= prevDown {
		deltaDown = curDown - prevDown
	} else {
		deltaDown = curDown
	}
	return deltaUp, deltaDown
}

// UpdateRollingThroughput recalculates CurrentUploadBps and CurrentDownloadBps over the elapsed interval.
func (s *Stats) UpdateRollingThroughput() {
	now := time.Now().UnixNano()
	prevTime := s.lastWindowUnixNano.Swap(now)
	elapsedSec := float64(now-prevTime) / float64(time.Second)
	if elapsedSec <= 0.1 {
		return
	}

	curUp := s.TotalUploadBytes.Load()
	curDown := s.TotalDownloadBytes.Load()
	prevUp := s.lastWindowUpload.Swap(curUp)
	prevDown := s.lastWindowDownload.Swap(curDown)

	upDiff := curUp - prevUp
	if upDiff < 0 {
		upDiff = 0
	}
	downDiff := curDown - prevDown
	if downDiff < 0 {
		downDiff = 0
	}

	s.CurrentUploadBps.Store(int64(float64(upDiff) / elapsedSec))
	s.CurrentDownloadBps.Store(int64(float64(downDiff) / elapsedSec))
}

// SetLastProbeResult records the latest bandwidth probe speeds (in Mbps) and health status.
func (s *Stats) SetLastProbeResult(uploadMbps, downloadMbps float64, status string) {
	s.lastProbeUploadBits.Store(math.Float64bits(uploadMbps))
	s.lastProbeDownloadBits.Store(math.Float64bits(downloadMbps))
	if status != "" {
		s.lastProbeStatus.Store(status)
	}
}

// GetLastProbeResult retrieves the latest bandwidth probe speeds (in Mbps) and health status.
func (s *Stats) GetLastProbeResult() (uploadMbps, downloadMbps float64, status string) {
	uploadMbps = math.Float64frombits(s.lastProbeUploadBits.Load())
	downloadMbps = math.Float64frombits(s.lastProbeDownloadBits.Load())
	if v := s.lastProbeStatus.Load(); v != nil {
		status, _ = v.(string)
	}
	if status == "" {
		status = "OPTIMAL"
	}
	return uploadMbps, downloadMbps, status
}

var relayBufferPool = sync.Pool{
	New: func() any {
		b := make([]byte, 64*1024)
		return &b
	},
}

// SpliceCopy moves data from src to dst.
// If both src and dst are *net.TCPConn on Linux, it runs zero-copy kernel splice(2) via 1 MiB pipes.
// Otherwise, it falls back to a pooled 64KB user-space buffer loop.
func SpliceCopy(dst io.Writer, src io.Reader, counter *atomic.Int64) (int64, error) {
	dstTCP, okDst := dst.(*net.TCPConn)
	srcTCP, okSrc := src.(*net.TCPConn)
	if okDst && okSrc {
		var total int64
		handled, err := spliceRelay(dstTCP, srcTCP, func(n int) {
			total += int64(n)
			if counter != nil {
				counter.Add(int64(n))
			}
		})
		if handled {
			return total, err
		}
	}

	bufPtr := relayBufferPool.Get().(*[]byte)
	defer relayBufferPool.Put(bufPtr)
	buf := *bufPtr

	var total int64
	for {
		nr, rErr := src.Read(buf)
		if nr > 0 {
			nw, wErr := dst.Write(buf[:nr])
			if nw > 0 {
				total += int64(nw)
				if counter != nil {
					counter.Add(int64(nw))
				}
			}
			if wErr != nil {
				return total, wErr
			}
		}
		if rErr != nil {
			if rErr == io.EOF {
				return total, nil
			}
			return total, rErr
		}
	}
}

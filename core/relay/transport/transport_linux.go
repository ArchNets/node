//go:build linux

package transport

import (
	"net"
	"os"
	"sync"

	"golang.org/x/sys/unix"
)

var kernelTuneOnce sync.Once

// ensureLinuxKernelTCPTuning applies best-effort high-BDP sysctl parameters when running with root privileges.
// Matches WaterWall's 16 MiB buffer ceilings and disables slow-start-after-idle for pooled reverse connections.
func ensureLinuxKernelTCPTuning() {
	kernelTuneOnce.Do(func() {
		sysctls := map[string]string{
			"/proc/sys/net/core/rmem_max":                  "16777216",
			"/proc/sys/net/core/wmem_max":                  "16777216",
			"/proc/sys/net/ipv4/tcp_rmem":                  "4096 262144 16777216",
			"/proc/sys/net/ipv4/tcp_wmem":                  "4096 262144 16777216",
			"/proc/sys/net/ipv4/tcp_slow_start_after_idle": "0",
			"/proc/sys/net/ipv4/tcp_window_scaling":        "1",
		}
		for path, val := range sysctls {
			_ = os.WriteFile(path, []byte(val+"\n"), 0644)
		}
	})
}

func setPlatformTCPTune(tc *net.TCPConn) {
	ensureLinuxKernelTCPTuning()
	if raw, err := tc.SyscallConn(); err == nil {
		_ = raw.Control(func(fd uintptr) {
			// Request BBR congestion control on Linux
			_ = unix.SetsockoptString(int(fd), unix.IPPROTO_TCP, unix.TCP_CONGESTION, "bbr")
			// Enable TCP_QUICKACK to accelerate slow-start window growth over high-RTT links
			_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_QUICKACK, 1)
		})
	}
}

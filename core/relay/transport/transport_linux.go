//go:build linux

package transport

import (
	"net"
	"os"
	"sync"
	"sync/atomic"
	"syscall"

	"golang.org/x/sys/unix"
)

var (
	kernelTuneOnce sync.Once
	configuredMTU  atomic.Int32
)

// attachSocketBPFProtocolFilter attaches an in-kernel Classic BPF filter to a raw PacketConn.
// The filter drops all packets whose IPv4 protocol byte (offset 9) does not match proto directly
// inside the Linux network driver before Go allocates buffers or memory.
func attachSocketBPFProtocolFilter(pc net.PacketConn, proto byte) error {
	sc, ok := pc.(syscall.Conn)
	if !ok {
		return nil
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		return err
	}
	var sockErr error
	err = raw.Control(func(fd uintptr) {
		filter := []unix.SockFilter{
			{Code: unix.BPF_LD | unix.BPF_B | unix.BPF_ABS, K: 9},
			{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 1, K: uint32(proto)},
			{Code: unix.BPF_RET | unix.BPF_K, K: 0},
			{Code: unix.BPF_RET | unix.BPF_K, K: 65535},
		}
		prog := unix.SockFprog{
			Len:    uint16(len(filter)),
			Filter: &filter[0],
		}
		sockErr = unix.SetsockoptSockFprog(int(fd), unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &prog)
	})
	if err != nil {
		return err
	}
	return sockErr
}
// SetSocketQoS marks IP_TOS = 0xB8 (DSCP 46 Expedited Forwarding) on Linux to prioritize game datagrams.
func SetSocketQoS(conn any) {
	if sc, ok := conn.(syscall.Conn); ok {
		if raw, err := sc.SyscallConn(); err == nil {
			_ = raw.Control(func(fd uintptr) {
				_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_TOS, 0xB8)
			})
		}
	}
}

func SetConfiguredMTU(mtu int) {
	if mtu >= 576 && mtu <= 9000 {
		configuredMTU.Store(int32(mtu))
	} else {
		configuredMTU.Store(0)
	}
}

// GetConfiguredMTU returns the currently configured server tunnel MTU (or 1500 if unset).
func GetConfiguredMTU() int {
	v := int(configuredMTU.Load())
	if v <= 0 {
		return 1500
	}
	return v
}

// socketPreHandshakeControl runs on the raw socket FD BEFORE bind()/listen()/connect().
// Setting TCP_MAXSEG here ensures the Linux kernel advertises the clamped MSS in SYN and SYN-ACK packets.
func socketPreHandshakeControl(network, address string, c syscall.RawConn) error {
	ensureLinuxKernelTCPTuning()
	mtu := int(configuredMTU.Load())
	_ = c.Control(func(fd uintptr) {
		_ = unix.SetsockoptString(int(fd), unix.IPPROTO_TCP, unix.TCP_CONGESTION, "bbr")
		if mtu >= 576 && mtu < 1500 {
			mss := mtu - 40
			_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_MAXSEG, mss)
		}
	})
	return nil
}

// ensureLinuxKernelTCPTuning applies best-effort high-BDP sysctl parameters when running with root privileges.
// Matches WaterWall 1.5.2's 128 MiB buffer ceilings, 250k backlog, and sets tcp_no_metrics_save=1 so temporary
// border congestion does not degrade TCP throughput permanently.
func ensureLinuxKernelTCPTuning() {
	kernelTuneOnce.Do(func() {
		sysctls := map[string]string{
			"/proc/sys/net/core/rmem_max":                  "134217728",
			"/proc/sys/net/core/wmem_max":                  "134217728",
			"/proc/sys/net/ipv4/tcp_rmem":                  "4096 87380 134217728",
			"/proc/sys/net/ipv4/tcp_wmem":                  "4096 87380 134217728",
			"/proc/sys/net/core/netdev_max_backlog":         "250000",
			"/proc/sys/net/core/somaxconn":                 "65535",
			"/proc/sys/net/ipv4/tcp_no_metrics_save":        "1",
			"/proc/sys/net/ipv4/tcp_slow_start_after_idle": "0",
			"/proc/sys/net/ipv4/tcp_window_scaling":        "1",
			"/proc/sys/net/ipv4/tcp_mtu_probing":           "1",
		}
		for path, val := range sysctls {
			_ = os.WriteFile(path, []byte(val+"\n"), 0644)
		}
	})
}

func setPlatformTCPTune(tc *net.TCPConn) {
	ensureLinuxKernelTCPTuning()
	mtu := int(configuredMTU.Load())
	if raw, err := tc.SyscallConn(); err == nil {
		_ = raw.Control(func(fd uintptr) {
			// Request BBR congestion control on Linux
			_ = unix.SetsockoptString(int(fd), unix.IPPROTO_TCP, unix.TCP_CONGESTION, "bbr")
			// Enable TCP_QUICKACK to accelerate slow-start window growth over high-RTT links
			_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_QUICKACK, 1)
			// Apply TCP_MAXSEG (MSS clamping = MTU - 40) when a custom sub-1500 MTU is configured
			if mtu >= 576 && mtu < 1500 {
				mss := mtu - 40
				_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_MAXSEG, mss)
			}
		})
	}
}

// ConfigureDontFragmentProbe sets IP_PMTUDISC_DO (DF=1, forbid fragmentation) and clamps TCP_MAXSEG
// on the underlying TCP socket(s) of c so Path MTU probes strictly test unfragmented delivery.
func ConfigureDontFragmentProbe(c net.Conn, testMTU int) {
	applyTo := func(tc *net.TCPConn) {
		if tc == nil {
			return
		}
		if raw, err := tc.SyscallConn(); err == nil {
			_ = raw.Control(func(fd uintptr) {
				_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_PMTUDISC, unix.IP_PMTUDISC_DO)
				if testMTU >= 576 && testMTU <= 1500 {
					_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_MAXSEG, testMTU-40)
				}
			})
		}
	}
	if tc, ok := c.(*net.TCPConn); ok {
		applyTo(tc)
		return
	}
	if hd, ok := c.(*HalfDuplexConn); ok {
		applyTo(hd.ReadTCPConn())
		applyTo(hd.WriteTCPConn())
	}
}

// InspectKernelPMTU queries the Linux kernel's TCP_INFO and IP_MTU socket options to read
// the discovered Path MTU (tcpi_pmtu / IP_MTU) and active Send MSS (tcpi_snd_mss).
func InspectKernelPMTU(c net.Conn) (pmtu int, sndMSS int) {
	inspectOne := func(tc *net.TCPConn) (int, int) {
		if tc == nil {
			return 0, 0
		}
		raw, err := tc.SyscallConn()
		if err != nil {
			return 0, 0
		}
		var p, m int
		_ = raw.Control(func(fd uintptr) {
			if ipMTU, err := unix.GetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_MTU); err == nil && ipMTU >= 576 {
				p = ipMTU
			}
			if info, err := unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO); err == nil && info != nil {
				if p == 0 || (int(info.Pmtu) >= 576 && int(info.Pmtu) < p) {
					p = int(info.Pmtu)
				}
				m = int(info.Snd_mss)
				// On loopback (pmtu=65535) or when MSS clamping is active on the route/socket,
				// derive the effective MTU from Snd_mss if it is clamped below standard 1500-byte Ethernet MSS (1448 with timestamps).
				if m > 0 && m < 1448 {
					clampedMTU := m + 52 // 20B IP + 20B TCP + 12B TCP timestamps
					if clampedMTU > 1500 {
						clampedMTU = 1500
					}
					if p > 1500 || clampedMTU < p {
						p = clampedMTU
					}
				} else if p > 1500 {
					p = 1500
				}
			}
		})
		return p, m
	}

	if tc, ok := c.(*net.TCPConn); ok {
		return inspectOne(tc)
	}
	if hd, ok := c.(*HalfDuplexConn); ok {
		p1, m1 := inspectOne(hd.WriteTCPConn())
		p2, m2 := inspectOne(hd.ReadTCPConn())
		if p2 > 0 && (p1 == 0 || p2 < p1) {
			p1 = p2
		}
		if m2 > 0 && (m1 == 0 || m2 < m1) {
			m1 = m2
		}
		return p1, m1
	}
	return 0, 0
}

func isTCPConnAlive(tc *net.TCPConn) bool {
	if tc == nil {
		return false
	}
	raw, err := tc.SyscallConn()
	if err != nil {
		return false
	}
	alive := true
	_ = raw.Control(func(fd uintptr) {
		var buf [1]byte
		n, _, recvErr := unix.Recvfrom(int(fd), buf[:], unix.MSG_PEEK|unix.MSG_DONTWAIT)
		if n == 0 && recvErr == nil {
			alive = false
		} else if recvErr != nil && recvErr != unix.EAGAIN && recvErr != unix.EWOULDBLOCK && recvErr != unix.EINTR {
			alive = false
		}
	})
	return alive
}

type StreamAliveChecker interface {
	IsAlive() bool
}

// IsStreamAlive performs a zero-cost non-blocking check (MSG_PEEK | MSG_DONTWAIT)
// to verify that a pooled reverse connection has not received FIN (EOF) or RST from the peer.
func IsStreamAlive(c net.Conn) bool {
	if c == nil {
		return false
	}
	if ac, ok := c.(StreamAliveChecker); ok {
		return ac.IsAlive()
	}
	if tc, ok := c.(*net.TCPConn); ok {
		return isTCPConnAlive(tc)
	}
	if hd, ok := c.(*HalfDuplexConn); ok {
		if rTC := hd.ReadTCPConn(); rTC != nil && !isTCPConnAlive(rTC) {
			return false
		}
		if wTC := hd.WriteTCPConn(); wTC != nil && !isTCPConnAlive(wTC) {
			return false
		}
		return true
	}
	return true
}

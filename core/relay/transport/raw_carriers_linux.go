//go:build linux

package transport

import (
	"encoding/binary"
	"errors"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
)

func htons(v uint16) uint16 {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], v)
	return binary.NativeEndian.Uint16(b[:])
}

func isVirtualInterface(name string) bool {
	lower := strings.ToLower(name)
	prefixes := []string{"docker", "veth", "wtun", "antun", "antbs", "wg", "tun", "tap", "br-", "virbr"}
	for _, p := range prefixes {
		if strings.HasPrefix(lower, p) {
			return true
		}
	}
	return false
}

func findDefaultGatewayInterface(dstHint net.IP) (*net.Interface, net.IP, error) {
	dstStr := "1.1.1.1:80"
	if dstHint != nil && !dstHint.IsUnspecified() && !dstHint.IsLoopback() {
		dstStr = net.JoinHostPort(dstHint.String(), "80")
	}
	conn, err := net.Dial("udp4", dstStr)
	if err == nil {
		defer conn.Close()
		if ua, ok := conn.LocalAddr().(*net.UDPAddr); ok && ua.IP != nil {
			if iface, local, fErr := findInterfaceByIP(ua.IP); fErr == nil {
				return iface, local, nil
			}
		}
	}
	return findInterfaceByIP(nil)
}

func findInterfaceByIP(localIP net.IP) (*net.Interface, net.IP, error) {
	v4 := localIP.To4()
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, nil, err
	}

	// Pass 1: If a specific localIP was requested, or when auto-discovering, prefer a physical
	// interface carrying a public (non-RFC1918) IPv4 address (e.g. eth0 91.107.255.40 / 194.5.188.55).
	for pass := 0; pass < 2; pass++ {
		for _, iface := range ifaces {
			if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
				continue
			}
			if (v4 == nil || v4.IsUnspecified()) && isVirtualInterface(iface.Name) {
				continue
			}
			addrs, err := iface.Addrs()
			if err != nil {
				continue
			}
			for _, a := range addrs {
				ipNet, ok := a.(*net.IPNet)
				if !ok || ipNet.IP == nil {
					continue
				}
				ip4 := ipNet.IP.To4()
				if ip4 == nil || ip4.IsLoopback() || ip4.IsLinkLocalUnicast() {
					continue
				}
				if v4 != nil && !v4.IsUnspecified() {
					if ip4.Equal(v4) {
						cp := iface
						return &cp, ip4, nil
					}
					continue
				}
				if pass == 0 && ip4.IsPrivate() {
					continue
				}
				cp := iface
				return &cp, ip4, nil
			}
		}
	}
	return nil, nil, errors.New("no active non-loopback IPv4 interface found")
}

// afPacketIPv4Conn implements net.PacketConn using Backhaul IPX's dual-socket architecture:
// - RX: AF_PACKET (SOCK_DGRAM, ETH_P_IP) bound to the physical interface with a socket-local
//   Classic BPF filter matching the exact IPv4 protocol number (and destination TCP/UDP port when applicable).
//   This captures packets directly from the NIC driver before kernel ipip/gre/conntrack modules can drop them.
// - TX: AF_INET (SOCK_RAW) with IP_HDRINCL=1 and SO_BINDTODEVICE so complete IPv4 packets
//   (including custom source IPs for spoofing) are transmitted directly onto the wire.
type afPacketIPv4Conn struct {
	rx          int
	tx          int
	wake        int
	proto       byte
	localIP     net.IP
	ifaceName   string
	closed      atomic.Bool
	closeOnce   sync.Once
	readMu      sync.Mutex
	writeMu     sync.Mutex
	readBuf     []byte
	readEnd     atomic.Int64 // UnixNano deadline
	ipIDCounter atomic.Uint32
}

// openPlatformRawIPv4Conn opens an AF_PACKET + IP_HDRINCL raw IPv4 socket pair on Linux
// when running as root on a non-loopback address. Returns (nil, error) if unavailable so
// callers can fall back to standard net.ListenPacket.
func openPlatformRawIPv4Conn(proto byte, bindHost string, ifaceHint string, localPort uint16) (net.PacketConn, error) {
	var parsedBind net.IP
	if bindHost != "" && bindHost != "0.0.0.0" {
		parsedBind = net.ParseIP(bindHost)
		if parsedBind != nil && parsedBind.IsLoopback() {
			return nil, errors.New("loopback uses standard packet socket")
		}
	}

	var iface *net.Interface
	var localIP net.IP
	var err error
	if ifaceHint != "" {
		if iface, err = net.InterfaceByName(ifaceHint); err == nil {
			if addrs, aErr := iface.Addrs(); aErr == nil {
				for _, a := range addrs {
					if ipNet, ok := a.(*net.IPNet); ok && ipNet.IP.To4() != nil {
						localIP = ipNet.IP.To4()
						break
					}
				}
			}
		}
	}
	if iface == nil || localIP == nil {
		iface, localIP, err = findDefaultGatewayInterface(parsedBind)
		if err != nil {
			return nil, err
		}
	}

	rx, err := unix.Socket(unix.AF_PACKET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, int(htons(unix.ETH_P_IP)))
	if err != nil {
		return nil, err
	}
	ok := false
	tx := -1
	wake := -1
	defer func() {
		if !ok {
			if rx >= 0 {
				_ = unix.Close(rx)
			}
			if tx >= 0 {
				_ = unix.Close(tx)
			}
			if wake >= 0 {
				_ = unix.Close(wake)
			}
		}
	}()

	if err = unix.Bind(rx, &unix.SockaddrLinklayer{
		Protocol: htons(unix.ETH_P_IP),
		Ifindex:  iface.Index,
	}); err != nil {
		return nil, err
	}

	// Build socket-local Classic BPF filter:
	// If localPort > 0 on TCP (6) or UDP (17), also filter L4 destination port (X + 2) in kernel
	// so high-volume TCP traffic (port 443, SSH) is never copied to userspace.
	var filter []unix.SockFilter
	if localPort > 0 && (proto == 6 || proto == 17) {
		filter = []unix.SockFilter{
			{Code: unix.BPF_LD | unix.BPF_B | unix.BPF_ABS, K: 9},
			{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 0, Jf: 4, K: uint32(proto)},
			{Code: unix.BPF_LDX | unix.BPF_B | unix.BPF_MSH, K: 0},
			{Code: unix.BPF_LD | unix.BPF_H | unix.BPF_IND, K: 2},
			{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 0, Jf: 1, K: uint32(localPort)},
			{Code: unix.BPF_RET | unix.BPF_K, K: 65535},
			{Code: unix.BPF_RET | unix.BPF_K, K: 0},
		}
	} else {
		filter = []unix.SockFilter{
			{Code: unix.BPF_LD | unix.BPF_B | unix.BPF_ABS, K: 9},
			{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, Jt: 1, K: uint32(proto)},
			{Code: unix.BPF_RET | unix.BPF_K, K: 0},
			{Code: unix.BPF_RET | unix.BPF_K, K: 65535},
		}
	}
	prog := unix.SockFprog{
		Len:    uint16(len(filter)),
		Filter: &filter[0],
	}
	if err = unix.SetsockoptSockFprog(rx, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &prog); err != nil {
		return nil, err
	}
	_ = unix.SetsockoptInt(rx, unix.SOL_SOCKET, unix.SO_RCVBUF, 8*1024*1024)

	tx, err = unix.Socket(unix.AF_INET, unix.SOCK_RAW|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, int(proto))
	if err != nil {
		return nil, err
	}
	if err = unix.SetsockoptInt(tx, unix.IPPROTO_IP, unix.IP_HDRINCL, 1); err != nil {
		return nil, err
	}
	_ = unix.SetsockoptString(tx, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, iface.Name)
	if ip4 := localIP.To4(); ip4 != nil {
		var bindAddr unix.SockaddrInet4
		copy(bindAddr.Addr[:], ip4)
		_ = unix.Bind(tx, &bindAddr)
	}
	_ = unix.SetsockoptInt(tx, unix.SOL_SOCKET, unix.SO_SNDBUF, 8*1024*1024)

	wake, err = unix.Eventfd(0, unix.EFD_CLOEXEC|unix.EFD_NONBLOCK)
	if err != nil {
		return nil, err
	}

	ok = true
	return &afPacketIPv4Conn{
		rx:        rx,
		tx:        tx,
		wake:      wake,
		proto:     proto,
		localIP:   localIP,
		ifaceName: iface.Name,
		readBuf:   make([]byte, 65535),
	}, nil
}

func (c *afPacketIPv4Conn) wait(fd int, events int16) error {
	for !c.closed.Load() {
		timeoutMs := 500
		if dl := c.readEnd.Load(); dl > 0 {
			rem := time.Until(time.Unix(0, dl))
			if rem <= 0 {
				return unix.ETIMEDOUT
			}
			if ms := int(rem.Milliseconds()); ms < timeoutMs {
				if ms <= 0 {
					ms = 1
				}
				timeoutMs = ms
			}
		}
		fds := []unix.PollFd{
			{Fd: int32(fd), Events: events},
			{Fd: int32(c.wake), Events: unix.POLLIN},
		}
		_, err := unix.Poll(fds, timeoutMs)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return err
		}
		if c.closed.Load() || fds[1].Revents != 0 {
			return net.ErrClosed
		}
		if fds[0].Revents&events != 0 {
			return nil
		}
		if dl := c.readEnd.Load(); dl > 0 && time.Now().UnixNano() >= dl {
			return unix.ETIMEDOUT
		}
	}
	return net.ErrClosed
}

// ReadFrom reads a complete IPv4 packet from AF_PACKET, validates its IPv4 header and protocol,
// strips the 20..60 byte IPv4 header (matching Go's IPConn.ReadFrom behavior), and returns the
// inner payload and sender *net.IPAddr.
func (c *afPacketIPv4Conn) ReadFrom(p []byte) (int, net.Addr, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	buf := c.readBuf
	for !c.closed.Load() {
		if err := c.wait(c.rx, unix.POLLIN); err != nil {
			return 0, nil, err
		}
		n, from, err := unix.Recvfrom(c.rx, buf, 0)
		if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return 0, nil, err
		}
		if link, ok := from.(*unix.SockaddrLinklayer); ok && link.Pkttype == unix.PACKET_OUTGOING {
			continue
		}
		if n < 20 || (buf[0]>>4) != 4 {
			continue
		}
		ihl := int(buf[0]&0x0F) * 4
		totalLen := int(binary.BigEndian.Uint16(buf[2:4]))
		if ihl < 20 || ihl > n || totalLen < ihl || buf[9] != c.proto {
			continue
		}
		if totalLen > n {
			totalLen = n
		}
		srcIP := net.IPv4(buf[12], buf[13], buf[14], buf[15])
		copied := copy(p, buf[ihl:totalLen])
		return copied, &net.IPAddr{IP: srcIP}, nil
	}
	return 0, nil, net.ErrClosed
}

func (c *afPacketIPv4Conn) WriteTo(p []byte, addr net.Addr) (int, error) {
	return c.WriteToWithIPOpts(p, addr, nil, 64, 0)
}

func (c *afPacketIPv4Conn) WriteToWithIPOpts(p []byte, addr net.Addr, srcIP net.IP, ttl byte, tos byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.closed.Load() {
		return 0, net.ErrClosed
	}

	host := addr.String()
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	dstIP := net.ParseIP(host)
	if dstIP == nil {
		if resolved, rErr := net.ResolveIPAddr("ip4", host); rErr == nil {
			dstIP = resolved.IP
		}
	}
	dst4 := dstIP.To4()
	if dst4 == nil {
		return 0, errors.New("invalid IPv4 destination")
	}

	src4 := c.localIP.To4()
	if srcIP != nil && srcIP.To4() != nil {
		src4 = srcIP.To4()
	}
	if src4 == nil || src4.IsUnspecified() {
		src4 = discoverLocalIPv4For(dst4).To4()
	}
	if ttl == 0 {
		ttl = 64
	}

	totalLen := 20 + len(p)
	pkt := make([]byte, totalLen)
	pkt[0] = 0x45
	pkt[1] = tos
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
	seq := uint16(c.ipIDCounter.Add(1))
	binary.BigEndian.PutUint16(pkt[4:6], seq)
	binary.BigEndian.PutUint16(pkt[6:8], 0x4000) // DF=1
	pkt[8] = ttl
	pkt[9] = c.proto
	copy(pkt[12:16], src4)
	copy(pkt[16:20], dst4)
	binary.BigEndian.PutUint16(pkt[10:12], internetChecksum(pkt[:20]))
	copy(pkt[20:], p)

	var sa unix.SockaddrInet4
	copy(sa.Addr[:], dst4)

	for !c.closed.Load() {
		err := unix.Sendto(c.tx, pkt, 0, &sa)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) {
			if wErr := c.wait(c.tx, unix.POLLOUT); wErr != nil {
				return 0, wErr
			}
			continue
		}
		if err != nil {
			return 0, err
		}
		return len(p), nil
	}
	return 0, net.ErrClosed
}

func (c *afPacketIPv4Conn) Close() error {
	c.closeOnce.Do(func() {
		c.closed.Store(true)
		if c.wake >= 0 {
			var b [8]byte
			binary.NativeEndian.PutUint64(b[:], 1)
			_, _ = unix.Write(c.wake, b[:])
		}
		if c.rx >= 0 {
			_ = unix.Close(c.rx)
		}
		if c.tx >= 0 {
			_ = unix.Close(c.tx)
		}
		if c.wake >= 0 {
			_ = unix.Close(c.wake)
		}
	})
	return nil
}

func (c *afPacketIPv4Conn) LocalAddr() net.Addr {
	return &net.IPAddr{IP: c.localIP}
}

func (c *afPacketIPv4Conn) SetDeadline(t time.Time) error {
	return c.SetReadDeadline(t)
}

func (c *afPacketIPv4Conn) SetReadDeadline(t time.Time) error {
	if t.IsZero() {
		c.readEnd.Store(0)
	} else {
		c.readEnd.Store(t.UnixNano())
	}
	if c.wake >= 0 {
		var b [8]byte
		binary.NativeEndian.PutUint64(b[:], 1)
		_, _ = unix.Write(c.wake, b[:])
	}
	return nil
}

func (c *afPacketIPv4Conn) SetWriteDeadline(t time.Time) error {
	return nil
}

package transport

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

const (
	icmpEchoRequest byte = 8
	icmpEchoReply   byte = 0

	xdiDirClientToServer byte = 0x01
	xdiDirServerToClient byte = 0x02
	xdiMetaLen                = 5 // [4B tunnelTag][1B direction]
)

// deriveXDITag derives a deterministic 4-byte tunnel tag from the shared password.
func deriveXDITag(password string) [4]byte {
	sum := sha256.Sum256([]byte("archnet-xdi-tag:" + password))
	var tag [4]byte
	copy(tag[:], sum[:4])
	return tag
}

// internetChecksum computes the RFC 1071 16-bit one's complement checksum.
func internetChecksum(data []byte) uint16 {
	var sum uint32
	length := len(data)
	for i := 0; i+1 < length; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	if length%2 == 1 {
		sum += uint32(data[length-1]) << 8
	}
	for (sum >> 16) > 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}

// tcpIPv4Checksum computes the RFC 793 TCP checksum over the IPv4 pseudo-header and TCP segment.
func tcpIPv4Checksum(srcIP, dstIP net.IP, tcpSegment []byte) uint16 {
	src4 := srcIP.To4()
	dst4 := dstIP.To4()
	if src4 == nil || dst4 == nil {
		return 0
	}
	var sum uint32
	sum += uint32(binary.BigEndian.Uint16(src4[0:2]))
	sum += uint32(binary.BigEndian.Uint16(src4[2:4]))
	sum += uint32(binary.BigEndian.Uint16(dst4[0:2]))
	sum += uint32(binary.BigEndian.Uint16(dst4[2:4]))
	sum += uint32(6) // IPPROTO_TCP
	sum += uint32(len(tcpSegment))

	length := len(tcpSegment)
	for i := 0; i+1 < length; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(tcpSegment[i : i+2]))
	}
	if length%2 == 1 {
		sum += uint32(tcpSegment[length-1]) << 8
	}
	for (sum >> 16) > 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}

// icmpPacketConn wraps a raw "ip4:icmp" net.PacketConn so that payloads written via WriteTo
// are encapsulated in valid ICMP Echo Request/Reply frames with a 5-byte [Tag(4B)+Dir(1B)] prefix.
// Filtering by both ICMP Type and Direction byte prevents the host kernel's automatic Echo Reply
// from being mistaken for a server reply or corrupting the client's handshake.
type icmpPacketConn struct {
	net.PacketConn
	isServer  bool
	ident     uint16
	tag       [4]byte
	seq       atomic.Uint32
	closeOnce sync.Once
	echoRule  []string
}

func (c *icmpPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	host := addr.String()
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	ipAddr, err := net.ResolveIPAddr("ip4", host)
	if err != nil {
		return 0, err
	}

	icmpType := icmpEchoRequest
	dirByte := xdiDirClientToServer
	if c.isServer {
		icmpType = icmpEchoReply
		dirByte = xdiDirServerToClient
	}
	seq := uint16(c.seq.Add(1))

	frame := make([]byte, 8+xdiMetaLen+len(p))
	frame[0] = icmpType
	frame[1] = 0
	binary.BigEndian.PutUint16(frame[4:6], c.ident)
	binary.BigEndian.PutUint16(frame[6:8], seq)
	copy(frame[8:12], c.tag[:])
	frame[12] = dirByte
	copy(frame[8+xdiMetaLen:], p)
	csum := internetChecksum(frame)
	binary.BigEndian.PutUint16(frame[2:4], csum)

	if _, err := c.PacketConn.WriteTo(frame, ipAddr); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *icmpPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	buf := make([]byte, 65535)
	expectedType := icmpEchoReply
	expectedDir := xdiDirServerToClient
	if c.isServer {
		expectedType = icmpEchoRequest
		expectedDir = xdiDirClientToServer
	}

	for {
		n, addr, err := c.PacketConn.ReadFrom(buf)
		if err != nil {
			return 0, nil, err
		}
		if n < 8+xdiMetaLen {
			continue
		}
		// Reject wrong ICMP type or kernel auto-echoed requests
		if buf[0] != expectedType {
			continue
		}
		ident := binary.BigEndian.Uint16(buf[4:6])
		if ident != c.ident {
			continue
		}
		if !bytes.Equal(buf[8:12], c.tag[:]) || buf[12] != expectedDir {
			continue
		}
		copied := copy(p, buf[8+xdiMetaLen:n])
		return copied, &net.UDPAddr{IP: net.ParseIP(addr.String()), Port: int(c.ident)}, nil
	}
}

func (c *icmpPacketConn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		if len(c.echoRule) > 0 {
			sweepIptablesRule("filter", c.echoRule)
		}
		err = c.PacketConn.Close()
	})
	return err
}

// installXDIEchoGuard installs a narrow iptables u32 rule on the server to drop the kernel's
// automatic ICMP Echo Replies for this tunnel's identifier, preventing uplink doubling.
func installXDIEchoGuard(ident uint16) []string {
	if _, err := exec.LookPath("iptables"); err != nil {
		return nil
	}
	rule := []string{
		"OUTPUT", "-p", "icmp", "--icmp-type", "echo-reply",
		"-m", "u32", "--u32", fmt.Sprintf("0>>22&0x3C@4>>16=%d", ident),
		"-j", "DROP",
	}
	sweepIptablesRule("filter", rule)
	if exec.Command("iptables", append([]string{"-w", "2", "-t", "filter", "-I"}, rule...)...).Run() == nil {
		return rule
	}
	return nil
}

// pckPacketConn implements BackPack's "pck" stateless raw TCP packet carrier over "ip4:tcp".
// It stamps each datagram inside a valid TCP PSH+ACK segment without kernel TCP state,
// and installs a refcounted iptables RST + NOTRACK guard on the port.
type pckPacketConn struct {
	net.PacketConn
	isServer  bool
	localPort uint16
	peerPort  uint16
	seq       atomic.Uint32
	ack       atomic.Uint32
	closeOnce sync.Once
	guardPort uint16
}

func newPCKPacketConn(rawConn net.PacketConn, isServer bool, localPort, peerPort uint16) *pckPacketConn {
	var seed [4]byte
	_, _ = rand.Read(seed[:])
	p := &pckPacketConn{
		PacketConn: rawConn,
		isServer:   isServer,
		localPort:  localPort,
		peerPort:   peerPort,
		guardPort:  localPort,
	}
	p.seq.Store(binary.BigEndian.Uint32(seed[:]) | 0x10000)
	p.ack.Store(0x20000)
	installPCKPortGuard(localPort)
	return p
}

func (c *pckPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	host, portStr, err := net.SplitHostPort(addr.String())
	if err != nil {
		host = addr.String()
	}
	dstPort := c.peerPort
	if pNum, pErr := strconv.Atoi(portStr); pErr == nil && pNum > 0 {
		dstPort = uint16(pNum)
	}
	ipAddr, err := net.ResolveIPAddr("ip4", host)
	if err != nil {
		return 0, err
	}

	seg := make([]byte, 20+len(p))
	binary.BigEndian.PutUint16(seg[0:2], c.localPort)
	binary.BigEndian.PutUint16(seg[2:4], dstPort)
	seq := c.seq.Add(uint32(len(p)))
	binary.BigEndian.PutUint32(seg[4:8], seq)
	binary.BigEndian.PutUint32(seg[8:12], c.ack.Load())
	seg[12] = 5 << 4 // 20-byte TCP header (Data Offset = 5)
	seg[13] = 0x18   // PSH | ACK
	binary.BigEndian.PutUint16(seg[14:16], 65535)
	copy(seg[20:], p)

	srcIP := discoverLocalIPv4For(ipAddr.IP)
	csum := tcpIPv4Checksum(srcIP, ipAddr.IP, seg)
	binary.BigEndian.PutUint16(seg[16:18], csum)

	if _, err := c.PacketConn.WriteTo(seg, ipAddr); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *pckPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	buf := make([]byte, 65535)
	for {
		n, addr, err := c.PacketConn.ReadFrom(buf)
		if err != nil {
			return 0, nil, err
		}
		if n < 20 {
			continue
		}
		srcPort := binary.BigEndian.Uint16(buf[0:2])
		dstPort := binary.BigEndian.Uint16(buf[2:4])
		if dstPort != c.localPort {
			continue
		}
		if !c.isServer && c.peerPort > 0 && srcPort != c.peerPort {
			continue
		}
		dataOffset := int(buf[12]>>4) * 4
		if dataOffset < 20 || n <= dataOffset {
			continue
		}
		peerSeq := binary.BigEndian.Uint32(buf[4:8])
		payloadLen := n - dataOffset
		c.ack.Store(peerSeq + uint32(payloadLen))

		copied := copy(p, buf[dataOffset:n])
		return copied, &net.UDPAddr{IP: net.ParseIP(addr.String()), Port: int(srcPort)}, nil
	}
}

func (c *pckPacketConn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		removePCKPortGuard(c.guardPort)
		err = c.PacketConn.Close()
	})
	return err
}

var (
	pckGuardMu   sync.Mutex
	pckGuardRefs = map[uint16]int{}
)

func pckRulesForPort(port uint16) [][]string {
	p := strconv.Itoa(int(port))
	return [][]string{
		{"raw", "PREROUTING", "-p", "tcp", "--dport", p, "-j", "NOTRACK"},
		{"raw", "OUTPUT", "-p", "tcp", "--sport", p, "-j", "NOTRACK"},
		{"filter", "OUTPUT", "-p", "tcp", "--sport", p, "--tcp-flags", "RST", "RST", "-j", "DROP"},
	}
}

func installPCKPortGuard(port uint16) {
	if port == 0 {
		return
	}
	pckGuardMu.Lock()
	defer pckGuardMu.Unlock()
	if pckGuardRefs[port] > 0 {
		pckGuardRefs[port]++
		return
	}
	if _, err := exec.LookPath("iptables"); err != nil {
		return
	}
	for _, r := range pckRulesForPort(port) {
		sweepIptablesRule(r[0], r[1:])
		_ = exec.Command("iptables", append([]string{"-w", "2", "-t", r[0], "-I"}, r[1:]...)...).Run()
	}
	pckGuardRefs[port] = 1
}

func removePCKPortGuard(port uint16) {
	if port == 0 {
		return
	}
	pckGuardMu.Lock()
	defer pckGuardMu.Unlock()
	if pckGuardRefs[port] <= 0 {
		return
	}
	pckGuardRefs[port]--
	if pckGuardRefs[port] > 0 {
		return
	}
	delete(pckGuardRefs, port)
	for _, r := range pckRulesForPort(port) {
		sweepIptablesRule(r[0], r[1:])
	}
}

func sweepIptablesRule(table string, body []string) {
	args := append([]string{"-w", "2", "-t", table, "-D"}, body...)
	for i := 0; i < 64; i++ {
		if exec.Command("iptables", args...).Run() != nil {
			return
		}
	}
}

func discoverLocalIPv4For(dst net.IP) net.IP {
	c, err := net.Dial("udp4", net.JoinHostPort(dst.String(), "80"))
	if err != nil {
		return net.IPv4(127, 0, 0, 1)
	}
	defer c.Close()
	if ua, ok := c.LocalAddr().(*net.UDPAddr); ok && ua.IP != nil {
		return ua.IP
	}
	return net.IPv4(127, 0, 0, 1)
}

// ListenXDICarrier starts an XDI (ICMP Echo) listener. If the process has CAP_NET_RAW / root,
// it binds a raw "ip4:icmp" socket with direction-tag filtering and iptables echo guard.
func ListenXDICarrier(addr, password string, port int) (*UDPCarrierListener, *net.UDPConn, error) {
 host, _, err := net.SplitHostPort(addr)
 if err != nil || host == "" {
  host = "0.0.0.0"
 }
 if os.Geteuid() == 0 && host != "127.0.0.1" {
  if rawConn, rErr := net.ListenPacket("ip4:icmp", host); rErr == nil {
   ident := uint16(port & 0xFFFF)
   wrapped := &icmpPacketConn{
    PacketConn: rawConn,
    isServer:   true,
    ident:      ident,
    tag:        deriveXDITag(password),
    echoRule:   installXDIEchoGuard(ident),
   }
   return newPacketCarrierListener(wrapped, nil, password, true), nil, nil
  }
 }
 return ListenUDPCarrier(addr, password, true)
}

// DialXDICarrier dials an XDI (ICMP Echo) session to addr.
func DialXDICarrier(ctx context.Context, addr, password string, port int) (net.Conn, error) {
 host, _, err := net.SplitHostPort(addr)
 if err != nil {
  host = addr
 }
 if os.Geteuid() == 0 && host != "127.0.0.1" {
  if rawConn, rErr := net.ListenPacket("ip4:icmp", "0.0.0.0"); rErr == nil {
   ident := uint16(port & 0xFFFF)
   wrapped := &icmpPacketConn{
    PacketConn: rawConn,
    isServer:   false,
    ident:      ident,
    tag:        deriveXDITag(password),
   }
   targetAddr := &net.UDPAddr{IP: net.ParseIP(host), Port: port}
   return dialPacketCarrier(ctx, wrapped, targetAddr, password, true)
  }
 }
 return DialUDPCarrier(ctx, addr, password, true)
}

// ListenPCKCarrier starts a PCK (Stateless Raw TCP Packet + KCP/FEC) carrier listener.
func ListenPCKCarrier(addr, password string) (*UDPCarrierListener, *net.UDPConn, error) {
 host, portStr, err := net.SplitHostPort(addr)
 if err != nil || host == "" {
  host = "0.0.0.0"
 }
 port, _ := strconv.Atoi(portStr)
 if os.Geteuid() == 0 && port > 0 && host != "127.0.0.1" {
  if rawConn, rErr := net.ListenPacket("ip4:tcp", host); rErr == nil {
   wrapped := newPCKPacketConn(rawConn, true, uint16(port), 0)
   return newPacketCarrierListener(wrapped, nil, password, true), nil, nil
  }
 }
 return ListenUDPCarrier(addr, password, true)
}

// DialPCKCarrier dials a PCK (Stateless Raw TCP Packet + KCP/FEC) carrier session.
func DialPCKCarrier(ctx context.Context, addr, password string) (net.Conn, error) {
 host, portStr, err := net.SplitHostPort(addr)
 if err != nil {
  host = addr
 }
 port, _ := strconv.Atoi(portStr)
 if os.Geteuid() == 0 && port > 0 && host != "127.0.0.1" {
  if rawConn, rErr := net.ListenPacket("ip4:tcp", "0.0.0.0"); rErr == nil {
   var rnd [2]byte
   _, _ = rand.Read(rnd[:])
   localPort := uint16(20000 + (int(rnd[0])<<8|int(rnd[1]))%25000)
   wrapped := newPCKPacketConn(rawConn, false, localPort, uint16(port))
   targetAddr := &net.UDPAddr{IP: net.ParseIP(host), Port: port}
   return dialPacketCarrier(ctx, wrapped, targetAddr, password, true)
  }
 }
 return DialUDPCarrier(ctx, addr, password, true)
}

// CheckRPFilterStatus checks /proc/sys/net/ipv4/conf/all/rp_filter on Linux (matching BackPack's ctStrictRPFilter).
func CheckRPFilterStatus() string {
	b, err := os.ReadFile("/proc/sys/net/ipv4/conf/all/rp_filter")
	if err != nil {
		return ""
	}
	if strings.TrimSpace(string(b)) == "1" {
		return "strict rp_filter=1 enabled (drops forged-source packets on arrival)"
	}
	return "loose/off (compatible with IP spoofing)"
}

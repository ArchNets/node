package transport

import (
	"bytes"
	"context"
	"crypto/hmac"
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

// deriveXDITag derives a deterministic 4-byte tunnel tag from the shared token.
func deriveXDITag(token string) [4]byte {
	return deriveScopedTag(token, 0, 0)
}

// deriveScopedTag derives a deterministic 4-byte tunnel tag scoped by password, protocol, and port.
// Scoping by port ensures multiple concurrent benchmark sandboxes on raw IP protocols (58, 4, 47, 1)
// never steal or misroute each other's packets.
func deriveScopedTag(token string, proto byte, port int) [4]byte {
	mac := hmac.New(sha256.New, []byte("archnet-xdi-tag-salt"))
	mac.Write([]byte(token))
	if proto != 0 || port > 0 {
		var meta [3]byte
		meta[0] = proto
		binary.BigEndian.PutUint16(meta[1:3], uint16(port&0xFFFF))
		mac.Write(meta[:])
	}
	sum := mac.Sum(nil)
	var tag [4]byte
	copy(tag[:], sum[:4])
	return tag
}

// udpIPv4Checksum computes the RFC 768 UDP checksum over the IPv4 pseudo-header and UDP datagram.
func udpIPv4Checksum(srcIP, dstIP net.IP, udpPkt []byte) uint16 {
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
	sum += uint32(17) // IPPROTO_UDP
	sum += uint32(len(udpPkt))

	length := len(udpPkt)
	for i := 0; i+1 < length; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(udpPkt[i : i+2]))
	}
	if length%2 == 1 {
		sum += uint32(udpPkt[length-1]) << 8
	}
	for (sum >> 16) > 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	csum := ^uint16(sum)
	if csum == 0 {
		return 0xFFFF
	}
	return csum
}

// openBestRawConn attempts to open a Backhaul IPX-grade AF_PACKET + IP_HDRINCL raw socket pair
// first, falling back to standard net.ListenPacket(network, host) when unavailable.
func openBestRawConn(proto byte, network, host, ifaceHint string, localPort uint16) (net.PacketConn, error) {
	if pc, err := openPlatformRawIPv4Conn(proto, host, ifaceHint, localPort); err == nil && pc != nil {
		return pc, nil
	}
	return net.ListenPacket(network, host)
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
	isServer    bool
	localPort   uint16
	peerPort    uint16
	tag         [4]byte
	seq         atomic.Uint32
	ack         atomic.Uint32
	closeOnce   sync.Once
	guardPort   uint16
	srcMu       sync.Mutex
	cachedSrcIP net.IP
}

func newPCKPacketConn(rawConn net.PacketConn, isServer bool, localPort, peerPort uint16, tag [4]byte) *pckPacketConn {
	var seed [4]byte
	_, _ = rand.Read(seed[:])
	p := &pckPacketConn{
		PacketConn: rawConn,
		isServer:   isServer,
		localPort:  localPort,
		peerPort:   peerPort,
		tag:        tag,
		guardPort:  localPort,
	}
	p.seq.Store(binary.BigEndian.Uint32(seed[:]) | 0x10000)
	p.ack.Store(0x20000)
	installPCKPortGuard(localPort)
	return p
}

func (c *pckPacketConn) resolveSrcIP(dst net.IP) net.IP {
	c.srcMu.Lock()
	defer c.srcMu.Unlock()
	if c.cachedSrcIP != nil {
		return c.cachedSrcIP
	}
	if ia, ok := c.PacketConn.LocalAddr().(*net.IPAddr); ok && ia.IP != nil && !ia.IP.IsUnspecified() {
		c.cachedSrcIP = ia.IP.To4()
		if c.cachedSrcIP != nil {
			return c.cachedSrcIP
		}
	}
	c.cachedSrcIP = discoverLocalIPv4For(dst)
	return c.cachedSrcIP
}

func (c *pckPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	host, portStr, err := net.SplitHostPort(addr.String())
	if err != nil {
		host = addr.String()
	}
	dstPort := c.peerPort
	if pNum, pErr := strconv.ParseUint(portStr, 10, 16); pErr == nil && pNum > 0 && pNum <= 65535 {
		dstPort = uint16(pNum)
	}
	ipAddr, err := net.ResolveIPAddr("ip4", host)
	if err != nil {
		return 0, err
	}

	dirByte := byte(0x01)
	if c.isServer {
		dirByte = byte(0x02)
	}
	payloadLen := 5 + len(p)
	seg := make([]byte, 20+payloadLen)
	binary.BigEndian.PutUint16(seg[0:2], c.localPort)
	binary.BigEndian.PutUint16(seg[2:4], dstPort)
	seq := c.seq.Add(uint32(payloadLen))
	binary.BigEndian.PutUint32(seg[4:8], seq)
	binary.BigEndian.PutUint32(seg[8:12], c.ack.Load())
	seg[12] = 5 << 4 // 20-byte TCP header (Data Offset = 5)
	seg[13] = 0x18   // PSH | ACK
	binary.BigEndian.PutUint16(seg[14:16], 65535)
	copy(seg[20:24], c.tag[:])
	seg[24] = dirByte
	copy(seg[25:], p)

	srcIP := c.resolveSrcIP(ipAddr.IP)
	csum := tcpIPv4Checksum(srcIP, ipAddr.IP, seg)
	binary.BigEndian.PutUint16(seg[16:18], csum)

	if _, err := c.PacketConn.WriteTo(seg, ipAddr); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *pckPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	buf := make([]byte, 65535)
	expectedDir := byte(0x02)
	if c.isServer {
		expectedDir = byte(0x01)
	}
	for {
		n, addr, err := c.PacketConn.ReadFrom(buf)
		if err != nil {
			return 0, nil, err
		}
		if n < 25 {
			continue
		}
		// Ignore TCP RST or SYN segments
		if buf[13]&0x06 != 0 {
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
		if dataOffset < 20 || n < dataOffset+5 {
			continue
		}
		if !bytes.Equal(buf[dataOffset:dataOffset+4], c.tag[:]) || buf[dataOffset+4] != expectedDir {
			continue
		}
		peerSeq := binary.BigEndian.Uint32(buf[4:8])
		payloadLen := n - dataOffset
		c.ack.Store(peerSeq + uint32(payloadLen))

		copied := copy(p, buf[dataOffset+5:n])
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
	tag := deriveScopedTag(password, 1, port)
	if os.Geteuid() == 0 && host != "127.0.0.1" {
		if rawConn, rErr := openBestRawConn(1, "ip4:icmp", host, "", 0); rErr == nil {
			ident := uint16(port & 0xFFFF)
			wrapped := &icmpPacketConn{
				PacketConn: rawConn,
				isServer:   true,
				ident:      ident,
				tag:        tag,
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
	tag := deriveScopedTag(password, 1, port)
	if os.Geteuid() == 0 && host != "127.0.0.1" {
		if rawConn, rErr := openBestRawConn(1, "ip4:icmp", "0.0.0.0", "", 0); rErr == nil {
			ident := uint16(port & 0xFFFF)
			wrapped := &icmpPacketConn{
				PacketConn: rawConn,
				isServer:   false,
				ident:      ident,
				tag:        tag,
			}
			targetAddr := &net.UDPAddr{IP: net.ParseIP(host), Port: port}
			return dialPacketCarrier(ctx, wrapped, targetAddr, password, true)
		}
	}
	return DialUDPCarrier(ctx, addr, password, true)
}

// ListenPCKCarrier starts a PCK (Stateless Raw TCP Packet + KCP/FEC) carrier listener.
func ListenPCKCarrier(addr, password string, port int) (*UDPCarrierListener, *net.UDPConn, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil || host == "" {
		host = "0.0.0.0"
	}
	pNum, pErr := strconv.ParseUint(portStr, 10, 16)
	if port <= 0 && pErr == nil {
		port = int(pNum)
	}
	tag := deriveScopedTag(password, 6, port)
	if os.Geteuid() == 0 && port > 0 && port <= 65535 && host != "127.0.0.1" {
		p16 := uint16(port)
		if rawConn, rErr := openBestRawConn(6, "ip4:tcp", host, "", p16); rErr == nil {
			wrapped := newPCKPacketConn(rawConn, true, p16, 0, tag)
			return newPacketCarrierListener(wrapped, nil, password, true), nil, nil
		}
	}
	return ListenUDPCarrier(addr, password, true)
}

// DialPCKCarrier dials a PCK (Stateless Raw TCP Packet + KCP/FEC) carrier session.
func DialPCKCarrier(ctx context.Context, addr, password string, port int) (net.Conn, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	pNum, pErr := strconv.ParseUint(portStr, 10, 16)
	if port <= 0 && pErr == nil {
		port = int(pNum)
	}
	tag := deriveScopedTag(password, 6, port)
	if os.Geteuid() == 0 && port > 0 && port <= 65535 && host != "127.0.0.1" {
		p16 := uint16(port)
		var rnd [2]byte
		_, _ = rand.Read(rnd[:])
		localPort := uint16(20000 + (int(rnd[0])<<8|int(rnd[1]))%25000)
		if rawConn, rErr := openBestRawConn(6, "ip4:tcp", "0.0.0.0", "", localPort); rErr == nil {
			wrapped := newPCKPacketConn(rawConn, false, localPort, p16, tag)
			targetAddr := &net.UDPAddr{IP: net.ParseIP(host), Port: port}
			return dialPacketCarrier(ctx, wrapped, targetAddr, password, true)
		}
	}
	return DialUDPCarrier(ctx, addr, password, true)
}

// newRawProtoPacketConn wraps an IPv4 raw packet connection (for Protocol 58 BIP or Protocol 4 IPIP).
func newRawProtoPacketConn(pc net.PacketConn, proto byte, isServer bool, tag [4]byte) *rawProtoPacketConn {
	return &rawProtoPacketConn{
		PacketConn: pc,
		proto:      proto,
		isServer:   isServer,
		tag:        tag,
	}
}

type rawProtoPacketConn struct {
	net.PacketConn
	proto     byte
	isServer  bool
	tag       [4]byte
	closeOnce sync.Once
}

func (c *rawProtoPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	host := addr.String()
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	ipAddr, err := net.ResolveIPAddr("ip4", host)
	if err != nil {
		return 0, err
	}
	dirByte := byte(0x01)
	if c.isServer {
		dirByte = byte(0x02)
	}
	frame := make([]byte, 5+len(p))
	copy(frame[0:4], c.tag[:])
	frame[4] = dirByte
	copy(frame[5:], p)

	if _, err := c.PacketConn.WriteTo(frame, ipAddr); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *rawProtoPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	buf := make([]byte, 65535)
	expectedDir := byte(0x02)
	if c.isServer {
		expectedDir = byte(0x01)
	}
	for {
		n, addr, err := c.PacketConn.ReadFrom(buf)
		if err != nil {
			return 0, nil, err
		}
		if n < 5 {
			continue
		}
		if !bytes.Equal(buf[0:4], c.tag[:]) || buf[4] != expectedDir {
			continue
		}
		copied := copy(p, buf[5:n])
		return copied, addr, nil
	}
}

// ListenBIPCarrier starts a raw IPv4 Protocol 58 (BIP / IPv6-ICMP on IPv4) carrier listener.
func ListenBIPCarrier(addr, password string, port int) (*UDPCarrierListener, *net.UDPConn, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil || host == "" {
		host = "0.0.0.0"
	}
	tag := deriveScopedTag(password, 58, port)
	if os.Geteuid() == 0 && host != "127.0.0.1" {
		if rawConn, rErr := openBestRawConn(58, "ip4:58", host, "", 0); rErr == nil {
			wrapped := newRawProtoPacketConn(rawConn, 58, true, tag)
			return newPacketCarrierListener(wrapped, nil, password, true), nil, nil
		}
	}
	return ListenUDPCarrier(addr, password, true)
}

// DialBIPCarrier dials a raw IPv4 Protocol 58 (BIP) carrier session.
func DialBIPCarrier(ctx context.Context, addr, password string, port int) (net.Conn, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	if port <= 0 {
		if pNum, pErr := strconv.ParseUint(portStr, 10, 16); pErr == nil {
			port = int(pNum)
		}
	}
	tag := deriveScopedTag(password, 58, port)
	if os.Geteuid() == 0 && host != "127.0.0.1" {
		if rawConn, rErr := openBestRawConn(58, "ip4:58", "0.0.0.0", "", 0); rErr == nil {
			wrapped := newRawProtoPacketConn(rawConn, 58, false, tag)
			targetAddr := &net.UDPAddr{IP: net.ParseIP(host), Port: port}
			return dialPacketCarrier(ctx, wrapped, targetAddr, password, true)
		}
	}
	return DialUDPCarrier(ctx, addr, password, true)
}

// ListenIPIPCarrier starts a raw IPv4 Protocol 4 (IPIP) carrier listener.
func ListenIPIPCarrier(addr, password string, port int) (*UDPCarrierListener, *net.UDPConn, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil || host == "" {
		host = "0.0.0.0"
	}
	tag := deriveScopedTag(password, 4, port)
	if os.Geteuid() == 0 && host != "127.0.0.1" {
		if rawConn, rErr := openBestRawConn(4, "ip4:4", host, "", 0); rErr == nil {
			wrapped := newRawProtoPacketConn(rawConn, 4, true, tag)
			return newPacketCarrierListener(wrapped, nil, password, true), nil, nil
		}
	}
	return ListenUDPCarrier(addr, password, true)
}

// DialIPIPCarrier dials a raw IPv4 Protocol 4 (IPIP) carrier session.
func DialIPIPCarrier(ctx context.Context, addr, password string, port int) (net.Conn, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	if port <= 0 {
		if pNum, pErr := strconv.ParseUint(portStr, 10, 16); pErr == nil {
			port = int(pNum)
		}
	}
	tag := deriveScopedTag(password, 4, port)
	if os.Geteuid() == 0 && host != "127.0.0.1" {
		if rawConn, rErr := openBestRawConn(4, "ip4:4", "0.0.0.0", "", 0); rErr == nil {
			wrapped := newRawProtoPacketConn(rawConn, 4, false, tag)
			targetAddr := &net.UDPAddr{IP: net.ParseIP(host), Port: port}
			return dialPacketCarrier(ctx, wrapped, targetAddr, password, true)
		}
	}
	return DialUDPCarrier(ctx, addr, password, true)
}

// ListenGRECarrier starts a raw IPv4 Protocol 47 (GRE) carrier listener with RFC 2784 4-byte GRE header.
func ListenGRECarrier(addr, password string, port int) (*UDPCarrierListener, *net.UDPConn, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil || host == "" {
		host = "0.0.0.0"
	}
	tag := deriveScopedTag(password, 47, port)
	if os.Geteuid() == 0 && host != "127.0.0.1" {
		if rawConn, rErr := openBestRawConn(47, "ip4:47", host, "", 0); rErr == nil {
			wrapped := newGREProtoPacketConn(rawConn, true, tag)
			return newPacketCarrierListener(wrapped, nil, password, true), nil, nil
		}
	}
	return ListenUDPCarrier(addr, password, true)
}

// DialGRECarrier dials a raw IPv4 Protocol 47 (GRE) carrier session with RFC 2784 4-byte GRE header.
func DialGRECarrier(ctx context.Context, addr, password string, port int) (net.Conn, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	if port <= 0 {
		if pNum, pErr := strconv.ParseUint(portStr, 10, 16); pErr == nil {
			port = int(pNum)
		}
	}
	tag := deriveScopedTag(password, 47, port)
	if os.Geteuid() == 0 && host != "127.0.0.1" {
		if rawConn, rErr := openBestRawConn(47, "ip4:47", "0.0.0.0", "", 0); rErr == nil {
			wrapped := newGREProtoPacketConn(rawConn, false, tag)
			targetAddr := &net.UDPAddr{IP: net.ParseIP(host), Port: port}
			return dialPacketCarrier(ctx, wrapped, targetAddr, password, true)
		}
	}
	return DialUDPCarrier(ctx, addr, password, true)
}

type greProtoPacketConn struct {
	net.PacketConn
	isServer bool
	tag      [4]byte
}

func newGREProtoPacketConn(pc net.PacketConn, isServer bool, tag [4]byte) *greProtoPacketConn {
	return &greProtoPacketConn{
		PacketConn: pc,
		isServer:   isServer,
		tag:        tag,
	}
}

func (c *greProtoPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	host := addr.String()
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	ipAddr, err := net.ResolveIPAddr("ip4", host)
	if err != nil {
		return 0, err
	}
	dirByte := byte(0x01)
	if c.isServer {
		dirByte = byte(0x02)
	}
	// 4B RFC 2784 GRE Header [0x00, 0x00, 0x08, 0x00] + 5B Tag/Dir + Payload
	frame := make([]byte, 4+5+len(p))
	frame[0] = 0x00
	frame[1] = 0x00
	frame[2] = 0x08
	frame[3] = 0x00 // EtherType IPv4
	copy(frame[4:8], c.tag[:])
	frame[8] = dirByte
	copy(frame[9:], p)

	if _, err := c.PacketConn.WriteTo(frame, ipAddr); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *greProtoPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	buf := make([]byte, 65535)
	expectedDir := byte(0x02)
	if c.isServer {
		expectedDir = byte(0x01)
	}
	for {
		n, addr, err := c.PacketConn.ReadFrom(buf)
		if err != nil {
			return 0, nil, err
		}
		if n < 9 {
			continue
		}
		// Check GRE flags (0x0000) and EtherType (0x0800 IPv4)
		if buf[0] != 0 || buf[1] != 0 || buf[2] != 0x08 || buf[3] != 0x00 {
			continue
		}
		if !bytes.Equal(buf[4:8], c.tag[:]) || buf[8] != expectedDir {
			continue
		}
		copied := copy(p, buf[9:n])
		return copied, addr, nil
	}
}

// SpoofOptions contains all tuning parameters for raw IP spoofing and evasion.
type SpoofOptions struct {
	SrcIP       string
	SrcPool     []string
	PeerSrcIP   string
	Profile     string // udp, tcp, icmp
	Uplink      string
	Downlink    string
	FakeTLS     bool
	TTLJitter   bool
	RandomDSCP  bool
	ShufflePort bool
	PortMin     uint16
	PortMax     uint16
	Padding     bool
	PaddingMax  uint8
	Interface   string
}

type spoofPacketConn struct {
	net.PacketConn
	opts       SpoofOptions
	isServer   bool
	srcCursor  atomic.Uint64
	tag        [4]byte
	closeOnce  sync.Once
}

func newSpoofPacketConn(pc net.PacketConn, opts SpoofOptions, isServer bool, tag [4]byte) *spoofPacketConn {
	if opts.PortMin == 0 {
		opts.PortMin = 20000
	}
	if opts.PortMax == 0 || opts.PortMax <= opts.PortMin {
		opts.PortMax = 60000
	}
	if opts.PaddingMax == 0 {
		opts.PaddingMax = 64
	}
	return &spoofPacketConn{
		PacketConn: pc,
		opts:       opts,
		isServer:   isServer,
		tag:        tag,
	}
}

func (c *spoofPacketConn) pickSrcIP() string {
	if len(c.opts.SrcPool) > 0 {
		idx := c.srcCursor.Add(1)
		cleanPool := make([]string, 0, len(c.opts.SrcPool))
		for _, s := range c.opts.SrcPool {
			t := strings.TrimSpace(s)
			if t != "" {
				cleanPool = append(cleanPool, t)
			}
		}
		if len(cleanPool) > 0 {
			return cleanPool[idx%uint64(len(cleanPool))]
		}
	}
	return strings.TrimSpace(c.opts.SrcIP)
}

func (c *spoofPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	host := addr.String()
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	ipAddr, err := net.ResolveIPAddr("ip4", host)
	if err != nil {
		return 0, err
	}

	data := p

	// 1. Self-describing padding
	if c.opts.Padding {
		maxPad := int(c.opts.PaddingMax)
		if maxPad <= 0 || maxPad > 255 {
			maxPad = 64
		}
		var rndByte [1]byte
		_, _ = rand.Read(rndByte[:])
		padLen := (int(rndByte[0]) % maxPad) + 1 // 1..maxPad
		padded := make([]byte, len(data)+padLen)
		copy(padded, data)
		_, _ = rand.Read(padded[len(data) : len(padded)-1])
		padded[len(padded)-1] = byte(padLen)
		data = padded
	}

	// 2. Fake TLS 1.2 ApplicationData record header
	if c.opts.FakeTLS && (c.opts.Profile == "tcp" || c.opts.Uplink == "tcp" || c.opts.Downlink == "tcp") {
		fake := make([]byte, 5+len(data))
		fake[0] = 0x17             // ApplicationData
		fake[1], fake[2] = 0x03, 0x03 // TLS 1.2
		binary.BigEndian.PutUint16(fake[3:5], uint16(len(data)))
		copy(fake[5:], data)
		data = fake
	}

	// 3. Prepend [4B tag][1B dirByte]
	dirByte := byte(0x01)
	if c.isServer {
		dirByte = byte(0x02)
	}
	frame := make([]byte, 5+len(data))
	copy(frame[0:4], c.tag[:])
	frame[4] = dirByte
	copy(frame[5:], data)

	if afConn, ok := c.PacketConn.(*afPacketIPv4Conn); ok {
		var spoofSrc net.IP
		if picked := c.pickSrcIP(); picked != "" {
			spoofSrc = net.ParseIP(picked)
		}
		ttl := byte(64)
		if c.opts.TTLJitter {
			var b [1]byte
			_, _ = rand.Read(b[:])
			ttl = 56 + (b[0] % 16)
		}
		tos := byte(0)
		if c.opts.RandomDSCP {
			var b [1]byte
			_, _ = rand.Read(b[:])
			tos = (b[0] & 0x3F) << 2
		}
		if _, err := afConn.WriteToWithIPOpts(frame, ipAddr, spoofSrc, ttl, tos); err != nil {
			return 0, err
		}
		return len(p), nil
	}

	if _, err := c.PacketConn.WriteTo(frame, ipAddr); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *spoofPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	buf := make([]byte, 65535)
	expectedDir := byte(0x02)
	if c.isServer {
		expectedDir = byte(0x01)
	}
	for {
		n, addr, err := c.PacketConn.ReadFrom(buf)
		if err != nil {
			return 0, nil, err
		}
		if n < 5 {
			continue
		}

		// Verify expected incoming peer source if set
		if c.opts.PeerSrcIP != "" {
			host := addr.String()
			if h, _, sErr := net.SplitHostPort(host); sErr == nil {
				host = h
			}
			if host != c.opts.PeerSrcIP {
				continue // Drop unexpected source
			}
		}

		if !bytes.Equal(buf[0:4], c.tag[:]) || buf[4] != expectedDir {
			continue
		}
		data := buf[5:n]

		// Strip fake TLS header if present
		if c.opts.FakeTLS && len(data) >= 5 && data[0] == 0x17 && data[1] == 0x03 && data[2] == 0x03 {
			data = data[5:]
		}

		// Strip self-describing padding if configured
		if c.opts.Padding && len(data) > 0 {
			padLen := int(data[len(data)-1])
			if padLen > 0 && padLen <= len(data) {
				data = data[:len(data)-padLen]
			}
		}

		copied := copy(p, data)
		return copied, addr, nil
	}
}

// ListenSpoofCarrier starts an advanced raw IP spoofing carrier listener.
func ListenSpoofCarrier(addr, password string, opts SpoofOptions, port int) (*UDPCarrierListener, *net.UDPConn, error) {
	proto := byte(58) // default BIP (Protocol 58)
	prof := strings.ToLower(strings.TrimSpace(opts.Profile))
	if opts.Downlink != "" {
		prof = strings.ToLower(strings.TrimSpace(opts.Downlink))
	}
	switch prof {
	case "ipip":
		proto = 4
	case "gre":
		proto = 47
	}

	host, portStr, err := net.SplitHostPort(addr)
	if err != nil || host == "" {
		host = "0.0.0.0"
	}
	if port <= 0 {
		if pNum, pErr := strconv.ParseUint(portStr, 10, 16); pErr == nil {
			port = int(pNum)
		}
	}
	tag := deriveScopedTag(password, proto, port)
	if os.Geteuid() == 0 && host != "127.0.0.1" {
		protoStr := fmt.Sprintf("ip4:%d", proto)
		if rawConn, rErr := openBestRawConn(proto, protoStr, host, opts.Interface, 0); rErr == nil {
			wrapped := newSpoofPacketConn(rawConn, opts, true, tag)
			return newPacketCarrierListener(wrapped, nil, password, true), nil, nil
		}
	}
	return ListenUDPCarrier(addr, password, true)
}

// DialSpoofCarrier dials an advanced raw IP spoofing carrier session.
func DialSpoofCarrier(ctx context.Context, addr, password string, opts SpoofOptions, port int) (net.Conn, error) {
	proto := byte(58) // default BIP (Protocol 58)
	prof := strings.ToLower(strings.TrimSpace(opts.Profile))
	if opts.Uplink != "" {
		prof = strings.ToLower(strings.TrimSpace(opts.Uplink))
	}
	switch prof {
	case "ipip":
		proto = 4
	case "gre":
		proto = 47
	}

	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	if port <= 0 {
		if pNum, pErr := strconv.ParseUint(portStr, 10, 16); pErr == nil {
			port = int(pNum)
		}
	}
	tag := deriveScopedTag(password, proto, port)
	if os.Geteuid() == 0 && host != "127.0.0.1" {
		protoStr := fmt.Sprintf("ip4:%d", proto)
		if rawConn, rErr := openBestRawConn(proto, protoStr, "0.0.0.0", opts.Interface, 0); rErr == nil {
			wrapped := newSpoofPacketConn(rawConn, opts, false, tag)
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

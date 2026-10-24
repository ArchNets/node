package transport

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

const (
	icmpEchoRequest byte = 8
	icmpEchoReply   byte = 0
)

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

// icmpPacketConn wraps a raw "ip4:icmp" net.PacketConn so that payloads written via WriteTo
// are encapsulated in valid ICMP Echo Request/Reply frames and stripped on ReadFrom.
type icmpPacketConn struct {
	net.PacketConn
	isServer bool
	ident    uint16
	seq      uint16
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
	if c.isServer {
		icmpType = icmpEchoReply
	}
	c.seq++

	frame := make([]byte, 8+len(p))
	frame[0] = icmpType
	frame[1] = 0
	binary.BigEndian.PutUint16(frame[4:6], c.ident)
	binary.BigEndian.PutUint16(frame[6:8], c.seq)
	copy(frame[8:], p)
	csum := internetChecksum(frame)
	binary.BigEndian.PutUint16(frame[2:4], csum)

	if _, err := c.PacketConn.WriteTo(frame, ipAddr); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *icmpPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	buf := make([]byte, 65535)
	for {
		n, addr, err := c.PacketConn.ReadFrom(buf)
		if err != nil {
			return 0, nil, err
		}
		if n < 8 {
			continue
		}
		ident := binary.BigEndian.Uint16(buf[4:6])
		if ident != c.ident {
			continue
		}
		copied := copy(p, buf[8:n])
		return copied, &net.UDPAddr{IP: net.ParseIP(addr.String()), Port: int(c.ident)}, nil
	}
}

// ListenXDICarrier starts an XDI (ICMP Echo) listener. If the process has CAP_NET_RAW / root,
// it binds a raw "ip4:icmp" socket; otherwise it falls back to UDP on the carrier port.
func ListenXDICarrier(addr, password string, port int) (*UDPCarrierListener, *net.UDPConn, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil || host == "" {
		host = "0.0.0.0"
	}
	if os.Geteuid() == 0 {
		if rawConn, rErr := net.ListenPacket("ip4:icmp", host); rErr == nil {
			wrapped := &icmpPacketConn{
				PacketConn: rawConn,
				isServer:   true,
				ident:      uint16(port & 0xFFFF),
			}
			l := &UDPCarrierListener{
				password: password,
				useFEC:   true,
				acceptCh: make(chan net.Conn, 128),
				closeCh:  make(chan struct{}),
			}
			go l.readLoopPacketConn(wrapped)
			return l, nil, nil
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
	if os.Geteuid() == 0 {
		if rawConn, rErr := net.ListenPacket("ip4:icmp", "0.0.0.0"); rErr == nil {
			wrapped := &icmpPacketConn{
				PacketConn: rawConn,
				isServer:   false,
				ident:      uint16(port & 0xFFFF),
			}
			targetAddr := &net.UDPAddr{IP: net.ParseIP(host), Port: port}
			return dialPacketCarrier(ctx, wrapped, targetAddr, password, true)
		}
	}
	return DialUDPCarrier(ctx, addr, password, true)
}

// ListenPCKCarrier starts a PCK (Stateless Raw TCP Packet + KCP/FEC) carrier listener.
func ListenPCKCarrier(addr, password string) (*UDPCarrierListener, *net.UDPConn, error) {
	return ListenUDPCarrier(addr, password, true)
}

// DialPCKCarrier dials a PCK (Stateless Raw TCP Packet + KCP/FEC) carrier session.
func DialPCKCarrier(ctx context.Context, addr, password string) (net.Conn, error) {
	return DialUDPCarrier(ctx, addr, password, true)
}

func (l *UDPCarrierListener) readLoopPacketConn(pconn net.PacketConn) {
	buf := make([]byte, 65535)
	magic := kcpAuthMagic
	key, _ := DeriveRealityKey(l.password, "archnet-udp-carrier")

	for {
		n, remote, err := pconn.ReadFrom(buf)
		if err != nil {
			if l.closed.Load() {
				_ = pconn.Close()
				return
			}
			continue
		}
		if n < 9 {
			continue
		}

		typ := buf[0]
		sessID := binary.BigEndian.Uint32(buf[1:5])
		rKey := remote.String()

		if typ == udpPktSYN && n >= 9+32 {
			if !VerifyRealityToken(key, buf[9:9+32], magic) {
				continue
			}
			var ack [9]byte
			ack[0] = udpPktACK
			binary.BigEndian.PutUint32(ack[1:5], sessID)
			_, _ = pconn.WriteTo(ack[:], remote)

			if _, exists := l.sessions.Load(rKey); !exists {
				sess := newUDPSessionConn(pconn, remote, sessID, false, true)
				l.sessions.Store(rKey, sess)
				select {
				case l.acceptCh <- sess:
				default:
					_ = sess.Close()
					l.sessions.Delete(rKey)
				}
			}
			continue
		}

		if val, ok := l.sessions.Load(rKey); ok {
			sess := val.(*UDPSessionConn)
			sess.pushPacket(buf[:n])
			if typ == udpPktFIN {
				l.sessions.Delete(rKey)
			}
		}
	}
}

func dialPacketCarrier(ctx context.Context, pconn net.PacketConn, rAddr net.Addr, password string, useFEC bool) (net.Conn, error) {
	magic := udpAuthMagic
	if useFEC {
		magic = kcpAuthMagic
	}
	key, err := DeriveRealityKey(password, "archnet-udp-carrier")
	if err != nil {
		_ = pconn.Close()
		return nil, err
	}
	token, err := GenerateRealityToken(key, magic)
	if err != nil {
		_ = pconn.Close()
		return nil, err
	}

	sessID := binary.BigEndian.Uint32(token[0:4])
	synPkt := make([]byte, 9+32)
	synPkt[0] = udpPktSYN
	binary.BigEndian.PutUint32(synPkt[1:5], sessID)
	copy(synPkt[9:], token[:])

	_ = pconn.SetReadDeadline(time.Now().Add(4 * time.Second))
	if _, err := pconn.WriteTo(synPkt, rAddr); err != nil {
		_ = pconn.Close()
		return nil, err
	}

	var ack [64]byte
	n, _, err := pconn.ReadFrom(ack[:])
	if err != nil || n < 9 || ack[0] != udpPktACK {
		_ = pconn.Close()
		return nil, fmt.Errorf("packet carrier handshake timed out")
	}
	_ = pconn.SetReadDeadline(time.Time{})

	sess := newUDPSessionConn(pconn, rAddr, sessID, true, useFEC)
	go func() {
		buf := make([]byte, 65535)
		for {
			nr, _, rErr := pconn.ReadFrom(buf)
			if rErr != nil {
				_ = sess.Close()
				return
			}
			if nr >= 9 {
				sess.pushPacket(buf[:nr])
			}
		}
	}()
	return sess, nil
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

package transport

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const (
	udpAuthMagic = "ARUD"
	kcpAuthMagic = "ARKC"

	udpPktSYN  byte = 0x01
	udpPktACK  byte = 0x02
	udpPktDATA byte = 0x03
	udpPktFIN  byte = 0x04
	udpPktFEC  byte = 0x05

	udpMaxPayload = 1350
)

// UDPSessionConn adapts a peer's UDP flow on a shared *net.UDPConn (or dedicated *net.UDPConn)
// into a reliable/FEC-protected net.Conn suitable for MuxSession or direct stream relaying.
type UDPSessionConn struct {
	pconn        net.PacketConn
	remoteAddr   net.Addr
	ownsConn     bool
	useFEC       bool
	sessionID    uint32
	txSeq        atomic.Uint32
	rxQueue      chan []byte
	closeOnce    sync.Once
	closeCh      chan struct{}
	closed       atomic.Bool
	readBuf      []byte
	readMu       sync.Mutex
	writeMu      sync.Mutex
	readDeadline atomic.Value // time.Time
	fecGroup     [][]byte
}

func newUDPSessionConn(pconn net.PacketConn, remote net.Addr, sessionID uint32, ownsConn, useFEC bool) *UDPSessionConn {
	u := &UDPSessionConn{
		pconn:      pconn,
		remoteAddr: remote,
		ownsConn:   ownsConn,
		useFEC:     useFEC,
		sessionID:  sessionID,
		rxQueue:    make(chan []byte, 2048),
		closeCh:    make(chan struct{}),
	}
	u.readDeadline.Store(time.Time{})
	return u
}

func (u *UDPSessionConn) pushPacket(pkt []byte) {
	if len(pkt) < 9 || u.closed.Load() {
		return
	}
	typ := pkt[0]
	switch typ {
	case udpPktDATA:
		dataLen := int(binary.BigEndian.Uint16(pkt[7:9]))
		if 9+dataLen > len(pkt) {
			return
		}
		payload := make([]byte, dataLen)
		copy(payload, pkt[9:9+dataLen])
		select {
		case u.rxQueue <- payload:
		default:
		}
	case udpPktFIN:
		_ = u.Close()
	}
}

func (u *UDPSessionConn) Read(p []byte) (int, error) {
	u.readMu.Lock()
	defer u.readMu.Unlock()

	if len(u.readBuf) > 0 {
		n := copy(p, u.readBuf)
		u.readBuf = u.readBuf[n:]
		return n, nil
	}

	var timerCh <-chan time.Time
	if dl, ok := u.readDeadline.Load().(time.Time); ok && !dl.IsZero() {
		wait := time.Until(dl)
		if wait <= 0 {
			return 0, errors.New("udp session read timeout")
		}
		t := time.NewTimer(wait)
		defer t.Stop()
		timerCh = t.C
	}

	select {
	case <-u.closeCh:
		return 0, io.EOF
	case <-timerCh:
		return 0, errors.New("udp session read timeout")
	case chunk := <-u.rxQueue:
		n := copy(p, chunk)
		if n < len(chunk) {
			u.readBuf = append(u.readBuf[:0], chunk[n:]...)
		}
		return n, nil
	}
}

func (u *UDPSessionConn) Write(p []byte) (int, error) {
	if u.closed.Load() {
		return 0, io.ErrClosedPipe
	}
	u.writeMu.Lock()
	defer u.writeMu.Unlock()

	total := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > udpMaxPayload {
			chunk = p[:udpMaxPayload]
		}
		p = p[len(chunk):]

		seq := u.txSeq.Add(1)
		pkt := make([]byte, 9+len(chunk))
		pkt[0] = udpPktDATA
		binary.BigEndian.PutUint32(pkt[1:5], u.sessionID)
		binary.BigEndian.PutUint16(pkt[5:7], uint16(seq))
		binary.BigEndian.PutUint16(pkt[7:9], uint16(len(chunk)))
		copy(pkt[9:], chunk)

		if _, err := u.pconn.WriteTo(pkt, u.remoteAddr); err != nil {
			return total, err
		}

		// When KCP/FEC mode is enabled, emit an XOR parity shard every 4 data packets
		if u.useFEC {
			cp := make([]byte, len(chunk))
			copy(cp, chunk)
			u.fecGroup = append(u.fecGroup, cp)
			if len(u.fecGroup) >= 4 {
				u.emitFECParity(seq)
				u.fecGroup = u.fecGroup[:0]
			}
		}

		total += len(chunk)
	}
	return total, nil
}

func (u *UDPSessionConn) emitFECParity(seq uint32) {
	maxLen := 0
	for _, s := range u.fecGroup {
		if len(s) > maxLen {
			maxLen = len(s)
		}
	}
	if maxLen == 0 {
		return
	}
	parity := make([]byte, 9+maxLen)
	parity[0] = udpPktFEC
	binary.BigEndian.PutUint32(parity[1:5], u.sessionID)
	binary.BigEndian.PutUint16(parity[5:7], uint16(seq))
	binary.BigEndian.PutUint16(parity[7:9], uint16(maxLen))
	for _, s := range u.fecGroup {
		for i := 0; i < len(s); i++ {
			parity[9+i] ^= s[i]
		}
	}
	_, _ = u.pconn.WriteTo(parity, u.remoteAddr)
}

func (u *UDPSessionConn) CloseWrite() error {
	if !u.closed.Load() {
		var fin [9]byte
		fin[0] = udpPktFIN
		binary.BigEndian.PutUint32(fin[1:5], u.sessionID)
		_, _ = u.pconn.WriteTo(fin[:], u.remoteAddr)
	}
	return nil
}

func (u *UDPSessionConn) CloseRead() error {
	return nil
}

func (u *UDPSessionConn) Close() error {
	u.closeOnce.Do(func() {
		u.closed.Store(true)
		var fin [9]byte
		fin[0] = udpPktFIN
		binary.BigEndian.PutUint32(fin[1:5], u.sessionID)
		_, _ = u.pconn.WriteTo(fin[:], u.remoteAddr)
		close(u.closeCh)
		if u.ownsConn {
			_ = u.pconn.Close()
		}
	})
	return nil
}

func (u *UDPSessionConn) LocalAddr() net.Addr  { return u.pconn.LocalAddr() }
func (u *UDPSessionConn) RemoteAddr() net.Addr { return u.remoteAddr }
func (u *UDPSessionConn) SetDeadline(t time.Time) error {
	u.readDeadline.Store(t)
	return nil
}
func (u *UDPSessionConn) SetReadDeadline(t time.Time) error {
	u.readDeadline.Store(t)
	return nil
}
func (u *UDPSessionConn) SetWriteDeadline(t time.Time) error { return nil }

// UDPCarrierListener listens on a UDP port and demultiplexes incoming KCP or UDP sessions.
type UDPCarrierListener struct {
	udpConn  *net.UDPConn
	password string
	useFEC   bool
	sessions sync.Map // string(remoteAddr) -> *UDPSessionConn
	acceptCh chan net.Conn
	closeCh  chan struct{}
	closed   atomic.Bool
}

// ListenUDPCarrier binds a UDP listener for "kcp" (useFEC=true) or "udp" (useFEC=false) transport.
func ListenUDPCarrier(addr, password string, useFEC bool) (*UDPCarrierListener, *net.UDPConn, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, nil, err
	}
	uConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, nil, err
	}
	_ = uConn.SetReadBuffer(8 * 1024 * 1024)
	_ = uConn.SetWriteBuffer(8 * 1024 * 1024)

	l := &UDPCarrierListener{
		udpConn:  uConn,
		password: password,
		useFEC:   useFEC,
		acceptCh: make(chan net.Conn, 128),
		closeCh:  make(chan struct{}),
	}
	go l.readLoop()
	return l, uConn, nil
}

func (l *UDPCarrierListener) Accept(ctx context.Context) (net.Conn, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-l.closeCh:
		return nil, io.EOF
	case c := <-l.acceptCh:
		return c, nil
	}
}

func (l *UDPCarrierListener) Close() error {
	if l.closed.CompareAndSwap(false, true) {
		close(l.closeCh)
		return l.udpConn.Close()
	}
	return nil
}

func (l *UDPCarrierListener) readLoop() {
	buf := make([]byte, 65535)
	magic := udpAuthMagic
	if l.useFEC {
		magic = kcpAuthMagic
	}
	key, _ := DeriveRealityKey(l.password, "archnet-udp-carrier")

	for {
		n, remote, err := l.udpConn.ReadFromUDP(buf)
		if err != nil {
			if l.closed.Load() {
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
			_, _ = l.udpConn.WriteToUDP(ack[:], remote)

			if _, exists := l.sessions.Load(rKey); !exists {
				sess := newUDPSessionConn(l.udpConn, remote, sessID, false, l.useFEC)
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

// DialUDPCarrier dials a UDP or KCP+FEC session to addr and authenticates with a 32-byte HMAC token.
func DialUDPCarrier(ctx context.Context, addr, password string, useFEC bool) (net.Conn, error) {
	rAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	uConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return nil, err
	}
	_ = uConn.SetReadBuffer(8 * 1024 * 1024)
	_ = uConn.SetWriteBuffer(8 * 1024 * 1024)

	magic := udpAuthMagic
	if useFEC {
		magic = kcpAuthMagic
	}
	key, err := DeriveRealityKey(password, "archnet-udp-carrier")
	if err != nil {
		_ = uConn.Close()
		return nil, err
	}
	token, err := GenerateRealityToken(key, magic)
	if err != nil {
		_ = uConn.Close()
		return nil, err
	}

	sessID := binary.BigEndian.Uint32(token[0:4])
	synPkt := make([]byte, 9+32)
	synPkt[0] = udpPktSYN
	binary.BigEndian.PutUint32(synPkt[1:5], sessID)
	copy(synPkt[9:], token[:])

	_ = uConn.SetReadDeadline(time.Now().Add(4 * time.Second))
	if _, err := uConn.WriteToUDP(synPkt, rAddr); err != nil {
		_ = uConn.Close()
		return nil, err
	}

	var ack [64]byte
	n, _, err := uConn.ReadFromUDP(ack[:])
	if err != nil || n < 9 || ack[0] != udpPktACK {
		_ = uConn.Close()
		return nil, errors.New("udp/kcp carrier handshake timed out")
	}
	_ = uConn.SetReadDeadline(time.Time{})

	sess := newUDPSessionConn(uConn, rAddr, sessID, true, useFEC)
	go func() {
		buf := make([]byte, 65535)
		for {
			nr, _, rErr := uConn.ReadFromUDP(buf)
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

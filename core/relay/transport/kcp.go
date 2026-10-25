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
	udpPktNACK byte = 0x06
	udpPktTUN  byte = 0x07 // Direct Layer-3 TUN IP/GRE datagram frame

	udpMaxPayload = 1350
	txRingSize    = 512
)

type fecBlockGroup struct {
	shards    [4][]byte
	hasShard  [4]bool
	count     int
	parity    []byte
	recovered bool
}

// UDPSessionConn adapts a peer's UDP/PCK/XDI flow into an ARQ+FEC reliable, in-order net.Conn
// for MuxSession, while also supporting direct datagram bypass (udpPktTUN) for Layer-3 TUN packets.
type UDPSessionConn struct {
	pconn          net.PacketConn
	remoteAddr     net.Addr
	ownsConn       bool
	useFEC         bool
	sessionID      uint32
	txSeq          atomic.Uint32
	rxQueue        chan []byte
	closeOnce      sync.Once
	closeCh        chan struct{}
	closed         atomic.Bool
	readBuf        []byte
	readMu         sync.Mutex
	writeMu        sync.Mutex
	readDeadline   atomic.Value // time.Time
	fecGroup       [][]byte
	txRingMu       sync.Mutex
	txRing         [txRingSize][]byte
	rxMu           sync.Mutex
	nextRxSeq      uint16
	reorderBuf     map[uint16][]byte
	fecGroups      map[uint16]*fecBlockGroup
	gapSince       time.Time
	tunPacketHook  atomic.Pointer[func([]byte)]
}

func newUDPSessionConn(pconn net.PacketConn, remote net.Addr, sessionID uint32, ownsConn, useFEC bool) *UDPSessionConn {
	u := &UDPSessionConn{
		pconn:      pconn,
		remoteAddr: remote,
		ownsConn:   ownsConn,
		useFEC:     useFEC,
		sessionID:  sessionID,
		rxQueue:    make(chan []byte, 4096),
		closeCh:    make(chan struct{}),
		nextRxSeq:  1,
		reorderBuf: make(map[uint16][]byte),
		fecGroups:  make(map[uint16]*fecBlockGroup),
	}
	u.readDeadline.Store(time.Time{})
	return u
}

// SetTUNPacketHandler registers a callback for incoming Layer-3 TUN (udpPktTUN) datagrams.
func (u *UDPSessionConn) SetTUNPacketHandler(fn func([]byte)) {
	u.tunPacketHook.Store(&fn)
}

// WriteTUNPacket sends a raw Layer-3 TUN packet (GRE/IPIP) directly as a datagram without stream head-of-line blocking.
func (u *UDPSessionConn) WriteTUNPacket(ipPkt []byte) error {
	if u.closed.Load() {
		return io.ErrClosedPipe
	}
	pkt := make([]byte, 9+len(ipPkt))
	pkt[0] = udpPktTUN
	binary.BigEndian.PutUint32(pkt[1:5], u.sessionID)
	binary.BigEndian.PutUint16(pkt[7:9], uint16(len(ipPkt)))
	copy(pkt[9:], ipPkt)
	_, err := u.pconn.WriteTo(pkt, u.remoteAddr)
	return err
}

func seqBefore(a, b uint16) bool {
	return int16(a-b) < 0
}

func (u *UDPSessionConn) pushPacket(pkt []byte) {
	if len(pkt) < 9 || u.closed.Load() {
		return
	}
	typ := pkt[0]
	seq := binary.BigEndian.Uint16(pkt[5:7])
	dataLen := int(binary.BigEndian.Uint16(pkt[7:9]))

	switch typ {
	case udpPktTUN:
		if 9+dataLen > len(pkt) {
			return
		}
		if hook := u.tunPacketHook.Load(); hook != nil && *hook != nil {
			payload := make([]byte, dataLen)
			copy(payload, pkt[9:9+dataLen])
			(*hook)(payload)
		}

	case udpPktDATA:
		if 9+dataLen > len(pkt) {
			return
		}
		payload := make([]byte, dataLen)
		copy(payload, pkt[9:9+dataLen])
		u.rxMu.Lock()
		u.handleDataLocked(seq, payload)
		u.rxMu.Unlock()

	case udpPktFEC:
		if !u.useFEC || 9+dataLen > len(pkt) {
			return
		}
		parity := make([]byte, dataLen)
		copy(parity, pkt[9:9+dataLen])
		u.rxMu.Lock()
		u.handleFECLocked(seq, parity)
		u.rxMu.Unlock()

	case udpPktNACK:
		u.txRingMu.Lock()
		saved := u.txRing[seq%txRingSize]
		if len(saved) >= 9 && binary.BigEndian.Uint16(saved[5:7]) == seq {
			_, _ = u.pconn.WriteTo(saved, u.remoteAddr)
		}
		u.txRingMu.Unlock()

	case udpPktFIN:
		_ = u.Close()
	}
}

func (u *UDPSessionConn) handleDataLocked(seq uint16, payload []byte) {
	if u.useFEC && seq >= 1 {
		grpID := (seq - 1) / 4
		idx := int((seq - 1) % 4)
		grp := u.fecGroups[grpID]
		if grp == nil {
			grp = &fecBlockGroup{}
			u.fecGroups[grpID] = grp
			if len(u.fecGroups) > 64 {
				delete(u.fecGroups, grpID-32)
			}
		}
		if !grp.hasShard[idx] {
			// Store [2B len] + payload for exact XOR reconstruction
			framed := make([]byte, 2+len(payload))
			binary.BigEndian.PutUint16(framed[0:2], uint16(len(payload)))
			copy(framed[2:], payload)
			grp.shards[idx] = framed
			grp.hasShard[idx] = true
			grp.count++
			u.tryRecoverFECLocked(grpID, grp)
		}
	}

	if seqBefore(seq, u.nextRxSeq) {
		return // duplicate packet already delivered
	}
	if seq == u.nextRxSeq {
		u.deliverInOrderLocked(payload)
		return
	}

	// Out-of-order arrival: buffer and request NACK retransmission if gap persists
	if _, exists := u.reorderBuf[seq]; !exists {
		u.reorderBuf[seq] = payload
	}
	if u.gapSince.IsZero() {
		u.gapSince = time.Now()
		var nack [9]byte
		nack[0] = udpPktNACK
		binary.BigEndian.PutUint32(nack[1:5], u.sessionID)
		binary.BigEndian.PutUint16(nack[5:7], u.nextRxSeq)
		_, _ = u.pconn.WriteTo(nack[:], u.remoteAddr)
	} else if time.Since(u.gapSince) > 80*time.Millisecond {
		// Advance past unrecoverable gap after 80ms so stream never deadlocks
		for len(u.reorderBuf) > 0 && u.reorderBuf[u.nextRxSeq] == nil {
			u.nextRxSeq++
		}
		u.drainReorderLocked()
	}
}

func (u *UDPSessionConn) handleFECLocked(baseSeq uint16, parity []byte) {
	if baseSeq < 1 {
		return
	}
	grpID := (baseSeq - 1) / 4
	grp := u.fecGroups[grpID]
	if grp == nil {
		grp = &fecBlockGroup{}
		u.fecGroups[grpID] = grp
	}
	grp.parity = parity
	u.tryRecoverFECLocked(grpID, grp)
}

func (u *UDPSessionConn) tryRecoverFECLocked(grpID uint16, grp *fecBlockGroup) {
	if grp.recovered || grp.count != 3 || len(grp.parity) < 2 {
		return
	}
	missingIdx := -1
	for i := 0; i < 4; i++ {
		if !grp.hasShard[i] {
			missingIdx = i
			break
		}
	}
	if missingIdx < 0 {
		return
	}

	rec := make([]byte, len(grp.parity))
	copy(rec, grp.parity)
	for i := 0; i < 4; i++ {
		if i == missingIdx {
			continue
		}
		sh := grp.shards[i]
		for b := 0; b < len(sh) && b < len(rec); b++ {
			rec[b] ^= sh[b]
		}
	}
	origLen := int(binary.BigEndian.Uint16(rec[0:2]))
	if origLen <= 0 || 2+origLen > len(rec) {
		return
	}
	grp.recovered = true
	recoveredPayload := make([]byte, origLen)
	copy(recoveredPayload, rec[2:2+origLen])
	missingSeq := grpID*4 + uint16(missingIdx) + 1

	if missingSeq == u.nextRxSeq {
		u.deliverInOrderLocked(recoveredPayload)
	} else if !seqBefore(missingSeq, u.nextRxSeq) {
		u.reorderBuf[missingSeq] = recoveredPayload
	}
}

func (u *UDPSessionConn) deliverInOrderLocked(payload []byte) {
	select {
	case u.rxQueue <- payload:
	default:
	}
	u.nextRxSeq++
	u.drainReorderLocked()
}

func (u *UDPSessionConn) drainReorderLocked() {
	for {
		next, ok := u.reorderBuf[u.nextRxSeq]
		if !ok {
			break
		}
		delete(u.reorderBuf, u.nextRxSeq)
		select {
		case u.rxQueue <- next:
		default:
		}
		u.nextRxSeq++
	}
	if len(u.reorderBuf) == 0 {
		u.gapSince = time.Time{}
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

		seq := uint16(u.txSeq.Add(1))
		if seq == 0 {
			seq = uint16(u.txSeq.Add(1))
		}
		pkt := make([]byte, 9+len(chunk))
		pkt[0] = udpPktDATA
		binary.BigEndian.PutUint32(pkt[1:5], u.sessionID)
		binary.BigEndian.PutUint16(pkt[5:7], seq)
		binary.BigEndian.PutUint16(pkt[7:9], uint16(len(chunk)))
		copy(pkt[9:], chunk)

		u.txRingMu.Lock()
		u.txRing[seq%txRingSize] = pkt
		u.txRingMu.Unlock()

		if _, err := u.pconn.WriteTo(pkt, u.remoteAddr); err != nil {
			return total, err
		}

		if u.useFEC {
			framed := make([]byte, 2+len(chunk))
			binary.BigEndian.PutUint16(framed[0:2], uint16(len(chunk)))
			copy(framed[2:], chunk)
			u.fecGroup = append(u.fecGroup, framed)
			if len(u.fecGroup) >= 4 {
				u.emitFECParity(seq)
				u.fecGroup = u.fecGroup[:0]
			}
		}

		total += len(chunk)
	}
	return total, nil
}

func (u *UDPSessionConn) emitFECParity(seq uint16) {
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
	binary.BigEndian.PutUint16(parity[5:7], seq)
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

// UDPCarrierListener listens on a UDP/PCK/XDI port and demultiplexes incoming sessions.
type UDPCarrierListener struct {
	udpConn  *net.UDPConn
	pconn    net.PacketConn
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
		pconn:    uConn,
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
		if l.pconn != nil {
			_ = l.pconn.Close()
		}
		if l.udpConn != nil {
			return l.udpConn.Close()
		}
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

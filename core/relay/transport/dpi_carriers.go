package transport

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"sync/atomic"
)

// DTLS 1.3 Application Data header (RFC 9147 / RFC 6347 wire lookalike)
// [1B type=0x17][2B version=0xfefd][2B epoch=0x0001][6B seq][2B length] = 13 bytes
const dtls13HeaderLen = 13

type dtls13PacketConn struct {
	net.PacketConn
	isServer bool
	seq      atomic.Uint32
}

// NewDTLS13PacketConn wraps a net.PacketConn in RFC 9147 DTLS 1.3 ApplicationData record framing.
func NewDTLS13PacketConn(pc net.PacketConn, isServer bool) net.PacketConn {
	return &dtls13PacketConn{
		PacketConn: pc,
		isServer:   isServer,
	}
}

func (c *dtls13PacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	s := c.seq.Add(1)
	frame := make([]byte, dtls13HeaderLen+len(p))
	// ContentType = ApplicationData (0x17), ProtocolVersion = DTLS 1.2/1.3 wire (0xfefd)
	frame[0] = 0x17
	frame[1] = 0xfe
	frame[2] = 0xfd
	// Epoch = 1
	binary.BigEndian.PutUint16(frame[3:5], 1)
	// 48-bit sequence number
	frame[5] = 0
	frame[6] = 0
	binary.BigEndian.PutUint32(frame[7:11], s)
	// Length
	binary.BigEndian.PutUint16(frame[11:13], uint16(len(p)))
	copy(frame[dtls13HeaderLen:], p)

	if _, err := c.PacketConn.WriteTo(frame, addr); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *dtls13PacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	bufPtr := rawPacketBufPool.Get().(*[]byte)
	defer rawPacketBufPool.Put(bufPtr)
	buf := *bufPtr

	for {
		n, addr, err := c.PacketConn.ReadFrom(buf)
		if err != nil {
			return 0, nil, err
		}
		if n < dtls13HeaderLen {
			continue
		}
		// Verify DTLS record header: type 0x17 (ApplicationData) and version 0xfefd
		if buf[0] != 0x17 || buf[1] != 0xfe || buf[2] != 0xfd {
			continue
		}
		recLen := int(binary.BigEndian.Uint16(buf[11:13]))
		if recLen <= 0 || dtls13HeaderLen+recLen > n {
			recLen = n - dtls13HeaderLen
		}
		copied := copy(p, buf[dtls13HeaderLen:dtls13HeaderLen+recLen])
		return copied, addr, nil
	}
}

// QUIC v1 1-RTT Short Header (RFC 9000 lookalike)
// [1B 0x40 | key_phase][8B DCID][2B PacketNumber] = 11 bytes
const quicV1HeaderLen = 11

type quicV1PacketConn struct {
	net.PacketConn
	dcid     [8]byte
	isServer bool
	seq      atomic.Uint32
}

// NewQUICv1PacketConn wraps a net.PacketConn in RFC 9000 QUIC v1 1-RTT short-header framing.
func NewQUICv1PacketConn(pc net.PacketConn, password string, isServer bool) net.PacketConn {
	mac := hmac.New(sha256.New, []byte(password))
	mac.Write([]byte("archnet-quic-v1-dcid"))
	sum := mac.Sum(nil)
	var dcid [8]byte
	copy(dcid[:], sum[:8])

	return &quicV1PacketConn{
		PacketConn: pc,
		dcid:       dcid,
		isServer:   isServer,
	}
}

func (c *quicV1PacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	s := c.seq.Add(1)
	frame := make([]byte, quicV1HeaderLen+len(p))
	// Fixed bit 0x40 + Spin bit / Key phase toggle
	frame[0] = 0x41 | byte((s&1)<<5)
	copy(frame[1:9], c.dcid[:])
	binary.BigEndian.PutUint16(frame[9:11], uint16(s))
	copy(frame[quicV1HeaderLen:], p)

	if _, err := c.PacketConn.WriteTo(frame, addr); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *quicV1PacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	bufPtr := rawPacketBufPool.Get().(*[]byte)
	defer rawPacketBufPool.Put(bufPtr)
	buf := *bufPtr

	for {
		n, addr, err := c.PacketConn.ReadFrom(buf)
		if err != nil {
			return 0, nil, err
		}
		if n < quicV1HeaderLen {
			continue
		}
		// Check QUIC v1 short header fixed bit (0x40) and connection ID
		if (buf[0]&0x40) == 0 || !hmac.Equal(buf[1:9], c.dcid[:]) {
			continue
		}
		copied := copy(p, buf[quicV1HeaderLen:n])
		return copied, addr, nil
	}
}

// RUDP 2+1 XOR Forward Error Correction Header
// [1B 0x00][2B seq][4B group][1B shard (0=data0, 1=data1, 2=parity)] = 8 bytes
const rudpHeaderLen = 8
const rudpMaxPacket = 9000

type rudpXORPacketConn struct {
	net.PacketConn
	isServer   bool
	seq        atomic.Uint32
	group      atomic.Uint32
	shardState atomic.Uint32 // 0 or 1
	txMu       sync.Mutex
	prevData   [rudpMaxPacket]byte
	prevLen    int

	rxMu      sync.Mutex
	rxGroups  map[uint32]*rudpGroupSlot
	recovered [][]byte
}

type rudpGroupSlot struct {
	have      [2]bool
	data      [2][]byte
	hasParity bool
	parity    []byte
}

// NewRUDPXORPacketConn wraps a net.PacketConn in 2+1 XOR forward error correction framing (from C-Tunnel).
// For every two data packets transmitted, a 3rd XOR parity packet is generated.
// If any single packet in the 2-packet group is dropped by network jitter, it is reconstructed in 0 microseconds!
func NewRUDPXORPacketConn(pc net.PacketConn, isServer bool) net.PacketConn {
	return &rudpXORPacketConn{
		PacketConn: pc,
		isServer:   isServer,
		rxGroups:   make(map[uint32]*rudpGroupSlot),
	}
}

func (c *rudpXORPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if len(p) > rudpMaxPacket {
		return c.PacketConn.WriteTo(p, addr)
	}

	c.txMu.Lock()
	defer c.txMu.Unlock()

	curGroup := c.group.Load()
	if curGroup == 0 {
		curGroup = 1
		c.group.Store(1)
	}
	curShard := byte(c.shardState.Load())
	s := c.seq.Add(1)

	// Send current data packet: [8B RUDP Header] + Payload
	hdr := make([]byte, rudpHeaderLen+len(p))
	hdr[0] = 0x00
	binary.BigEndian.PutUint16(hdr[1:3], uint16(s))
	binary.BigEndian.PutUint32(hdr[3:7], curGroup)
	hdr[7] = curShard
	copy(hdr[rudpHeaderLen:], p)

	if _, err := c.PacketConn.WriteTo(hdr, addr); err != nil {
		return 0, err
	}

	if curShard == 0 {
		c.prevLen = copy(c.prevData[:], p)
		c.shardState.Store(1)
		return len(p), nil
	}

	// Shard 1 completes the group: generate and send Shard 2 (Parity)
	c.shardState.Store(0)
	c.group.Add(1)

	maxLen := c.prevLen
	if len(p) > maxLen {
		maxLen = len(p)
	}
	parityPayload := make([]byte, 4+maxLen)
	binary.BigEndian.PutUint16(parityPayload[0:2], uint16(c.prevLen))
	binary.BigEndian.PutUint16(parityPayload[2:4], uint16(len(p)))
	for i := 0; i < maxLen; i++ {
		var b0, b1 byte
		if i < c.prevLen {
			b0 = c.prevData[i]
		}
		if i < len(p) {
			b1 = p[i]
		}
		parityPayload[4+i] = b0 ^ b1
	}

	pSeq := c.seq.Add(1)
	pHdr := make([]byte, rudpHeaderLen+len(parityPayload))
	pHdr[0] = 0x00
	binary.BigEndian.PutUint16(pHdr[1:3], uint16(pSeq))
	binary.BigEndian.PutUint32(pHdr[3:7], curGroup)
	pHdr[7] = 2 // ShardParity
	copy(pHdr[rudpHeaderLen:], parityPayload)

	// Best-effort send of parity packet
	_, _ = c.PacketConn.WriteTo(pHdr, addr)

	return len(p), nil
}

func (c *rudpXORPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	c.rxMu.Lock()
	if len(c.recovered) > 0 {
		rec := c.recovered[0]
		c.recovered = c.recovered[1:]
		c.rxMu.Unlock()
		copied := copy(p, rec)
		return copied, c.LocalAddr(), nil
	}
	c.rxMu.Unlock()

	bufPtr := rawPacketBufPool.Get().(*[]byte)
	defer rawPacketBufPool.Put(bufPtr)
	buf := *bufPtr

	for {
		n, addr, err := c.PacketConn.ReadFrom(buf)
		if err != nil {
			return 0, nil, err
		}
		if n < rudpHeaderLen {
			continue
		}
		if buf[0] != 0x00 {
			continue
		}
		group := binary.BigEndian.Uint32(buf[3:7])
		shard := buf[7]
		payload := buf[rudpHeaderLen:n]

		c.rxMu.Lock()
		slot := c.rxGroups[group]
		if slot == nil {
			slot = &rudpGroupSlot{}
			if len(c.rxGroups) > 128 {
				c.rxGroups = make(map[uint32]*rudpGroupSlot)
			}
			c.rxGroups[group] = slot
		}

		if shard == 0 || shard == 1 {
			slot.have[shard] = true
			slot.data[shard] = append([]byte(nil), payload...)

			// If other shard was missing and parity already arrived, reconstruct it!
			if slot.hasParity {
				missingShard := byte(1 - shard)
				if !slot.have[missingShard] {
					if rec, recErr := recoverXOR(payload, shard == 0, slot.parity); recErr == nil && rec != nil {
						slot.have[missingShard] = true
						c.recovered = append(c.recovered, rec)
					}
				}
			}
			c.rxMu.Unlock()
			copied := copy(p, payload)
			return copied, addr, nil
		}

		if shard == 2 {
			slot.hasParity = true
			slot.parity = append([]byte(nil), payload...)

			// If exactly one data shard arrived, reconstruct the missing one!
			if slot.have[0] && !slot.have[1] {
				if rec, recErr := recoverXOR(slot.data[0], true, slot.parity); recErr == nil && rec != nil {
					slot.have[1] = true
					c.rxMu.Unlock()
					copied := copy(p, rec)
					return copied, addr, nil
				}
			} else if slot.have[1] && !slot.have[0] {
				if rec, recErr := recoverXOR(slot.data[1], false, slot.parity); recErr == nil && rec != nil {
					slot.have[0] = true
					c.rxMu.Unlock()
					copied := copy(p, rec)
					return copied, addr, nil
				}
			}
			c.rxMu.Unlock()
			continue
		}
		c.rxMu.Unlock()
	}
}

func recoverXOR(availableData []byte, isData0 bool, parity []byte) ([]byte, error) {
	if len(parity) < 4 {
		return nil, errors.New("rudp: parity too short")
	}
	len0 := int(binary.BigEndian.Uint16(parity[0:2]))
	len1 := int(binary.BigEndian.Uint16(parity[2:4]))
	targetLen := len1
	if !isData0 {
		targetLen = len0
	}
	if targetLen <= 0 || targetLen > rudpMaxPacket {
		return nil, errors.New("rudp: invalid target length")
	}
	xorBytes := parity[4:]
	recovered := make([]byte, targetLen)
	for i := 0; i < targetLen; i++ {
		var a byte
		if i < len(availableData) {
			a = availableData[i]
		}
		var p byte
		if i < len(xorBytes) {
			p = xorBytes[i]
		}
		recovered[i] = a ^ p
	}
	return recovered, nil
}

// SRTP Direct (RFC 3550 / 3711 Video Media Stream Lookalike)
// [1B V=2,PT=96][1B 0x60][2B seq][4B timestamp][4B SSRC] = 12 bytes
const srtpHeaderLen = 12

type srtpPacketConn struct {
	net.PacketConn
	ssrc     uint32
	isServer bool
	seq      atomic.Uint32
	ts       atomic.Uint32
}

func NewSRTPPacketConn(pc net.PacketConn, password string, isServer bool) net.PacketConn {
	mac := hmac.New(sha256.New, []byte(password))
	mac.Write([]byte("archnet-srtp-ssrc"))
	sum := mac.Sum(nil)
	ssrc := binary.BigEndian.Uint32(sum[:4])

	c := &srtpPacketConn{
		PacketConn: pc,
		ssrc:       ssrc,
		isServer:   isServer,
	}
	c.ts.Store(binary.BigEndian.Uint32(sum[4:8]))
	return c
}

func (c *srtpPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	s := c.seq.Add(1)
	frame := make([]byte, srtpHeaderLen+len(p))
	frame[0], frame[1] = 0x80, 0x60 // V=2, PayloadType=96 (dynamic video)
	binary.BigEndian.PutUint16(frame[2:4], uint16(s))
	binary.BigEndian.PutUint32(frame[4:8], c.ts.Add(3000))
	binary.BigEndian.PutUint32(frame[8:12], c.ssrc)
	copy(frame[srtpHeaderLen:], p)

	if _, err := c.PacketConn.WriteTo(frame, addr); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *srtpPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	bufPtr := rawPacketBufPool.Get().(*[]byte)
	defer rawPacketBufPool.Put(bufPtr)
	buf := *bufPtr

	for {
		n, addr, err := c.PacketConn.ReadFrom(buf)
		if err != nil {
			return 0, nil, err
		}
		if n < srtpHeaderLen {
			continue
		}
		if (buf[0]&0xc0) != 0x80 || binary.BigEndian.Uint32(buf[8:12]) != c.ssrc {
			continue
		}
		copied := copy(p, buf[srtpHeaderLen:n])
		return copied, addr, nil
	}
}

// WireGuard Stealth Obfuscated Header
// [4B Obfuscated Magic ^ Mask][4B Sequence Number] = 8 bytes
const wgStealthHeaderLen = 8

type wgStealthPacketConn struct {
	net.PacketConn
	magic    [4]byte
	isServer bool
	seq      atomic.Uint32
}

func NewWGStealthPacketConn(pc net.PacketConn, password string, isServer bool) net.PacketConn {
	mac := hmac.New(sha256.New, []byte(password))
	mac.Write([]byte("archnet-wg-stealth-magic"))
	sum := mac.Sum(nil)
	var magic [4]byte
	copy(magic[:], sum[:4])

	return &wgStealthPacketConn{
		PacketConn: pc,
		magic:      magic,
		isServer:   isServer,
	}
}

func (c *wgStealthPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	s := c.seq.Add(1)
	frame := make([]byte, wgStealthHeaderLen+len(p))
	mask := byte(s)
	frame[0] = c.magic[0] ^ mask
	frame[1] = c.magic[1] ^ mask
	frame[2] = c.magic[2] ^ mask
	frame[3] = c.magic[3]
	binary.BigEndian.PutUint32(frame[4:8], s)
	copy(frame[wgStealthHeaderLen:], p)

	if _, err := c.PacketConn.WriteTo(frame, addr); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *wgStealthPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	bufPtr := rawPacketBufPool.Get().(*[]byte)
	defer rawPacketBufPool.Put(bufPtr)
	buf := *bufPtr

	for {
		n, addr, err := c.PacketConn.ReadFrom(buf)
		if err != nil {
			return 0, nil, err
		}
		if n < wgStealthHeaderLen {
			continue
		}
		mask := buf[7]
		if buf[0] != (c.magic[0]^mask) || buf[1] != (c.magic[1]^mask) || buf[2] != (c.magic[2]^mask) || buf[3] != c.magic[3] {
			continue
		}
		copied := copy(p, buf[wgStealthHeaderLen:n])
		return copied, addr, nil
	}
}

// DNSCrypt UDP Response Lookalike
// [2B TransactionID][2B 0x8180 (Response+RecursionAvailable)][2B Questions=1][2B Answers=1][4B Magic] = 12 bytes
const dnsCryptHeaderLen = 12

type dnsCryptPacketConn struct {
	net.PacketConn
	magic    [4]byte
	isServer bool
	seq      atomic.Uint32
}

func NewDNSCryptPacketConn(pc net.PacketConn, password string, isServer bool) net.PacketConn {
	mac := hmac.New(sha256.New, []byte(password))
	mac.Write([]byte("archnet-dnscrypt-magic"))
	sum := mac.Sum(nil)
	var magic [4]byte
	copy(magic[:], sum[:4])

	return &dnsCryptPacketConn{
		PacketConn: pc,
		magic:      magic,
		isServer:   isServer,
	}
}

func (c *dnsCryptPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	s := c.seq.Add(1)
	frame := make([]byte, dnsCryptHeaderLen+len(p))
	binary.BigEndian.PutUint16(frame[0:2], uint16(s))
	binary.BigEndian.PutUint16(frame[2:4], 0x8180) // Standard query response, No error
	binary.BigEndian.PutUint16(frame[4:6], 1)      // Questions
	binary.BigEndian.PutUint16(frame[6:8], 1)      // Answer RRs
	copy(frame[8:12], c.magic[:])
	copy(frame[dnsCryptHeaderLen:], p)

	if _, err := c.PacketConn.WriteTo(frame, addr); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *dnsCryptPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	bufPtr := rawPacketBufPool.Get().(*[]byte)
	defer rawPacketBufPool.Put(bufPtr)
	buf := *bufPtr

	for {
		n, addr, err := c.PacketConn.ReadFrom(buf)
		if err != nil {
			return 0, nil, err
		}
		if n < dnsCryptHeaderLen {
			continue
		}
		if binary.BigEndian.Uint16(buf[2:4]) != 0x8180 || !hmac.Equal(buf[8:12], c.magic[:]) {
			continue
		}
		copied := copy(p, buf[dnsCryptHeaderLen:n])
		return copied, addr, nil
	}
}

// NTPv4 Direct Server Packet Lookalike (RFC 5905)
// [1B LI/VN/Mode 0x24][1B Stratum 0x02][1B Poll 0x06][1B Precision 0xec][4B Magic] = 8 bytes
const ntpHeaderLen = 8

type ntpPacketConn struct {
	net.PacketConn
	magic    [4]byte
	isServer bool
	seq      atomic.Uint32
}

func NewNTPPacketConn(pc net.PacketConn, password string, isServer bool) net.PacketConn {
	mac := hmac.New(sha256.New, []byte(password))
	mac.Write([]byte("archnet-ntp-magic"))
	sum := mac.Sum(nil)
	var magic [4]byte
	copy(magic[:], sum[:4])

	return &ntpPacketConn{
		PacketConn: pc,
		magic:      magic,
		isServer:   isServer,
	}
}

func (c *ntpPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	frame := make([]byte, ntpHeaderLen+len(p))
	frame[0], frame[1], frame[2], frame[3] = 0x24, 0x02, 0x06, 0xec // LI=0, VN=4, Mode=4 (Server), Stratum=2 secondary
	copy(frame[4:8], c.magic[:])
	copy(frame[ntpHeaderLen:], p)

	if _, err := c.PacketConn.WriteTo(frame, addr); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *ntpPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	bufPtr := rawPacketBufPool.Get().(*[]byte)
	defer rawPacketBufPool.Put(bufPtr)
	buf := *bufPtr

	for {
		n, addr, err := c.PacketConn.ReadFrom(buf)
		if err != nil {
			return 0, nil, err
		}
		if n < ntpHeaderLen {
			continue
		}
		if buf[0] != 0x24 || !hmac.Equal(buf[4:8], c.magic[:]) {
			continue
		}
		copied := copy(p, buf[ntpHeaderLen:n])
		return copied, addr, nil
	}
}

// OpenVPN DCO (P_DATA_V2) Lookalike Header
// [1B opcode=0x48][3B magic][4B seq] = 8 bytes
const openvpnDCOHeaderLen = 8

type openvpnDCOPacketConn struct {
	net.PacketConn
	magic    [3]byte
	isServer bool
	seq      atomic.Uint32
}

func NewOpenVPNDCOPacketConn(pc net.PacketConn, password string, isServer bool) net.PacketConn {
	mac := hmac.New(sha256.New, []byte(password))
	mac.Write([]byte("archnet-openvpn-dco-magic"))
	sum := mac.Sum(nil)
	var magic [3]byte
	copy(magic[:], sum[:3])

	return &openvpnDCOPacketConn{
		PacketConn: pc,
		magic:      magic,
		isServer:   isServer,
	}
}

func (c *openvpnDCOPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	s := c.seq.Add(1)
	frame := make([]byte, openvpnDCOHeaderLen+len(p))
	frame[0] = 0x48 // P_DATA_V2 opcode
	copy(frame[1:4], c.magic[:])
	binary.BigEndian.PutUint32(frame[4:8], s)
	copy(frame[openvpnDCOHeaderLen:], p)

	if _, err := c.PacketConn.WriteTo(frame, addr); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *openvpnDCOPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	bufPtr := rawPacketBufPool.Get().(*[]byte)
	defer rawPacketBufPool.Put(bufPtr)
	buf := *bufPtr

	for {
		n, addr, err := c.PacketConn.ReadFrom(buf)
		if err != nil {
			return 0, nil, err
		}
		if n < openvpnDCOHeaderLen {
			continue
		}
		if buf[0] != 0x48 || !hmac.Equal(buf[1:4], c.magic[:]) {
			continue
		}
		copied := copy(p, buf[openvpnDCOHeaderLen:n])
		return copied, addr, nil
	}
}


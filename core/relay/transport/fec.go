package transport

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/klauspost/reedsolomon"
)

// Wire format for Stateless Reed-Solomon Forward Error Correction matching xtaci/kcp-go/v5:
//
// Data Packet:
//  0        4        6        8
// +--------+--------+--------+-------------------------------+
// | seqid  | type   | size   | payload                       |
// +--------+--------+--------+-------------------------------+
//   (4B LE)  (2B LE)  (2B LE)   (size-2 bytes)
//
// Parity Packet:
//  0        4        6
// +--------+--------+----------------------------------------+
// | seqid  | type   | RS parity body (size + payload padded) |
// +--------+--------+----------------------------------------+
//   (4B LE)  (2B LE)   (maxSize bytes)
const (
	FECHeaderLen       = 6
	FECLenPrefix       = 2
	FECOverhead        = FECHeaderLen + FECLenPrefix // 8 bytes
	fecHeaderSizePlus2 = FECHeaderLen + FECLenPrefix

	fecTypeData   uint16 = 0x00f1
	fecTypeParity uint16 = 0x00f2

	maxFECEncodeLatency = 500 // 500ms inactivity threshold (skip parity if sparse/idle)
	maxShardSets        = 3   // max concurrent shard sets before discarding old ones
	maxAutoTuneSamples  = 258
)

type fecPacket []byte

func (b fecPacket) seqid() uint32 { return binary.LittleEndian.Uint32(b[:4]) }
func (b fecPacket) flag() uint16  { return binary.LittleEndian.Uint16(b[4:6]) }
func (b fecPacket) data() []byte  { return b[FECHeaderLen:] }

type pulse struct {
	bit bool
	seq uint32
}

type autoTune struct {
	pulses    [maxAutoTuneSamples]pulse
	sortCache [maxAutoTuneSamples]pulse
	head      int
	tail      int
	count     int
}

func (tune *autoTune) Sample(bit bool, seq uint32) {
	tune.pulses[tune.tail] = pulse{bit: bit, seq: seq}
	tune.tail = (tune.tail + 1) % maxAutoTuneSamples
	if tune.count < maxAutoTuneSamples {
		tune.count++
	} else {
		tune.head = (tune.head + 1) % maxAutoTuneSamples
	}
}

func (tune *autoTune) FindPeriod(bit bool) int {
	if tune.count < 3 {
		return -1
	}
	for i := 0; i < tune.count; i++ {
		idx := (tune.head + i) % maxAutoTuneSamples
		tune.sortCache[i] = tune.pulses[idx]
	}
	sorted := tune.sortCache[:tune.count]
	sort.Slice(sorted, func(i, j int) bool {
		return int32(sorted[i].seq-sorted[j].seq) < 0
	})

	leftEdge := -1
	last := sorted[0]
	for idx := 1; idx < len(sorted); idx++ {
		if last.seq+1 == sorted[idx].seq {
			if last.bit != bit && sorted[idx].bit == bit {
				leftEdge = idx
				break
			}
		} else {
			return -1
		}
		last = sorted[idx]
	}
	if leftEdge == -1 {
		return -1
	}

	last = sorted[leftEdge]
	for idx := leftEdge + 1; idx < len(sorted); idx++ {
		if last.seq+1 == sorted[idx].seq {
			if last.bit == bit && sorted[idx].bit != bit {
				return idx - leftEdge
			}
		} else {
			return -1
		}
		last = sorted[idx]
	}
	return -1
}

var fecShardPool = sync.Pool{
	New: func() any {
		b := make([]byte, 2048)
		return &b
	},
}

func getFECShard(needed int) []byte {
	if needed <= 2048 {
		bufPtr := fecShardPool.Get().(*[]byte)
		return (*bufPtr)[:needed]
	}
	return make([]byte, needed)
}

func putFECShard(b []byte) {
	if cap(b) >= 2048 {
		b = b[:2048]
		clear(b)
		fecShardPool.Put(&b)
	}
}

// FECPacketConn is a net.PacketConn decorator providing stateless Reed-Solomon FEC
// matching xtaci/kcp-go/v5 design characteristics with 0ms transmit delay and zero head-of-line blocking.
type FECPacketConn struct {
	below        net.PacketConn
	dataShards   int
	parityShards int
	totalShards  int
	paws         uint32
	codec        reedsolomon.Encoder

	sendMu         sync.Mutex
	next           uint32
	shardCount     int
	maxSize        int
	shardCache     [][]byte
	encodeCache    [][]byte
	tsLatestPacket int64
	sendPeer       net.Addr
	sendFrame      []byte
	headerMask     uint64

	readMu    sync.Mutex
	readFrame []byte

	recvMu          sync.Mutex
	shardSet        map[uint32]*fecShardSet
	newestShardID   uint32
	hasNewestShard  bool
	decodeCache     [][]byte
	flagCache       []bool
	autoTune      autoTune
	shouldTune    bool
	pending       []fecRebuiltPacket
	closed        atomic.Bool
	closeCh       chan struct{}
}

type fecRebuiltPacket struct {
	data []byte
	addr net.Addr
}

type fecShardSet struct {
	shards map[uint32]fecPacket
	addr   net.Addr
}

func newFECShardSet(addr net.Addr) *fecShardSet {
	return &fecShardSet{
		shards: make(map[uint32]fecPacket),
		addr:   addr,
	}
}

func (s *fecShardSet) Len() int { return len(s.shards) }

// NewFECPacketConn wraps below in a stateless Reed-Solomon FEC decorator.
func NewFECPacketConn(below net.PacketConn, dataShards, parityShards int) (net.PacketConn, error) {
	return NewFECPacketConnWithSecret(below, dataShards, parityShards, "")
}

// NewFECPacketConnWithSecret wraps below in a stateless Reed-Solomon FEC decorator with
// encrypted/obfuscated wire headers derived from password to prevent DPI traffic shaping.
func NewFECPacketConnWithSecret(below net.PacketConn, dataShards, parityShards int, password string) (net.PacketConn, error) {
	if dataShards <= 0 || parityShards <= 0 {
		return below, nil
	}
	if dataShards+parityShards > 256 {
		return nil, fmt.Errorf("fec: total shards (%d) exceeds Reed-Solomon limit (256)", dataShards+parityShards)
	}
	codec, err := reedsolomon.New(dataShards, parityShards)
	if err != nil {
		return nil, fmt.Errorf("fec: create reedsolomon encoder (%d:%d): %w", dataShards, parityShards, err)
	}

	shardSize := dataShards + parityShards
	paws := 0xffffffff / uint32(shardSize) * uint32(shardSize)

	var first [4]byte
	_, _ = rand.Read(first[:])
	initialSeq := (binary.LittleEndian.Uint32(first[:]) / uint32(shardSize)) * uint32(shardSize)

	var mask uint64
	if password != "" {
		if k, kErr := DeriveRealityKey(password, "archnet-fec-mask"); kErr == nil {
			mask = binary.BigEndian.Uint64(k[:8])
		}
	}

	f := &FECPacketConn{
		below:        below,
		dataShards:   dataShards,
		parityShards: parityShards,
		totalShards:  shardSize,
		paws:         paws,
		codec:        codec,
		next:         initialSeq,
		shardCache:   make([][]byte, shardSize),
		encodeCache:  make([][]byte, shardSize),
		headerMask:   mask,
		shardSet:     make(map[uint32]*fecShardSet),
		decodeCache:  make([][]byte, shardSize),
		flagCache:    make([]bool, shardSize),
		closeCh:      make(chan struct{}),
	}
	for i := range f.shardCache {
		f.shardCache[i] = make([]byte, 2048)
	}
	return f, nil
}

// WriteTo transmits p as a data shard immediately (0 ms delay), and flushes Reed-Solomon
// parity shards once quorum is reached (kcp-go postProcess style).
func (c *FECPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	if len(p) > 65533 {
		return 0, errors.New("fec: packet exceeds max payload size")
	}

	c.sendMu.Lock()
	defer c.sendMu.Unlock()

	bodyLen := FECLenPrefix + len(p)
	frameSize := FECHeaderLen + bodyLen
	if cap(c.sendFrame) < frameSize {
		c.sendFrame = make([]byte, frameSize)
	} else {
		c.sendFrame = c.sendFrame[:frameSize]
	}

	// Format kcp-go data packet header: | seqid(4B LE) | typeData(2B LE) | size(2B LE) |
	binary.LittleEndian.PutUint32(c.sendFrame[0:4], c.next)
	binary.LittleEndian.PutUint16(c.sendFrame[4:6], fecTypeData)
	binary.LittleEndian.PutUint16(c.sendFrame[6:8], uint16(bodyLen))
	copy(c.sendFrame[fecHeaderSizePlus2:], p)
	c.next = (c.next + 1) % c.paws

	// Cache shard for parity calculation
	if cap(c.shardCache[c.shardCount]) < bodyLen {
		c.shardCache[c.shardCount] = make([]byte, bodyLen)
	}
	shardBuf := c.shardCache[c.shardCount][:bodyLen]
	copy(shardBuf, c.sendFrame[FECHeaderLen:frameSize])
	c.shardCache[c.shardCount] = shardBuf
	c.shardCount++
	if bodyLen > c.maxSize {
		c.maxSize = bodyLen
	}
	c.sendPeer = addr

	// Header encryption if configured (6-byte FEC header only; payload size stays intact)
	if c.headerMask != 0 {
		h0 := binary.LittleEndian.Uint32(c.sendFrame[0:4]) ^ uint32(c.headerMask>>32)
		h1 := binary.LittleEndian.Uint16(c.sendFrame[4:6]) ^ uint16(c.headerMask&0xFFFF)
		binary.LittleEndian.PutUint32(c.sendFrame[0:4], h0)
		binary.LittleEndian.PutUint16(c.sendFrame[4:6], h1)
	}
	n, err := c.below.WriteTo(c.sendFrame, addr)
	if c.headerMask != 0 {
		h0 := binary.LittleEndian.Uint32(c.sendFrame[0:4]) ^ uint32(c.headerMask>>32)
		h1 := binary.LittleEndian.Uint16(c.sendFrame[4:6]) ^ uint16(c.headerMask&0xFFFF)
		binary.LittleEndian.PutUint32(c.sendFrame[0:4], h0)
		binary.LittleEndian.PutUint16(c.sendFrame[4:6], h1)
	}

	// Reed-Solomon parity generation upon collecting dataShards
	now := time.Now().UnixMilli()
	if c.shardCount == c.dataShards {
		// If interval between packets exceeds 500ms, skip parity generation to avoid useless parity on idle/sparse ticks
		if c.tsLatestPacket > 0 && now-c.tsLatestPacket < maxFECEncodeLatency {
			for i := 0; i < c.dataShards; i++ {
				shard := c.shardCache[i]
				slen := len(shard)
				if cap(shard) < c.maxSize {
					padded := make([]byte, c.maxSize)
					copy(padded, shard)
					c.shardCache[i] = padded
				} else {
					c.shardCache[i] = shard[:c.maxSize]
					clear(c.shardCache[i][slen:c.maxSize])
				}
				c.encodeCache[i] = c.shardCache[i][:c.maxSize]
			}
			for i := c.dataShards; i < c.totalShards; i++ {
				if cap(c.shardCache[i]) < c.maxSize {
					c.shardCache[i] = make([]byte, c.maxSize)
				} else {
					c.shardCache[i] = c.shardCache[i][:c.maxSize]
					clear(c.shardCache[i])
				}
				c.encodeCache[i] = c.shardCache[i][:c.maxSize]
			}

			if err := c.codec.Encode(c.encodeCache); err == nil {
				parityFrameSize := FECHeaderLen + c.maxSize
				if cap(c.sendFrame) < parityFrameSize {
					c.sendFrame = make([]byte, parityFrameSize)
				} else {
					c.sendFrame = c.sendFrame[:parityFrameSize]
				}
				for i := c.dataShards; i < c.totalShards; i++ {
					binary.LittleEndian.PutUint32(c.sendFrame[0:4], c.next)
					binary.LittleEndian.PutUint16(c.sendFrame[4:6], fecTypeParity)
					copy(c.sendFrame[FECHeaderLen:], c.shardCache[i][:c.maxSize])
					c.next = (c.next + 1) % c.paws

					if c.headerMask != 0 {
						h0 := binary.LittleEndian.Uint32(c.sendFrame[0:4]) ^ uint32(c.headerMask>>32)
						h1 := binary.LittleEndian.Uint16(c.sendFrame[4:6]) ^ uint16(c.headerMask&0xFFFF)
						binary.LittleEndian.PutUint32(c.sendFrame[0:4], h0)
						binary.LittleEndian.PutUint16(c.sendFrame[4:6], h1)
					}
					_, _ = c.below.WriteTo(c.sendFrame, c.sendPeer)
					if c.headerMask != 0 {
						h0 := binary.LittleEndian.Uint32(c.sendFrame[0:4]) ^ uint32(c.headerMask>>32)
						h1 := binary.LittleEndian.Uint16(c.sendFrame[4:6]) ^ uint16(c.headerMask&0xFFFF)
						binary.LittleEndian.PutUint32(c.sendFrame[0:4], h0)
						binary.LittleEndian.PutUint16(c.sendFrame[4:6], h1)
					}
				}
			} else {
				c.next = (c.next + uint32(c.parityShards)) % c.paws
			}
		} else {
			// Discontinuous data: skip parity to avoid emitting obsolete parity packets
			c.next = (c.next + uint32(c.parityShards)) % c.paws
		}
		c.shardCount = 0
		c.maxSize = 0
	}

	c.tsLatestPacket = now
	if err != nil {
		return 0, err
	}
	_ = n
	return len(p), nil
}

// ReadFrom delivers incoming data packets immediately (0 ms delay), and instantly
// delivers any missing packet reconstructed by Reed-Solomon parity shards.
func (c *FECPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	// 1. Deliver any previously reconstructed packet
	if n, addr, ok := c.popPending(p); ok {
		return n, addr, nil
	}

	need := len(p) + FECOverhead + 64
	if cap(c.readFrame) < need {
		c.readFrame = make([]byte, need)
	}
	buf := c.readFrame[:need]

	for !c.closed.Load() {
		n, addr, err := c.below.ReadFrom(buf)
		if err != nil {
			return 0, nil, err
		}
		if n < FECHeaderLen {
			continue
		}

		if c.headerMask != 0 {
			h0 := binary.LittleEndian.Uint32(buf[0:4]) ^ uint32(c.headerMask>>32)
			h1 := binary.LittleEndian.Uint16(buf[4:6]) ^ uint16(c.headerMask&0xFFFF)
			binary.LittleEndian.PutUint32(buf[0:4], h0)
			binary.LittleEndian.PutUint16(buf[4:6], h1)
		}

		flag := binary.LittleEndian.Uint16(buf[4:6])
		if flag != fecTypeData && flag != fecTypeParity {
			// Transparent pass-through for non-FEC frames
			if c.headerMask != 0 {
				h0 := binary.LittleEndian.Uint32(buf[0:4]) ^ uint32(c.headerMask>>32)
				h1 := binary.LittleEndian.Uint16(buf[4:6]) ^ uint16(c.headerMask&0xFFFF)
				binary.LittleEndian.PutUint32(buf[0:4], h0)
				binary.LittleEndian.PutUint16(buf[4:6], h1)
			}
			copied := copy(p, buf[:n])
			return copied, addr, nil
		}

		seqid := binary.LittleEndian.Uint32(buf[:4])
		if seqid >= c.paws {
			continue
		}

		payload, deliverNow := c.absorb(buf[:n], addr)
		if deliverNow && len(payload) > 0 {
			copied := copy(p, payload)
			return copied, addr, nil
		}

		if nP, aP, ok := c.popPending(p); ok {
			return nP, aP, nil
		}
	}
	return 0, nil, net.ErrClosed
}

func (c *FECPacketConn) popPending(p []byte) (int, net.Addr, bool) {
	c.recvMu.Lock()
	defer c.recvMu.Unlock()
	if len(c.pending) == 0 {
		return 0, nil, false
	}
	pkt := c.pending[0]
	c.pending = c.pending[1:]
	copied := copy(p, pkt.data)
	return copied, pkt.addr, true
}

func (c *FECPacketConn) absorb(raw []byte, addr net.Addr) ([]byte, bool) {
	c.recvMu.Lock()
	defer c.recvMu.Unlock()

	in := fecPacket(raw)
	seqid := in.seqid()
	flag := in.flag()

	// Auto-tune pulse sampling
	c.autoTune.Sample(flag == fecTypeData, seqid)
	shardIdx := seqid % uint32(c.totalShards)
	if (shardIdx < uint32(c.dataShards) && flag != fecTypeData) || (shardIdx >= uint32(c.dataShards) && flag != fecTypeParity) {
		c.shouldTune = true
	}

	if c.shouldTune {
		autoDS := c.autoTune.FindPeriod(true)
		autoPS := c.autoTune.FindPeriod(false)
		if autoDS > 0 && autoPS > 0 && autoDS+autoPS <= 256 {
			if autoDS != c.dataShards || autoPS != c.parityShards {
				if codec, err := reedsolomon.New(autoDS, autoPS); err == nil {
					c.dataShards = autoDS
					c.parityShards = autoPS
					c.totalShards = autoDS + autoPS
					c.codec = codec
					c.paws = 0xffffffff / uint32(c.totalShards) * uint32(c.totalShards)
					for _, set := range c.shardSet {
						for _, pkt := range set.shards {
							putFECShard([]byte(pkt))
						}
					}
					c.shardSet = make(map[uint32]*fecShardSet)
					c.decodeCache = make([][]byte, c.totalShards)
					c.flagCache = make([]bool, c.totalShards)
				}
			}
			c.shouldTune = false
		}
	}

	shardID := seqid / uint32(c.totalShards)
	set, exists := c.shardSet[shardID]
	if !exists {
		set = newFECShardSet(addr)
		c.shardSet[shardID] = set
	}

	if _, dup := set.shards[seqid]; dup {
		return nil, false
	}

	shardCopy := fecPacket(getFECShard(len(in)))
	copy(shardCopy, in)
	set.shards[seqid] = shardCopy

	var out []byte
	var deliver bool
	if flag == fecTypeData && len(in) >= fecHeaderSizePlus2 {
		sz := binary.LittleEndian.Uint16(in[6:8])
		if sz >= 2 && int(sz) <= len(in)-FECHeaderLen {
			out = in[fecHeaderSizePlus2 : FECHeaderLen+int(sz)]
			deliver = true
		}
	}

	// Quorum check and Reed-Solomon data reconstruction
	if set.Len() >= c.dataShards {
		var numDataShard, maxlen int
		for k := range c.decodeCache {
			c.decodeCache[k] = nil
			c.flagCache[k] = false
		}

		for sID, pkt := range set.shards {
			idx := sID % uint32(c.totalShards)
			c.decodeCache[idx] = pkt.data()
			c.flagCache[idx] = true
			if pkt.flag() == fecTypeData {
				numDataShard++
			}
			if len(pkt.data()) > maxlen {
				maxlen = len(pkt.data())
			}
		}

		if numDataShard < c.dataShards && maxlen >= FECLenPrefix {
			var newBuffers [][]byte
			for k := range c.decodeCache {
				if c.decodeCache[k] != nil {
					dlen := len(c.decodeCache[k])
					if cap(c.decodeCache[k]) < maxlen {
						expanded := getFECShard(maxlen)
						copy(expanded, c.decodeCache[k])
						c.decodeCache[k] = expanded
					} else {
						c.decodeCache[k] = c.decodeCache[k][:maxlen]
					}
					clear(c.decodeCache[k][dlen:])
				} else if k < c.dataShards {
					recoveredBuf := getFECShard(maxlen)[:0]
					c.decodeCache[k] = recoveredBuf
					newBuffers = append(newBuffers, recoveredBuf)
				}
			}

			if err := c.codec.ReconstructData(c.decodeCache); err == nil {
				for k := range c.decodeCache[:c.dataShards] {
					if !c.flagCache[k] {
						recShard := c.decodeCache[k]
						if len(recShard) >= FECLenPrefix {
							sz := binary.LittleEndian.Uint16(recShard[:FECLenPrefix])
							if sz >= 2 && int(sz) <= len(recShard) {
								recPayload := append([]byte(nil), recShard[FECLenPrefix:int(sz)]...)
								c.pending = append(c.pending, fecRebuiltPacket{data: recPayload, addr: set.addr})
							}
						}
					}
				}
			}
			for _, buf := range newBuffers {
				putFECShard(buf)
			}
		}

		// Discard completed shard set and recycle buffers
		for _, pkt := range set.shards {
			putFECShard([]byte(pkt))
		}
		delete(c.shardSet, shardID)
	}

	if !c.hasNewestShard || int32((shardID-c.newestShardID)*uint32(c.totalShards)) > 0 {
		c.newestShardID = shardID
		c.hasNewestShard = true
	}
	c.discardShardsLocked()

	return out, deliver
}

func (c *FECPacketConn) discardShardsLocked() {
	for sID, set := range c.shardSet {
		if int32((c.newestShardID-sID)*uint32(c.totalShards)) > maxShardSets*int32(c.totalShards) {
			for _, pkt := range set.shards {
				putFECShard([]byte(pkt))
			}
			delete(c.shardSet, sID)
		}
	}
}

func (c *FECPacketConn) Close() error {
	if c.closed.CompareAndSwap(false, true) {
		close(c.closeCh)
		c.recvMu.Lock()
		for _, set := range c.shardSet {
			for _, pkt := range set.shards {
				putFECShard([]byte(pkt))
			}
		}
		c.shardSet = nil
		c.recvMu.Unlock()
		return c.below.Close()
	}
	return nil
}

func (c *FECPacketConn) LocalAddr() net.Addr                { return c.below.LocalAddr() }
func (c *FECPacketConn) SetDeadline(t time.Time) error      { return c.below.SetDeadline(t) }
func (c *FECPacketConn) SetReadDeadline(t time.Time) error  { return c.below.SetReadDeadline(t) }
func (c *FECPacketConn) SetWriteDeadline(t time.Time) error { return c.below.SetWriteDeadline(t) }

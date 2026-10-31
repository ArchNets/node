package transport

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/klauspost/reedsolomon"
)

// Wire format for Stateless Reed-Solomon Forward Error Correction (UDPspeeder style):
//
//	 0        1                    5        6        8
//	+--------+--------------------+--------+--------+---------------+
//	| kind   | group (uint32BE)   | index  | length | body          |
//	+--------+--------------------+--------+--------+---------------+
//
// - kind: 0x00 = Data Shard, 0x01 = Parity Shard
// - group: Monotonically increasing group ID
// - index: 0..DataShards-1 for data, DataShards..TotalShards-1 for parity
// - length: Original unpadded payload length (2 bytes BE)
// - body: Unpadded payload (for data), or padded parity shard
const (
	FECHeaderLen = 6
	FECLenPrefix = 2
	FECOverhead  = FECHeaderLen + FECLenPrefix // 8 bytes

	fecKindData   byte = 0x00
	fecKindParity byte = 0x01

	fecWindow = 32 // Number of recent groups cached on receiver
)

// FECPacketConn is a net.PacketConn decorator providing stateless Reed-Solomon FEC.
// Data packets are transmitted and received with 0 ms added latency (zero head-of-line blocking).
// When packet loss occurs, missing packets are reconstructed in 0 RTT using parity shards.
type FECPacketConn struct {
	below        net.PacketConn
	dataShards   int
	parityShards int
	totalShards  int
	enc          reedsolomon.Encoder

	sendMu      sync.Mutex
	sendGrp     uint32
	sendIdx     int
	sendPad     [][]byte
	sendMax     int
	sendPeer    net.Addr
	sendFrame   []byte
	flushTimer  *time.Timer
	flushActive bool

	readMu    sync.Mutex
	readFrame []byte

	recvMu  sync.Mutex
	groups  map[uint32]*fecRecvGroup
	order   []uint32
	pending []fecRebuiltPacket
	closed  atomic.Bool
	closeCh chan struct{}
}

type fecRebuiltPacket struct {
	data []byte
	addr net.Addr
}

type fecRecvGroup struct {
	shards    [][]byte
	haveData  int
	haveTotal int
	size      int
	delivered []bool
	done      bool
	addr      net.Addr
}

// NewFECPacketConn wraps below in a stateless Reed-Solomon FEC decorator.
// If dataShards <= 0 or parityShards <= 0, below is returned as-is with no FEC overhead.
func NewFECPacketConn(below net.PacketConn, dataShards, parityShards int) (net.PacketConn, error) {
	if dataShards <= 0 || parityShards <= 0 {
		return below, nil
	}
	if dataShards+parityShards > 256 {
		return nil, fmt.Errorf("fec: total shards (%d) exceeds Reed-Solomon limit (256)", dataShards+parityShards)
	}
	enc, err := reedsolomon.New(dataShards, parityShards)
	if err != nil {
		return nil, fmt.Errorf("fec: create reedsolomon encoder (%d:%d): %w", dataShards, parityShards, err)
	}

	var first [4]byte
	_, _ = rand.Read(first[:])
	initialGrp := binary.BigEndian.Uint32(first[:])

	f := &FECPacketConn{
		below:        below,
		dataShards:   dataShards,
		parityShards: parityShards,
		totalShards:  dataShards + parityShards,
		enc:          enc,
		sendGrp:      initialGrp,
		groups:       make(map[uint32]*fecRecvGroup),
		closeCh:      make(chan struct{}),
	}
	return f, nil
}

// WriteTo transmits p as a data shard immediately (0 ms delay), and flushes Reed-Solomon
// parity shards once the group completes (or on sparse packet timeout).
func (c *FECPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	if len(p) > 65535 {
		return 0, errors.New("fec: packet exceeds 65535 bytes")
	}

	c.sendMu.Lock()
	defer c.sendMu.Unlock()

	if c.sendPad == nil {
		c.sendPad = make([][]byte, c.totalShards)
	}

	need := FECLenPrefix + len(p)
	shard := c.sendPad[c.sendIdx]
	if cap(shard) < need {
		shard = make([]byte, need)
	} else {
		shard = shard[:need]
	}
	binary.BigEndian.PutUint16(shard[:FECLenPrefix], uint16(len(p)))
	copy(shard[FECLenPrefix:], p)
	c.sendPad[c.sendIdx] = shard
	if need > c.sendMax {
		c.sendMax = need
	}
	c.sendPeer = addr

	// Frame: [1B kind=0][4B grp][1B idx][2B len][payload]
	frameSize := FECHeaderLen + need
	if cap(c.sendFrame) < frameSize {
		c.sendFrame = make([]byte, frameSize)
	} else {
		c.sendFrame = c.sendFrame[:frameSize]
	}
	c.sendFrame[0] = fecKindData
	binary.BigEndian.PutUint32(c.sendFrame[1:5], c.sendGrp)
	c.sendFrame[5] = byte(c.sendIdx)
	copy(c.sendFrame[FECHeaderLen:], shard)

	n, err := c.below.WriteTo(c.sendFrame, addr)
	c.sendIdx++

	if c.sendIdx == c.dataShards {
		if c.flushActive && c.flushTimer != nil {
			c.flushTimer.Stop()
			c.flushActive = false
		}
		c.flushParityLocked()
	} else if !c.flushActive {
		// Low-rate gaming packets: start an 8ms flush timer so a lone packet gets parity protection without waiting
		c.flushActive = true
		if c.flushTimer == nil {
			c.flushTimer = time.AfterFunc(8*time.Millisecond, func() {
				c.sendMu.Lock()
				defer c.sendMu.Unlock()
				if c.flushActive && c.sendIdx > 0 {
					c.flushActive = false
					c.flushParityLocked()
				}
			})
		} else {
			c.flushTimer.Reset(8 * time.Millisecond)
		}
	}

	if err != nil {
		return 0, err
	}
	_ = n
	return len(p), nil
}

func (c *FECPacketConn) flushParityLocked() {
	if c.sendIdx == 0 || c.sendMax == 0 || c.sendPeer == nil {
		c.sendGrp++
		c.sendIdx = 0
		c.sendMax = 0
		return
	}

	size := c.sendMax
	actualCount := c.sendIdx
	// Zero-pad missing data shards if partial flush
	for i := 0; i < c.dataShards; i++ {
		shard := c.sendPad[i]
		if i >= actualCount || shard == nil {
			shard = make([]byte, size)
			c.sendPad[i] = shard
		} else if len(shard) < size {
			padded := make([]byte, size)
			copy(padded, shard)
			c.sendPad[i] = padded
		}
	}
	for i := c.dataShards; i < c.totalShards; i++ {
		if cap(c.sendPad[i]) < size {
			c.sendPad[i] = make([]byte, size)
		} else {
			c.sendPad[i] = c.sendPad[i][:size]
			clear(c.sendPad[i])
		}
	}

	if err := c.enc.Encode(c.sendPad); err == nil {
		frameSize := FECHeaderLen + size
		if cap(c.sendFrame) < frameSize {
			c.sendFrame = make([]byte, frameSize)
		} else {
			c.sendFrame = c.sendFrame[:frameSize]
		}
		// Encode actualCount (1..dataShards) in byte 0 for parity shards so the receiver
		// knows how many data shards were actually transmitted in partial/sparse groups.
		parityKind := byte(actualCount)
		for i := c.dataShards; i < c.totalShards; i++ {
			c.sendFrame[0] = parityKind
			binary.BigEndian.PutUint32(c.sendFrame[1:5], c.sendGrp)
			c.sendFrame[5] = byte(i)
			copy(c.sendFrame[FECHeaderLen:], c.sendPad[i])
			_, _ = c.below.WriteTo(c.sendFrame, c.sendPeer)
		}
	}

	c.sendGrp++
	c.sendIdx = 0
	c.sendMax = 0
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

		kind := buf[0]
		if int(kind) > c.dataShards {
			// Transparent pass-through for non-FEC frames
			copied := copy(p, buf[:n])
			return copied, addr, nil
		}

		group := binary.BigEndian.Uint32(buf[1:5])
		index := int(buf[5])
		body := buf[FECHeaderLen:n]

		payload, deliverNow := c.absorb(kind, group, index, body, addr)
		if deliverNow && len(payload) > 0 {
			copied := copy(p, payload)
			return copied, addr, nil
		}

		// Check if parity completed a reconstruction
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

func (c *FECPacketConn) absorb(kind byte, group uint32, index int, body []byte, addr net.Addr) ([]byte, bool) {
	c.recvMu.Lock()
	defer c.recvMu.Unlock()

	isParity := kind >= 1 && int(kind) <= c.dataShards
	if index >= c.totalShards || (kind == fecKindData && index >= c.dataShards) || (isParity && index < c.dataShards) {
		return nil, false
	}

	g := c.groups[group]
	if g == nil {
		g = &fecRecvGroup{
			shards:    make([][]byte, c.totalShards),
			delivered: make([]bool, c.dataShards),
			addr:      addr,
		}
		c.groups[group] = g
		c.order = append(c.order, group)
		c.evictLocked()
	}

	if g.shards[index] == nil {
		g.shards[index] = append([]byte(nil), body...)
		g.haveTotal++
		if index < c.dataShards {
			g.haveData++
		}
		if isParity {
			if g.size == 0 {
				g.size = len(body)
			}
			// If this was a partial/sparse group (actualCount < dataShards), pre-fill the
			// unused data shard slots (actualCount .. dataShards-1) with zeros so Reed-Solomon
			// can immediately reconstruct lost packets in sparse gaming bursts.
			actualCount := int(kind)
			for i := actualCount; i < c.dataShards; i++ {
				if g.shards[i] == nil {
					g.shards[i] = make([]byte, g.size)
					g.haveTotal++
					g.haveData++
					g.delivered[i] = true
				}
			}
		}
	}

	var out []byte
	var deliver bool
	if kind == fecKindData && !g.delivered[index] {
		g.delivered[index] = true
		if len(body) >= FECLenPrefix {
			pLen := int(binary.BigEndian.Uint16(body[:FECLenPrefix]))
			if pLen <= len(body)-FECLenPrefix {
				out = body[FECLenPrefix : FECLenPrefix+pLen]
				deliver = true
			}
		}
	}

	c.reconstructLocked(g)
	return out, deliver
}

func (c *FECPacketConn) reconstructLocked(g *fecRecvGroup) {
	if g.done || g.haveData == c.dataShards || g.haveTotal < c.dataShards || g.size == 0 {
		return
	}

	work := make([][]byte, c.totalShards)
	for i, s := range g.shards {
		if s == nil {
			continue
		}
		if len(s) == g.size {
			work[i] = s
			continue
		}
		if len(s) > g.size {
			return
		}
		padded := make([]byte, g.size)
		copy(padded, s)
		work[i] = padded
	}

	if err := c.enc.Reconstruct(work); err != nil {
		return
	}
	g.done = true

	for i := 0; i < c.dataShards; i++ {
		if g.delivered[i] || work[i] == nil || len(work[i]) < FECLenPrefix {
			continue
		}
		pLen := int(binary.BigEndian.Uint16(work[i][:FECLenPrefix]))
		if pLen <= len(work[i])-FECLenPrefix {
			g.delivered[i] = true
			recovered := append([]byte(nil), work[i][FECLenPrefix:FECLenPrefix+pLen]...)
			c.pending = append(c.pending, fecRebuiltPacket{data: recovered, addr: g.addr})
		}
	}
}

func (c *FECPacketConn) evictLocked() {
	for len(c.order) > fecWindow {
		oldest := c.order[0]
		c.order = c.order[1:]
		delete(c.groups, oldest)
	}
}

func (c *FECPacketConn) Close() error {
	if c.closed.CompareAndSwap(false, true) {
		close(c.closeCh)
		c.sendMu.Lock()
		if c.flushTimer != nil {
			c.flushTimer.Stop()
		}
		c.sendMu.Unlock()
		return c.below.Close()
	}
	return nil
}

func (c *FECPacketConn) LocalAddr() net.Addr                { return c.below.LocalAddr() }
func (c *FECPacketConn) SetDeadline(t time.Time) error      { return c.below.SetDeadline(t) }
func (c *FECPacketConn) SetReadDeadline(t time.Time) error  { return c.below.SetReadDeadline(t) }
func (c *FECPacketConn) SetWriteDeadline(t time.Time) error { return c.below.SetWriteDeadline(t) }

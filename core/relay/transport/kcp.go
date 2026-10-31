package transport

import (
	"context"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtaci/kcp-go/v5"
	"golang.org/x/crypto/pbkdf2"
)

var (
	kcpKeyCache sync.Map // password -> []byte (32-byte AES key)
)

// KCPSettings defines fine-tuning parameters for KCP sessions.
type KCPSettings struct {
	MTU          int
	Interval     int
	Resend       int
	NoDelay      int
	NoCongestion int
	SndWnd       int
	RcvWnd       int
	DataShards   int
	ParityShards int
}

func DefaultKCPSettings(useFEC bool) KCPSettings {
	dataShards := 0
	parityShards := 0
	mtu := 1350
	if useFEC {
		dataShards = 10
		parityShards = 3
		mtu = 1250 // Conservative MTU when FEC is active
	}
	return KCPSettings{
		MTU:          mtu,
		Interval:     10,
		Resend:       2,
		NoDelay:      1,
		NoCongestion: 1,
		SndWnd:       1024,
		RcvWnd:       1024,
		DataShards:   dataShards,
		ParityShards: parityShards,
	}
}

// kcpCrypt derives and caches an AES-256 block cipher from the tunnel password.
// Encrypts both KCP segments and Reed-Solomon FEC headers in-place on the wire.
func kcpCrypt(password string) (kcp.BlockCrypt, error) {
	if key, ok := kcpKeyCache.Load(password); ok {
		return kcp.NewAESBlockCrypt(key.([]byte))
	}
	key := pbkdf2.Key([]byte(password), []byte("archnet-kcp-v1"), 100_000, 32, sha256.New)
	kcpKeyCache.Store(password, key)
	return kcp.NewAESBlockCrypt(key)
}

// ApplyKCPSettings configures low-latency gaming parameters on an active KCP session.
func ApplyKCPSettings(session *kcp.UDPSession, s KCPSettings) {
	session.SetNoDelay(s.NoDelay, s.Interval, s.Resend, s.NoCongestion)
	session.SetWindowSize(s.SndWnd, s.RcvWnd)
	session.SetMtu(s.MTU)
	session.SetStreamMode(true)
	session.SetWriteDelay(false)
	session.SetACKNoDelay(true)
	session.SetDSCP(46) // DSCP 46 Expedited Forwarding (EF) for low latency
	_ = session.SetReadBuffer(8 * 1024 * 1024)
	_ = session.SetWriteBuffer(8 * 1024 * 1024)
}

// UDPCarrierListener wraps a KCP listener for UDP, raw PCK (TCP), or raw XDI (ICMP).
type UDPCarrierListener struct {
	ln       *kcp.Listener
	pconn    io.Closer
	settings KCPSettings
	closed   atomic.Bool
}

func (l *UDPCarrierListener) Accept(ctx context.Context) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	sess, err := l.ln.AcceptKCP()
	if err != nil {
		return nil, err
	}
	ApplyKCPSettings(sess, l.settings)
	return IdleAwareKCP(sess, l.settings), nil
}

func (l *UDPCarrierListener) Close() error {
	if l.closed.CompareAndSwap(false, true) {
		var err error
		if l.ln != nil {
			err = l.ln.Close()
		}
		if l.pconn != nil {
			_ = l.pconn.Close()
		}
		return err
	}
	return nil
}

// newPacketCarrierListener wraps a raw packet connection (pck TCP, xdi ICMP) into a KCP listener.
func newPacketCarrierListener(pconn net.PacketConn, udpConn *net.UDPConn, password string, useFEC bool) *UDPCarrierListener {
	settings := DefaultKCPSettings(useFEC)
	block, err := kcpCrypt(password)
	if err != nil {
		_ = pconn.Close()
		return nil
	}
	ln, err := kcp.ServeConn(block, settings.DataShards, settings.ParityShards, pconn)
	if err != nil {
		_ = pconn.Close()
		return nil
	}
	_ = ln.SetDSCP(46)
	return &UDPCarrierListener{
		ln:       ln,
		pconn:    pconn,
		settings: settings,
	}
}

// ListenUDPCarrier starts a high-performance UDP listener with KCP + Reed-Solomon FEC.
func ListenUDPCarrier(addr, password string, useFEC bool) (*UDPCarrierListener, *net.UDPConn, error) {
	return ListenUDPCarrierWithSettings(addr, password, DefaultKCPSettings(useFEC))
}

// ListenUDPCarrierWithSettings starts a UDP KCP listener using custom KCPSettings.
func ListenUDPCarrierWithSettings(addr, password string, settings KCPSettings) (*UDPCarrierListener, *net.UDPConn, error) {
	block, err := kcpCrypt(password)
	if err != nil {
		return nil, nil, err
	}
	ln, err := kcp.ListenWithOptions(addr, block, settings.DataShards, settings.ParityShards)
	if err != nil {
		return nil, nil, fmt.Errorf("listen kcp on %s: %w", addr, err)
	}
	_ = ln.SetReadBuffer(8 * 1024 * 1024)
	_ = ln.SetWriteBuffer(8 * 1024 * 1024)
	_ = ln.SetDSCP(46)
	return &UDPCarrierListener{
		ln:       ln,
		settings: settings,
	}, nil, nil
}

// dialPacketCarrier opens an authenticated KCP session over any net.PacketConn with ownConn=true.
func dialPacketCarrier(ctx context.Context, pconn net.PacketConn, rAddr net.Addr, password string, useFEC bool) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		_ = pconn.Close()
		return nil, err
	}
	settings := DefaultKCPSettings(useFEC)
	block, err := kcpCrypt(password)
	if err != nil {
		_ = pconn.Close()
		return nil, err
	}

	var convid uint32
	if err := binary.Read(crand.Reader, binary.LittleEndian, &convid); err != nil {
		_ = pconn.Close()
		return nil, err
	}

	// NewConn4 with ownConn=true ensures closing the KCP session closes pconn
	sess, err := kcp.NewConn4(convid, rAddr, block, settings.DataShards, settings.ParityShards, true, pconn)
	if err != nil {
		_ = pconn.Close()
		return nil, fmt.Errorf("open kcp packet session: %w", err)
	}

	ApplyKCPSettings(sess, settings)
	return IdleAwareKCP(sess, settings), nil
}

// DialUDPCarrier dials a standard UDP KCP session with Reed-Solomon FEC.
func DialUDPCarrier(ctx context.Context, addr, password string, useFEC bool) (net.Conn, error) {
	return DialUDPCarrierWithSettings(ctx, addr, password, DefaultKCPSettings(useFEC))
}

// DialUDPCarrierWithSettings dials a UDP KCP session using custom KCPSettings.
func DialUDPCarrierWithSettings(ctx context.Context, addr, password string, settings KCPSettings) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	block, err := kcpCrypt(password)
	if err != nil {
		return nil, err
	}

	sess, err := kcp.DialWithOptions(addr, block, settings.DataShards, settings.ParityShards)
	if err != nil {
		return nil, fmt.Errorf("dial kcp to %s: %w", addr, err)
	}

	ApplyKCPSettings(sess, settings)
	return IdleAwareKCP(sess, settings), nil
}

// ─── Idle-Aware KCP CPU Governor (from BackPack kcpidle.go) ───────────────
// Slows KCP tick timer from 10ms to 200ms when idle after 3s, restoring 10ms
// immediately on the first Read or Write. Reduces idle CPU consumption by 90%.

const (
	kcpIdleAfter    = 3 * time.Second
	kcpIdleInterval = 200
	kcpIdleSweep    = time.Second
)

type idleKCPConn struct {
	*kcp.UDPSession
	interval int
	last     atomic.Int64
	idle     atomic.Bool
	mu       sync.Mutex
}

func IdleAwareKCP(sess *kcp.UDPSession, s KCPSettings) net.Conn {
	c := &idleKCPConn{
		UDPSession: sess,
		interval:   s.Interval,
	}
	c.touch()
	kcpGov.add(c)
	return c
}

func (c *idleKCPConn) Read(b []byte) (int, error) {
	n, err := c.UDPSession.Read(b)
	if n > 0 {
		c.touch()
	}
	return n, err
}

func (c *idleKCPConn) Write(b []byte) (int, error) {
	c.touch()
	return c.UDPSession.Write(b)
}

func (c *idleKCPConn) Close() error {
	kcpGov.remove(c)
	return c.UDPSession.Close()
}

func (c *idleKCPConn) touch() {
	c.last.Store(time.Now().UnixNano())
	if c.idle.Load() {
		c.mu.Lock()
		if c.idle.Load() {
			c.idle.Store(false)
			c.UDPSession.SetNoDelay(-1, c.interval, -1, -1)
			c.UDPSession.SetACKNoDelay(true)
		}
		c.mu.Unlock()
	}
}

func (c *idleKCPConn) sweep(now time.Time, after time.Duration) {
	quietSince := now.Add(-after).UnixNano()
	if c.idle.Load() || c.last.Load() > quietSince {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.idle.Load() {
		return
	}
	c.idle.Store(true)
	c.UDPSession.SetACKNoDelay(true)
	c.UDPSession.SetNoDelay(-1, kcpIdleInterval, -1, -1)
}

var kcpGov = &kcpGovernor{conns: make(map[*idleKCPConn]struct{}), after: kcpIdleAfter, every: kcpIdleSweep}

type kcpGovernor struct {
	mu      sync.Mutex
	conns   map[*idleKCPConn]struct{}
	running bool
	after   time.Duration
	every   time.Duration
}

func (g *kcpGovernor) add(c *idleKCPConn) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.conns[c] = struct{}{}
	if !g.running {
		g.running = true
		go g.loop()
	}
}

func (g *kcpGovernor) remove(c *idleKCPConn) {
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.conns, c)
}

func (g *kcpGovernor) loop() {
	ticker := time.NewTicker(g.every)
	defer ticker.Stop()
	for {
		<-ticker.C
		g.mu.Lock()
		if len(g.conns) == 0 {
			g.running = false
			g.mu.Unlock()
			return
		}
		list := make([]*idleKCPConn, 0, len(g.conns))
		for c := range g.conns {
			list = append(list, c)
		}
		g.mu.Unlock()

		now := time.Now()
		for _, c := range list {
			c.sweep(now, g.after)
		}
	}
}

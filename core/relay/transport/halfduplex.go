package transport

import (
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

const (
	HalfDuplexRoleUpload   byte = 0x01
	HalfDuplexRoleDownload byte = 0x02
	HalfDuplexIntroSize         = 17
)

// HalfDuplexConn combines two unidirectional net.Conn sockets into a single unified net.Conn.
type HalfDuplexConn struct {
	readConn  net.Conn
	writeConn net.Conn
	closeOnce sync.Once
}

func NewHalfDuplexConn(readConn, writeConn net.Conn) *HalfDuplexConn {
	return &HalfDuplexConn{
		readConn:  readConn,
		writeConn: writeConn,
	}
}

func (c *HalfDuplexConn) Read(b []byte) (int, error) {
	return c.readConn.Read(b)
}

func (c *HalfDuplexConn) Write(b []byte) (int, error) {
	return c.writeConn.Write(b)
}

func (c *HalfDuplexConn) ReadFrom(r io.Reader) (int64, error) {
	if rf, ok := c.writeConn.(io.ReaderFrom); ok {
		return rf.ReadFrom(r)
	}
	return io.Copy(c.writeConn, r)
}

func (c *HalfDuplexConn) WriteTo(w io.Writer) (int64, error) {
	if wt, ok := c.readConn.(io.WriterTo); ok {
		return wt.WriteTo(w)
	}
	return io.Copy(w, c.readConn)
}

// ReadTCPConn returns the underlying read *net.TCPConn for zero-copy kernel splice(2).
func (c *HalfDuplexConn) ReadTCPConn() *net.TCPConn {
	if c.readConn == nil {
		return nil
	}
	if tc, ok := c.readConn.(*net.TCPConn); ok {
		return tc
	}
	if u, ok := c.readConn.(interface{ ReadTCPConn() *net.TCPConn }); ok {
		return u.ReadTCPConn()
	}
	return nil
}

// WriteTCPConn returns the underlying write *net.TCPConn for zero-copy kernel splice(2).
func (c *HalfDuplexConn) WriteTCPConn() *net.TCPConn {
	if c.writeConn == nil {
		return nil
	}
	if tc, ok := c.writeConn.(*net.TCPConn); ok {
		return tc
	}
	if u, ok := c.writeConn.(interface{ WriteTCPConn() *net.TCPConn }); ok {
		return u.WriteTCPConn()
	}
	return nil
}

func (c *HalfDuplexConn) CloseWrite() error {
	if tc, ok := c.writeConn.(*net.TCPConn); ok {
		return tc.CloseWrite()
	}
	type closer interface{ CloseWrite() error }
	if hc, ok := c.writeConn.(closer); ok {
		return hc.CloseWrite()
	}
	if c.writeConn != nil {
		return c.writeConn.Close()
	}
	return nil
}

func (c *HalfDuplexConn) CloseRead() error {
	if tc, ok := c.readConn.(*net.TCPConn); ok {
		return tc.CloseRead()
	}
	type closer interface{ CloseRead() error }
	if hc, ok := c.readConn.(closer); ok {
		return hc.CloseRead()
	}
	if c.readConn != nil {
		return c.readConn.Close()
	}
	return nil
}

func (c *HalfDuplexConn) Close() error {
	var err1, err2 error
	c.closeOnce.Do(func() {
		if c.readConn != nil {
			err1 = c.readConn.Close()
		}
		if c.writeConn != nil {
			err2 = c.writeConn.Close()
		}
	})
	if err1 != nil {
		return err1
	}
	return err2
}

func (c *HalfDuplexConn) LocalAddr() net.Addr {
	if c.readConn != nil {
		return c.readConn.LocalAddr()
	}
	return c.writeConn.LocalAddr()
}

func (c *HalfDuplexConn) RemoteAddr() net.Addr {
	if c.readConn != nil {
		return c.readConn.RemoteAddr()
	}
	return c.writeConn.RemoteAddr()
}

func (c *HalfDuplexConn) SetDeadline(t time.Time) error {
	err1 := c.readConn.SetDeadline(t)
	err2 := c.writeConn.SetDeadline(t)
	if err1 != nil {
		return err1
	}
	return err2
}

func (c *HalfDuplexConn) SetReadDeadline(t time.Time) error {
	return c.readConn.SetReadDeadline(t)
}

func (c *HalfDuplexConn) SetWriteDeadline(t time.Time) error {
	return c.writeConn.SetWriteDeadline(t)
}

type pendingPair struct {
	role      byte
	conn      net.Conn
	createdAt time.Time
}

// HalfDuplexMatcher pairs incoming Upload and Download sockets by 128-bit PairID.
type HalfDuplexMatcher struct {
	mu      sync.Mutex
	pending map[[16]byte]pendingPair
	closed  bool
}

func NewHalfDuplexMatcher() *HalfDuplexMatcher {
	return &HalfDuplexMatcher{
		pending: make(map[[16]byte]pendingPair),
	}
}

func (m *HalfDuplexMatcher) AcceptHalf(conn net.Conn) (*HalfDuplexConn, error) {
	var intro [HalfDuplexIntroSize]byte
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	var first5 [5]byte
	if _, err := io.ReadFull(conn, first5[:]); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("read halfduplex intro prefix: %w", err)
	}

	// Support both TLS 1.3 ApplicationData framed intro (0x17 0x03 0x03 0x00 0x11 + 17B)
	// and legacy raw 17-byte intro (0x01/0x02 + 16B PairID).
	if first5[0] == 0x17 && first5[1] == 0x03 && first5[2] == 0x03 && first5[3] == 0x00 && first5[4] == HalfDuplexIntroSize {
		if _, err := io.ReadFull(conn, intro[:]); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("read halfduplex tls-framed intro: %w", err)
		}
	} else {
		copy(intro[0:5], first5[:])
		if _, err := io.ReadFull(conn, intro[5:]); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("read halfduplex raw intro: %w", err)
		}
	}
	_ = conn.SetReadDeadline(time.Time{})

	role := intro[0]
	if role != HalfDuplexRoleUpload && role != HalfDuplexRoleDownload {
		_ = conn.Close()
		return nil, fmt.Errorf("invalid halfduplex role byte: 0x%02x", role)
	}

	var pairID [16]byte
	copy(pairID[:], intro[1:17])

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.closed {
		_ = conn.Close()
		return nil, net.ErrClosed
	}

	now := time.Now()
	for id, p := range m.pending {
		if now.Sub(p.createdAt) > 10*time.Second {
			_ = p.conn.Close()
			delete(m.pending, id)
		}
	}

	existing, exists := m.pending[pairID]
	if !exists {
		m.pending[pairID] = pendingPair{
			role:      role,
			conn:      conn,
			createdAt: now,
		}
		return nil, nil
	}

	if existing.role == role {
		_ = existing.conn.Close()
		m.pending[pairID] = pendingPair{
			role:      role,
			conn:      conn,
			createdAt: now,
		}
		return nil, nil
	}

	delete(m.pending, pairID)

	var uploadConn, downloadConn net.Conn
	if role == HalfDuplexRoleUpload {
		uploadConn = conn
		downloadConn = existing.conn
	} else {
		uploadConn = existing.conn
		downloadConn = conn
	}

	return NewHalfDuplexConn(downloadConn, uploadConn), nil
}

func (m *HalfDuplexMatcher) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	for id, p := range m.pending {
		_ = p.conn.Close()
		delete(m.pending, id)
	}
}

func DialHalfDuplexPair(dialFn CarrierDialer) (*HalfDuplexConn, error) {
	var pairID [16]byte
	if _, err := rand.Read(pairID[:]); err != nil {
		return nil, fmt.Errorf("generate pair id: %w", err)
	}

	type dialRes struct {
		conn net.Conn
		err  error
	}

	upCh := make(chan dialRes, 1)
	downCh := make(chan dialRes, 1)

	go func() {
		c, err := dialFn()
		if err != nil {
			upCh <- dialRes{err: err}
			return
		}
		var framed [5 + HalfDuplexIntroSize]byte
		framed[0] = 0x17
		framed[1] = 0x03
		framed[2] = 0x03
		framed[3] = 0x00
		framed[4] = HalfDuplexIntroSize
		framed[5] = HalfDuplexRoleUpload
		copy(framed[6:22], pairID[:])
		_ = c.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if _, err := c.Write(framed[:]); err != nil {
			_ = c.Close()
			upCh <- dialRes{err: err}
			return
		}
		_ = c.SetWriteDeadline(time.Time{})
		upCh <- dialRes{conn: c}
	}()

	go func() {
		c, err := dialFn()
		if err != nil {
			downCh <- dialRes{err: err}
			return
		}
		var framed [5 + HalfDuplexIntroSize]byte
		framed[0] = 0x17
		framed[1] = 0x03
		framed[2] = 0x03
		framed[3] = 0x00
		framed[4] = HalfDuplexIntroSize
		framed[5] = HalfDuplexRoleDownload
		copy(framed[6:22], pairID[:])
		_ = c.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if _, err := c.Write(framed[:]); err != nil {
			_ = c.Close()
			downCh <- dialRes{err: err}
			return
		}
		_ = c.SetWriteDeadline(time.Time{})
		downCh <- dialRes{conn: c}
	}()

	upRes := <-upCh
	downRes := <-downCh

	if upRes.err != nil {
		if downRes.conn != nil {
			_ = downRes.conn.Close()
		}
		return nil, upRes.err
	}
	if downRes.err != nil {
		if upRes.conn != nil {
			_ = upRes.conn.Close()
		}
		return nil, downRes.err
	}

	return NewHalfDuplexConn(upRes.conn, downRes.conn), nil
}

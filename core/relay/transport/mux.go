package transport

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const (
	tcpAuthMagic   = "ARTP"
	tcpAuthAckByte = 0xA5

	muxCmdSYN  byte = 0x01
	muxCmdDATA byte = 0x02
	muxCmdFIN  byte = 0x03
	muxCmdRST  byte = 0x04
	muxCmdPING byte = 0x05
	muxCmdPONG byte = 0x06

	muxHeaderLen    = 7 // [1B cmd][4B streamID][2B length]
	muxMaxChunkSize = 32768
)

// DialTCPCarrier dials a raw TCP carrier connection with 32-byte PoolNonce / HMAC token authentication.
// Once authenticated, the raw *net.TCPConn is returned directly for Linux kernel splice(2) zero-copy.
func DialTCPCarrier(dialCtx CarrierDialer, password string) (net.Conn, error) {
	key, err := DeriveRealityKey(password, "archnet-tcp-pool")
	if err != nil {
		return nil, err
	}
	token, err := GenerateRealityToken(key, tcpAuthMagic)
	if err != nil {
		return nil, err
	}

	conn, err := dialCtx()
	if err != nil {
		return nil, err
	}
	TuneTCPConn(conn)
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	if _, err := conn.Write(token[:]); err != nil {
		_ = conn.Close()
		return nil, err
	}
	var ack [1]byte
	if _, err := io.ReadFull(conn, ack[:]); err != nil || ack[0] != tcpAuthAckByte {
		_ = conn.Close()
		return nil, errors.New("tcp carrier authentication rejected")
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

// InspectTCPTraffic inspects the initial 32 bytes on Entry for a valid TCP PoolNonce token.
func InspectTCPTraffic(conn net.Conn, password string, hasUserForwarder bool) (InspectAction, net.Conn, error) {
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	var token [32]byte
	n, err := io.ReadFull(conn, token[:])
	if err != nil {
		if hasUserForwarder && n > 0 {
			_ = conn.SetReadDeadline(time.Time{})
			return ActionUserClient, NewPrefixConn(conn, token[:n]), nil
		}
		_ = conn.Close()
		return ActionDPIProbe, nil, err
	}

	if key, kErr := DeriveRealityKey(password, "archnet-tcp-pool"); kErr == nil {
		if VerifyRealityToken(key, token[:], tcpAuthMagic) {
			_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			if _, wErr := conn.Write([]byte{tcpAuthAckByte}); wErr != nil {
				_ = conn.Close()
				return ActionDPIProbe, nil, wErr
			}
			_ = conn.SetDeadline(time.Time{})
			return ActionReverseCarrier, conn, nil
		}
	}

	if hasUserForwarder {
		_ = conn.SetDeadline(time.Time{})
		return ActionUserClient, NewPrefixConn(conn, token[:]), nil
	}

	_ = conn.Close()
	return ActionDPIProbe, nil, errors.New("unauthenticated tcp probe dropped")
}

// MuxSession multiplexes multiple virtual net.Conn streams over a single underlying net.Conn
// (used by tcpmux, wsmux, and wssmux).
type MuxSession struct {
	conn       net.Conn
	isClient   bool
	nextID     atomic.Uint32
	lastRxNano atomic.Int64
	writeMu    sync.Mutex
	streamsMu  sync.RWMutex
	streams    map[uint32]*MuxStream
	acceptCh   chan *MuxStream
	closed     atomic.Bool
	closeOnce  sync.Once
	closeCh    chan struct{}
}

// NewMuxSession wraps an authenticated carrier connection into a multiplexed session.
func NewMuxSession(conn net.Conn, isClient bool) *MuxSession {
	s := &MuxSession{
		conn:     conn,
		isClient: isClient,
		streams:  make(map[uint32]*MuxStream),
		acceptCh: make(chan *MuxStream, 256),
		closeCh:  make(chan struct{}),
	}
	s.lastRxNano.Store(time.Now().UnixNano())
	if isClient {
		s.nextID.Store(1)
		go s.pingLoop()
	} else {
		s.nextID.Store(2)
	}
	go s.readLoop()
	return s
}

func (s *MuxSession) pingLoop() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-s.closeCh:
			return
		case <-ticker.C:
			if s.IsClosed() {
				return
			}
			if last := s.lastRxNano.Load(); last > 0 && time.Since(time.Unix(0, last)) > 20*time.Second {
				_ = s.Close()
				return
			}
			if err := s.writeFrame(muxCmdPING, 0, nil); err != nil {
				_ = s.Close()
				return
			}
		}
	}
}

// IsClosed reports whether the session has been closed.
func (s *MuxSession) IsClosed() bool {
	return s.closed.Load()
}

func (s *MuxSession) Close() error {
	s.closeOnce.Do(func() {
		s.closed.Store(true)
		close(s.closeCh)
		_ = s.conn.Close()
		s.streamsMu.Lock()
		for _, st := range s.streams {
			st.remoteClose()
		}
		s.streams = make(map[uint32]*MuxStream)
		s.streamsMu.Unlock()
	})
	return nil
}

// OpenStream opens a new multiplexed virtual stream on the session.
func (s *MuxSession) OpenStream() (net.Conn, error) {
	if s.IsClosed() {
		return nil, io.ErrClosedPipe
	}
	id := s.nextID.Add(2) - 2
	st := newMuxStream(s, id)

	s.streamsMu.Lock()
	s.streams[id] = st
	s.streamsMu.Unlock()

	if err := s.writeFrame(muxCmdSYN, id, nil); err != nil {
		s.removeStream(id)
		return nil, err
	}
	return st, nil
}

// AcceptStream waits for the peer to open a new multiplexed stream.
func (s *MuxSession) AcceptStream() (net.Conn, error) {
	select {
	case <-s.closeCh:
		return nil, io.EOF
	case st, ok := <-s.acceptCh:
		if !ok || st == nil {
			return nil, io.EOF
		}
		return st, nil
	}
}

func (s *MuxSession) writeFrame(cmd byte, id uint32, payload []byte) error {
	if s.IsClosed() {
		return io.ErrClosedPipe
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	var hdr [muxHeaderLen]byte
	hdr[0] = cmd
	binary.BigEndian.PutUint32(hdr[1:5], id)
	binary.BigEndian.PutUint16(hdr[5:7], uint16(len(payload)))

	_ = s.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if len(payload) == 0 {
		_, err := s.conn.Write(hdr[:])
		_ = s.conn.SetWriteDeadline(time.Time{})
		return err
	}

	buf := make([]byte, muxHeaderLen+len(payload))
	copy(buf[:muxHeaderLen], hdr[:])
	copy(buf[muxHeaderLen:], payload)
	_, err := s.conn.Write(buf)
	_ = s.conn.SetWriteDeadline(time.Time{})
	return err
}

func (s *MuxSession) removeStream(id uint32) {
	s.streamsMu.Lock()
	delete(s.streams, id)
	s.streamsMu.Unlock()
}

func (s *MuxSession) readLoop() {
	defer s.Close()
	var hdr [muxHeaderLen]byte
	for {
		if _, err := io.ReadFull(s.conn, hdr[:]); err != nil {
			return
		}
		s.lastRxNano.Store(time.Now().UnixNano())
		cmd := hdr[0]
		id := binary.BigEndian.Uint32(hdr[1:5])
		length := int(binary.BigEndian.Uint16(hdr[5:7]))

		var data []byte
		if length > 0 {
			data = make([]byte, length)
			if _, err := io.ReadFull(s.conn, data); err != nil {
				return
			}
		}

		switch cmd {
		case muxCmdSYN:
			st := newMuxStream(s, id)
			s.streamsMu.Lock()
			s.streams[id] = st
			s.streamsMu.Unlock()
			select {
			case s.acceptCh <- st:
			default:
				_ = st.Close()
			}

		case muxCmdDATA:
			s.streamsMu.RLock()
			st := s.streams[id]
			s.streamsMu.RUnlock()
			if st != nil {
				st.pushData(data)
			} else {
				_ = s.writeFrame(muxCmdRST, id, nil)
			}

		case muxCmdFIN:
			s.streamsMu.RLock()
			st := s.streams[id]
			s.streamsMu.RUnlock()
			if st != nil {
				st.remoteFIN()
			}

		case muxCmdRST:
			s.streamsMu.RLock()
			st := s.streams[id]
			s.streamsMu.RUnlock()
			if st != nil {
				st.remoteClose()
				s.removeStream(id)
			}

		case muxCmdPING:
			_ = s.writeFrame(muxCmdPONG, id, nil)
		}
	}
}

// MuxStream is a single virtual stream inside a MuxSession implementing net.Conn.
type MuxStream struct {
	sess         *MuxSession
	id           uint32
	readMu       sync.Mutex
	cond         *sync.Cond
	chunks       [][]byte
	readClosed   bool
	writeClosed  atomic.Bool
	fullClosed   atomic.Bool
	readDeadline time.Time
}

func newMuxStream(sess *MuxSession, id uint32) *MuxStream {
	st := &MuxStream{
		sess: sess,
		id:   id,
	}
	st.cond = sync.NewCond(&st.readMu)
	return st
}

func (m *MuxStream) pushData(data []byte) {
	if len(data) == 0 {
		return
	}
	m.readMu.Lock()
	if !m.readClosed {
		m.chunks = append(m.chunks, data)
		m.cond.Signal()
	}
	m.readMu.Unlock()
}

func (m *MuxStream) remoteFIN() {
	m.readMu.Lock()
	m.readClosed = true
	m.cond.Broadcast()
	m.readMu.Unlock()
}

func (m *MuxStream) remoteClose() {
	m.writeClosed.Store(true)
	m.remoteFIN()
}

func (m *MuxStream) Read(p []byte) (int, error) {
	m.readMu.Lock()
	defer m.readMu.Unlock()

	for len(m.chunks) == 0 && !m.readClosed && !m.sess.IsClosed() {
		if !m.readDeadline.IsZero() {
			wait := time.Until(m.readDeadline)
			if wait <= 0 {
				return 0, fmt.Errorf("mux stream read timeout")
			}
			timer := time.AfterFunc(wait, func() {
				m.cond.Broadcast()
			})
			m.cond.Wait()
			timer.Stop()
			if len(m.chunks) == 0 && time.Now().After(m.readDeadline) {
				return 0, fmt.Errorf("mux stream read timeout")
			}
		} else {
			m.cond.Wait()
		}
	}

	if len(m.chunks) > 0 {
		front := m.chunks[0]
		n := copy(p, front)
		if n < len(front) {
			m.chunks[0] = front[n:]
		} else {
			m.chunks[0] = nil
			m.chunks = m.chunks[1:]
		}
		return n, nil
	}
	return 0, io.EOF
}

func (m *MuxStream) Write(p []byte) (int, error) {
	if m.writeClosed.Load() || m.sess.IsClosed() {
		return 0, io.ErrClosedPipe
	}
	total := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > muxMaxChunkSize {
			chunk = p[:muxMaxChunkSize]
		}
		p = p[len(chunk):]
		if err := m.sess.writeFrame(muxCmdDATA, m.id, chunk); err != nil {
			return total, err
		}
		total += len(chunk)
	}
	return total, nil
}

func (m *MuxStream) CloseWrite() error {
	if m.writeClosed.CompareAndSwap(false, true) {
		return m.sess.writeFrame(muxCmdFIN, m.id, nil)
	}
	return nil
}

func (m *MuxStream) CloseRead() error {
	m.remoteFIN()
	return nil
}

// IsAlive reports whether the virtual stream and its parent carrier session are healthy.
func (m *MuxStream) IsAlive() bool {
	return !m.fullClosed.Load() && !m.sess.IsClosed()
}

func (m *MuxStream) Close() error {
	if m.fullClosed.CompareAndSwap(false, true) {
		_ = m.CloseWrite()
		m.remoteFIN()
		m.sess.removeStream(m.id)
	}
	return nil
}

func (m *MuxStream) LocalAddr() net.Addr  { return m.sess.conn.LocalAddr() }
func (m *MuxStream) RemoteAddr() net.Addr { return m.sess.conn.RemoteAddr() }

func (m *MuxStream) SetDeadline(t time.Time) error {
	return m.SetReadDeadline(t)
}

func (m *MuxStream) SetReadDeadline(t time.Time) error {
	m.readMu.Lock()
	m.readDeadline = t
	m.cond.Broadcast()
	m.readMu.Unlock()
	return nil
}

func (m *MuxStream) SetWriteDeadline(t time.Time) error {
	return nil
}

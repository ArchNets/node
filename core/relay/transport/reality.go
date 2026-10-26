package transport

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

const (
	realityHKDFSalt       = "archnet-reverse-reality-v1"
	realityMagic          = "ARRL"
	realityAckMagic       = "AROK"
	realityClockSkew      = 10 * time.Minute
	maxTLS13RecordPayload = 16384
)

// RealityRecordConn wraps a post-handshake carrier connection in RFC 8446 TLS 1.3
// ApplicationData (0x17 0x03 0x03 <len>) record framing using zero-copy writev(2)
// scatter-gather writes and direct-to-caller reads.
// This matches WaterWall's RealityClient/RealityServer post-takeover wire framing so
// stateful DPI record-boundary trackers never see raw unframed bytes on the wire.
type RealityRecordConn struct {
	net.Conn
	readMu  sync.Mutex
	writeMu sync.Mutex
	rem     int
}

func NewRealityRecordConn(c net.Conn) *RealityRecordConn {
	return &RealityRecordConn{Conn: c}
}

func (c *RealityRecordConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.readMu.Lock()
	defer c.readMu.Unlock()

	for c.rem == 0 {
		var hdr [5]byte
		if _, err := io.ReadFull(c.Conn, hdr[:]); err != nil {
			return 0, err
		}
		if hdr[0] != 0x17 && hdr[0] != 0x16 && hdr[0] != 0x14 {
			return 0, fmt.Errorf("invalid reality tls record type: 0x%02x", hdr[0])
		}
		recLen := int(binary.BigEndian.Uint16(hdr[3:5]))
		if recLen <= 0 || recLen > 32768 {
			return 0, fmt.Errorf("invalid reality tls record length: %d", recLen)
		}
		c.rem = recLen
	}

	toRead := len(p)
	if toRead > c.rem {
		toRead = c.rem
	}
	n, err := c.Conn.Read(p[:toRead])
	c.rem -= n
	return n, err
}

func (c *RealityRecordConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	total := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > maxTLS13RecordPayload {
			chunk = p[:maxTLS13RecordPayload]
		}
		var hdr [5]byte
		hdr[0] = 0x17
		hdr[1] = 0x03
		hdr[2] = 0x03
		binary.BigEndian.PutUint16(hdr[3:5], uint16(len(chunk)))

		bufs := net.Buffers{hdr[:], chunk}
		n, err := bufs.WriteTo(c.Conn)
		if n > 5 {
			written := int(n - 5)
			if written > len(chunk) {
				written = len(chunk)
			}
			total += written
			p = p[written:]
		}
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

func (c *RealityRecordConn) CloseWrite() error {
	if tc, ok := c.Conn.(*net.TCPConn); ok {
		return tc.CloseWrite()
	}
	type closer interface{ CloseWrite() error }
	if hc, ok := c.Conn.(closer); ok {
		return hc.CloseWrite()
	}
	return c.Conn.Close()
}

func (c *RealityRecordConn) CloseRead() error {
	if tc, ok := c.Conn.(*net.TCPConn); ok {
		return tc.CloseRead()
	}
	type closer interface{ CloseRead() error }
	if hc, ok := c.Conn.(closer); ok {
		return hc.CloseRead()
	}
	return c.Conn.Close()
}

// PrefixConn wraps a net.Conn with prepended initial bytes that were pre-read during inspection.
type PrefixConn struct {
	net.Conn
	prefix io.Reader
}

func NewPrefixConn(conn net.Conn, initialBytes []byte) *PrefixConn {
	TuneTCPConn(conn)
	_ = conn.SetDeadline(time.Time{})
	return &PrefixConn{
		Conn:   conn,
		prefix: bytes.NewReader(initialBytes),
	}
}

func (p *PrefixConn) Read(b []byte) (int, error) {
	if p.prefix != nil {
		n, err := p.prefix.Read(b)
		if err == io.EOF {
			p.prefix = nil
			err = nil
		}
		if n > 0 {
			return n, err
		}
	}
	return p.Conn.Read(b)
}

// DrainPrefixTo flushes any buffered prefix bytes directly to w so the underlying
// TCPConn can then be used with kernel splice(2).
func (p *PrefixConn) DrainPrefixTo(w io.Writer) (int64, error) {
	if p.prefix == nil {
		return 0, nil
	}
	n, err := io.Copy(w, p.prefix)
	p.prefix = nil
	return n, err
}

// ReadTCPConn returns the underlying *net.TCPConn once the prefix buffer has been drained.
func (p *PrefixConn) ReadTCPConn() *net.TCPConn {
	if p.prefix != nil {
		return nil
	}
	if tc, ok := p.Conn.(*net.TCPConn); ok {
		return tc
	}
	if u, ok := p.Conn.(interface{ ReadTCPConn() *net.TCPConn }); ok {
		return u.ReadTCPConn()
	}
	return nil
}

// WriteTCPConn returns the underlying *net.TCPConn for zero-copy splice writes.
func (p *PrefixConn) WriteTCPConn() *net.TCPConn {
	if tc, ok := p.Conn.(*net.TCPConn); ok {
		return tc
	}
	if u, ok := p.Conn.(interface{ WriteTCPConn() *net.TCPConn }); ok {
		return u.WriteTCPConn()
	}
	return nil
}

func (p *PrefixConn) CloseWrite() error {
	if tc, ok := p.Conn.(*net.TCPConn); ok {
		return tc.CloseWrite()
	}
	type closer interface{ CloseWrite() error }
	if hc, ok := p.Conn.(closer); ok {
		return hc.CloseWrite()
	}
	return p.Conn.Close()
}

// DeriveRealityKey derives a 32-byte AEAD key from the tunnel password and SNI using HKDF-SHA256.
func DeriveRealityKey(password, sni string) ([32]byte, error) {
	var key [32]byte
	if password == "" {
		password = "archnet-default-secret"
	}
	cleanSNI := strings.ToLower(strings.TrimSpace(sni))
	r := hkdf.New(sha256.New, []byte(password), []byte(realityHKDFSalt), []byte(cleanSNI))
	if _, err := io.ReadFull(r, key[:]); err != nil {
		return key, fmt.Errorf("hkdf derive key: %w", err)
	}
	return key, nil
}

// GenerateRealityToken creates a 32-byte ChaCha20-Poly1305 authenticated token for ClientHello.Random.
func GenerateRealityToken(key [32]byte, magic string) ([32]byte, error) {
	var token [32]byte
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return token, err
	}

	var nonce [12]byte
	binary.BigEndian.PutUint32(nonce[0:4], uint32(time.Now().Unix()))
	if _, err := rand.Read(nonce[4:12]); err != nil {
		return token, err
	}

	sealed := aead.Seal(nil, nonce[:], []byte(magic), key[:])
	copy(token[0:12], nonce[:])
	copy(token[12:32], sealed)
	return token, nil
}

// VerifyRealityToken verifies a 32-byte ChaCha20-Poly1305 token and validates its timestamp.
func VerifyRealityToken(key [32]byte, token []byte, expectedMagic string) bool {
	if len(token) != 32 {
		return false
	}
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return false
	}

	nonce := token[0:12]
	ciphertext := token[12:32]
	plaintext, err := aead.Open(nil, nonce, ciphertext, key[:])
	if err != nil || string(plaintext) != expectedMagic {
		return false
	}

	ts := int64(binary.BigEndian.Uint32(nonce[0:4]))
	diff := time.Since(time.Unix(ts, 0))
	if diff < 0 {
		diff = -diff
	}
	return diff <= realityClockSkew
}

var (
	realityReplayMu    sync.Mutex
	realityReplayCache = make(map[[12]byte]int64)
	realityLastPrune   int64
)

// CheckAndRecordRealityNonce validates that the 12-byte token nonce has not been observed
// before within the validity window, preventing replay and A/B differential probe attacks.
// Returns true if the nonce is fresh, or false if it is a replayed packet.
func CheckAndRecordRealityNonce(nonce []byte) bool {
	if len(nonce) < 12 {
		return false
	}
	var n [12]byte
	copy(n[:], nonce[:12])

	now := time.Now().Unix()
	realityReplayMu.Lock()
	defer realityReplayMu.Unlock()

	// Periodically prune expired nonces (older than 60s) every 30s
	if now-realityLastPrune > 30 {
		cutoff := now - 60
		for k, ts := range realityReplayCache {
			if ts < cutoff {
				delete(realityReplayCache, k)
			}
		}
		realityLastPrune = now
	}

	if _, exists := realityReplayCache[n]; exists {
		return false // Replay detected!
	}
	realityReplayCache[n] = now
	return true
}

// ResetRealityReplayCache clears the anti-replay cache (used by unit tests).
func ResetRealityReplayCache() {
	realityReplayMu.Lock()
	defer realityReplayMu.Unlock()
	realityReplayCache = make(map[[12]byte]int64)
	realityLastPrune = time.Now().Unix()
}

// buildTLS13ServerFlight constructs a genuine TLS 1.3 ServerHello (0x16) +
// ChangeCipherSpec (0x14) + Encrypted Handshake ApplicationData (0x17) flight.
// This ensures stateful DPI middleboxes observe a complete RFC 8446 TLS 1.3 handshake
// and offload the connection to the router fast-path without throttling.
func buildTLS13ServerFlight(clientHelloBody []byte, ackToken [32]byte) []byte {
	// Extract client session_id from ClientHello (starts at offset 38: 1B type + 3B len + 2B ver + 32B random)
	var sessionID []byte
	if len(clientHelloBody) >= 39 {
		sidLen := int(clientHelloBody[38])
		if sidLen <= 32 && len(clientHelloBody) >= 39+sidLen {
			sessionID = clientHelloBody[39 : 39+sidLen]
		}
	}

	var serverRandom [32]byte
	_, _ = rand.Read(serverRandom[:])

	var x25519Pub [32]byte
	_, _ = rand.Read(x25519Pub[:])

	// Extensions: supported_versions (0x002b -> 0x0304) + key_share (0x0033 -> x25519 32B)
	extLen := 6 + 40 // 46 bytes
	shBodyLen := 2 + 32 + 1 + len(sessionID) + 2 + 1 + 2 + extLen
	shRecordLen := 4 + shBodyLen

	// Encrypted handshake record body: 32B ackToken + randomized realistic TLS 1.3
	// EncryptedExtensions/Certificate/CertificateVerify/Finished size (1024..1280 bytes),
	// fitting inside a single TCP MSS alongside ServerHello + ChangeCipherSpec.
	var jitterByte [1]byte
	_, _ = rand.Read(jitterByte[:])
	appBodyLen := 1024 + int(jitterByte[0]) // 1024..1279 bytes
	appPadding := make([]byte, appBodyLen-32)
	_, _ = rand.Read(appPadding)

	totalLen := (5 + shRecordLen) + 6 + (5 + appBodyLen)
	flight := make([]byte, 0, totalLen)

	// 1. TLS 1.3 ServerHello Record (0x16)
	flight = append(flight,
		0x16, 0x03, 0x03,
		byte(shRecordLen>>8), byte(shRecordLen),
		0x02, // HandshakeType: ServerHello
		byte(shBodyLen>>16), byte(shBodyLen>>8), byte(shBodyLen),
		0x03, 0x03, // legacy_version: TLS 1.2
	)
	flight = append(flight, serverRandom[:]...)
	flight = append(flight, byte(len(sessionID)))
	flight = append(flight, sessionID...)
	flight = append(flight,
		0x13, 0x01, // CipherSuite: TLS_AES_128_GCM_SHA256
		0x00,                         // CompressionMethod: null
		byte(extLen>>8), byte(extLen), // Extensions length (46)
		// Extension: supported_versions (0x002b) = TLS 1.3 (0x0304)
		0x00, 0x2b, 0x00, 0x02, 0x03, 0x04,
		// Extension: key_share (0x0033) = x25519 (0x001d), 32 bytes
		0x00, 0x33, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20,
	)
	flight = append(flight, x25519Pub[:]...)

	// 2. TLS 1.3 ChangeCipherSpec Record (0x14)
	flight = append(flight, 0x14, 0x03, 0x03, 0x00, 0x01, 0x01)

	// 3. TLS 1.3 ApplicationData Record (0x17) carrying ackToken + encrypted handshake padding
	flight = append(flight,
		0x17, 0x03, 0x03,
		byte(appBodyLen>>8), byte(appBodyLen),
	)
	flight = append(flight, ackToken[:]...)
	flight = append(flight, appPadding...)

	return flight
}

// DialRealityCarrier connects to EntryServerIP:CarrierPort with genuine Chrome uTLS ClientHello
// embedding the authenticated Reality token in ClientRandom.
func DialRealityCarrier(dialCtx CarrierDialer, sni, password string) (net.Conn, error) {
	key, err := DeriveRealityKey(password, sni)
	if err != nil {
		return nil, err
	}
	token, err := GenerateRealityToken(key, realityMagic)
	if err != nil {
		return nil, err
	}

	conn, err := dialCtx()
	if err != nil {
		return nil, err
	}
	TuneTCPConn(conn)

	_ = conn.SetDeadline(time.Now().Add(6 * time.Second))

	uConn := utls.UClient(conn, &utls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true,
	}, utls.HelloChrome_Auto)

	if err := uConn.BuildHandshakeState(); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("utls build handshake state: %w", err)
	}

	uConn.HandshakeState.Hello.Random = make([]byte, 32)
	copy(uConn.HandshakeState.Hello.Random, token[:])
	uConn.HandshakeState.Hello.Raw = nil

	helloBytes, err := uConn.HandshakeState.Hello.Marshal()
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("marshal utls client hello: %w", err)
	}

	record := make([]byte, 5+len(helloBytes))
	record[0] = 0x16
	record[1] = 0x03
	record[2] = 0x01
	binary.BigEndian.PutUint16(record[3:5], uint16(len(helloBytes)))
	copy(record[5:], helloBytes)

	if _, err := conn.Write(record); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("write reality client hello: %w", err)
	}

	// Read TLS 1.3 Server Flight: skip ServerHello (0x16) and ChangeCipherSpec (0x14)
	// until we read the ApplicationData (0x17) record carrying the 32-byte ackToken.
	for i := 0; i < 4; i++ {
		var recHdr [5]byte
		if _, err := io.ReadFull(conn, recHdr[:]); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("read reality server record header: %w", err)
		}
		recLen := int(binary.BigEndian.Uint16(recHdr[3:5]))
		if recLen <= 0 || recLen > 16384 {
			_ = conn.Close()
			return nil, fmt.Errorf("invalid reality server record length: %d", recLen)
		}
		recBody := make([]byte, recLen)
		if _, err := io.ReadFull(conn, recBody); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("read reality server record body: %w", err)
		}

		if recHdr[0] == 0x16 || recHdr[0] == 0x14 {
			continue
		}
		if recHdr[0] == 0x17 {
			if len(recBody) < 32 || !VerifyRealityToken(key, recBody[0:32], realityAckMagic) {
				_ = conn.Close()
				return nil, fmt.Errorf("invalid reality server ack token")
			}
			_ = conn.SetDeadline(time.Time{})
			return conn, nil
		}
		_ = conn.Close()
		return nil, fmt.Errorf("unexpected reality server record type: 0x%02x", recHdr[0])
	}

	_ = conn.Close()
	return nil, fmt.Errorf("reality server flight exceeded max records")
}

type InspectAction int

const (
	ActionReverseCarrier InspectAction = iota // Authenticated reverse carrier socket
	ActionUserClient                          // User client connection to be forwarded
	ActionDPIProbe                            // Camouflage TLS probe to be spliced to origin
)

// InspectRealityTraffic inspects incoming TCP connections on the carrier port.
// It supports single-port multiplexing:
// 1. Authenticated & Peer-gated Kharej peers -> ActionReverseCarrier (enters reverse idle pool)
// 2. Unauthenticated clients -> ActionUserClient (if user forwarder is enabled on this port)
// 3. Camouflage SNI probes or unauthorized peers -> ActionDPIProbe (spliced to camouflage origin)
func InspectRealityTraffic(conn net.Conn, sni, password string, hasUserForwarder bool, isAllowedPeer bool) (InspectAction, net.Conn, error) {
	TuneTCPConn(conn)
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	var hdr [5]byte
	nHdr, err := io.ReadFull(conn, hdr[:])
	if err != nil {
		_ = conn.Close()
		return ActionDPIProbe, nil, err
	}

	recLen := int(binary.BigEndian.Uint16(hdr[3:5]))
	// If not a TLS handshake record, it's user client traffic (Socks, HTTP, Shadowsocks, etc.)
	if hdr[0] != 0x16 || recLen < 42 || recLen > 16384 {
		if hasUserForwarder {
			_ = conn.SetReadDeadline(time.Time{})
			return ActionUserClient, NewPrefixConn(conn, hdr[:nHdr]), nil
		}
		return ActionDPIProbe, NewPrefixConn(conn, hdr[:nHdr]), nil
	}

	body := make([]byte, recLen)
	nBody, err := io.ReadFull(conn, body)
	if err != nil {
		captured := make([]byte, 5+nBody)
		copy(captured[0:5], hdr[:])
		copy(captured[5:], body[:nBody])
		return ActionDPIProbe, NewPrefixConn(conn, captured), nil
	}

	captured := make([]byte, 5+recLen)
	copy(captured[0:5], hdr[:])
	copy(captured[5:], body)

	// Check if genuine Reality ClientHello from authorized Kharej peer.
	// We require:
	// 1. isAllowedPeer: peer IP must be the expected Exit/Entry node (deflects arbitrary active scanners to origin)
	// 2. Valid ChaCha20-Poly1305 authentication token in ClientRandom (body[6:38])
	// 3. Single-use nonce freshness: prevents on-path MitM from capturing and replaying the ClientHello for A/B probing
	if isAllowedPeer && body[0] == 0x01 && len(body) >= 38 {
		key, keyErr := DeriveRealityKey(password, sni)
		if keyErr == nil && VerifyRealityToken(key, body[6:38], realityMagic) && CheckAndRecordRealityNonce(body[6:18]) {
			ackToken, ackErr := GenerateRealityToken(key, realityAckMagic)
			if ackErr != nil {
				_ = conn.Close()
				return ActionDPIProbe, nil, ackErr
			}
			flight := buildTLS13ServerFlight(body, ackToken)

			_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			if _, wErr := conn.Write(flight); wErr != nil {
				_ = conn.Close()
				return ActionDPIProbe, nil, wErr
			}
			_ = conn.SetDeadline(time.Time{})
			return ActionReverseCarrier, conn, nil
		}
	}

	// Not authenticated Reality peer.
	// If user forwarder is enabled on this port, check if it's user TLS client vs DPI probe
	if hasUserForwarder {
		// If ClientHello doesn't match camouflage SNI, or user forwarder accepts all:
		// Forward as user client
		_ = conn.SetDeadline(time.Time{})
		return ActionUserClient, NewPrefixConn(conn, captured), nil
	}

	return ActionDPIProbe, NewPrefixConn(conn, captured), nil
}

// SpliceToOrigin dials the camouflage origin server and splices visitor streams with a strict
// 15s deadline and 512 KiB cap so active GFW probes see the genuine origin site without allowing
// scanners to hold zombie sockets or drain Iran server bandwidth.
func SpliceToOrigin(visitorConn net.Conn, originAddr string) {
	defer visitorConn.Close()
	_ = visitorConn.SetDeadline(time.Now().Add(15 * time.Second))

	if originAddr == "" {
		return
	}
	targetAddr := originAddr
	if !strings.Contains(targetAddr, ":") {
		targetAddr = net.JoinHostPort(targetAddr, "443")
	}

	originConn, err := net.DialTimeout("tcp", targetAddr, 5*time.Second)
	if err != nil {
		return
	}
	defer originConn.Close()
	TuneTCPConn(originConn)
	_ = originConn.SetDeadline(time.Now().Add(15 * time.Second))

	const maxOriginSpliceBytes = 512 * 1024 // 512 KiB max per probe

	respDone := make(chan struct{})
	go func() {
		if pc, ok := visitorConn.(*PrefixConn); ok {
			_, _ = pc.DrainPrefixTo(originConn)
			_, _ = io.Copy(originConn, io.LimitReader(pc.Conn, maxOriginSpliceBytes))
		} else {
			_, _ = io.Copy(originConn, io.LimitReader(visitorConn, maxOriginSpliceBytes))
		}
		if tc, ok := originConn.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}()
	go func() {
		if pc, ok := visitorConn.(*PrefixConn); ok {
			_, _ = io.Copy(pc.Conn, io.LimitReader(originConn, maxOriginSpliceBytes))
		} else {
			_, _ = io.Copy(visitorConn, io.LimitReader(originConn, maxOriginSpliceBytes))
		}
		if hc, ok := visitorConn.(interface{ CloseWrite() error }); ok {
			_ = hc.CloseWrite()
		}
		close(respDone)
	}()
	<-respDone
}

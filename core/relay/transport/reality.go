package transport

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

const (
	realityHKDFSalt  = "archnet-reverse-reality-v1"
	realityMagic     = "ARRL"
	realityAckMagic  = "AROK"
	realityClockSkew = 10 * time.Minute
)

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

	var ackBuf [37]byte
	if _, err := io.ReadFull(conn, ackBuf[:]); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("read reality server ack: %w", err)
	}
	if ackBuf[0] != 0x17 || ackBuf[1] != 0x03 || ackBuf[2] != 0x03 {
		_ = conn.Close()
		return nil, fmt.Errorf("unexpected reality ack record header")
	}
	if !VerifyRealityToken(key, ackBuf[5:37], realityAckMagic) {
		_ = conn.Close()
		return nil, fmt.Errorf("invalid reality server ack token")
	}

	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

// InspectRealityOrSplice inspects incoming TCP connections on Entry.
// Authenticated peers are admitted; active probes or unauthenticated visitors are transparently
// spliced to the camouflage origin server at originAddr:443.
func InspectRealityOrSplice(conn net.Conn, sni, password, originAddr, allowedExitIP string) (bool, error) {
	TuneTCPConn(conn)
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	var hdr [5]byte
	nHdr, err := io.ReadFull(conn, hdr[:])
	if err != nil {
		if nHdr > 0 {
			go SpliceToOrigin(conn, hdr[:nHdr], originAddr)
			return false, nil
		}
		_ = conn.Close()
		return false, err
	}

	recLen := int(binary.BigEndian.Uint16(hdr[3:5]))
	if hdr[0] != 0x16 || recLen < 42 || recLen > 16384 {
		go SpliceToOrigin(conn, hdr[:], originAddr)
		return false, nil
	}

	body := make([]byte, recLen)
	nBody, err := io.ReadFull(conn, body)
	if err != nil {
		captured := make([]byte, 5+nBody)
		copy(captured[0:5], hdr[:])
		copy(captured[5:], body[:nBody])
		go SpliceToOrigin(conn, captured, originAddr)
		return false, nil
	}

	if allowedExitIP != "" {
		if host, _, splitErr := net.SplitHostPort(conn.RemoteAddr().String()); splitErr == nil {
			if host != allowedExitIP && host != "127.0.0.1" && host != "::1" {
				captured := make([]byte, 5+recLen)
				copy(captured[0:5], hdr[:])
				copy(captured[5:], body)
				go SpliceToOrigin(conn, captured, originAddr)
				return false, nil
			}
		}
	}

	if body[0] == 0x01 && len(body) >= 38 {
		key, keyErr := DeriveRealityKey(password, sni)
		if keyErr == nil && VerifyRealityToken(key, body[6:38], realityMagic) {
			ackToken, ackErr := GenerateRealityToken(key, realityAckMagic)
			if ackErr != nil {
				_ = conn.Close()
				return false, ackErr
			}
			var ackRecord [37]byte
			ackRecord[0] = 0x17
			ackRecord[1] = 0x03
			ackRecord[2] = 0x03
			binary.BigEndian.PutUint16(ackRecord[3:5], 32)
			copy(ackRecord[5:37], ackToken[:])

			_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			if _, wErr := conn.Write(ackRecord[:]); wErr != nil {
				_ = conn.Close()
				return false, wErr
			}
			_ = conn.SetDeadline(time.Time{})
			return true, nil
		}
	}

	captured := make([]byte, 5+recLen)
	copy(captured[0:5], hdr[:])
	copy(captured[5:], body)
	go SpliceToOrigin(conn, captured, originAddr)
	return false, nil
}

// SpliceToOrigin dials the camouflage origin server and splices visitor streams with Linux splice(2).
func SpliceToOrigin(visitorConn net.Conn, initialBytes []byte, originAddr string) {
	defer visitorConn.Close()
	_ = visitorConn.SetDeadline(time.Time{})

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

	if len(initialBytes) > 0 {
		_ = originConn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if _, err := originConn.Write(initialBytes); err != nil {
			return
		}
		_ = originConn.SetWriteDeadline(time.Time{})
	}

	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(originConn, visitorConn)
		if tc, ok := originConn.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(visitorConn, originConn)
		if tc, ok := visitorConn.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
		done <- struct{}{}
	}()
	<-done
	<-done
}

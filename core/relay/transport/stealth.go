package transport

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	mathrand "math/rand/v2"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

const (
	stealthPrologue     = "archnet-stealth-nnpsk0-v1"
	stealthMaxFrameData = 32768
	stealthMaxPad       = 127
)

func deriveStealthPSK(password string) ([]byte, error) {
	if password == "" {
		password = "archnet-default-secret"
	}
	psk := make([]byte, chacha20poly1305.KeySize)
	r := hkdf.New(sha256.New, []byte(password), []byte("archnet-stealth-psk-salt"), []byte(stealthPrologue))
	if _, err := io.ReadFull(r, psk); err != nil {
		return nil, err
	}
	return psk, nil
}

func deriveStealthSessionKeys(psk, sharedSecret, pubC, pubS []byte) (c2sKey, s2cKey []byte, err error) {
	transcript := make([]byte, 0, len(pubC)+len(pubS)+len(stealthPrologue))
	transcript = append(transcript, []byte(stealthPrologue)...)
	transcript = append(transcript, pubC...)
	transcript = append(transcript, pubS...)

	ikm := make([]byte, 0, len(psk)+len(sharedSecret))
	ikm = append(ikm, psk...)
	ikm = append(ikm, sharedSecret...)

	r := hkdf.New(sha256.New, ikm, transcript, []byte("archnet-stealth-session-v1"))
	keys := make([]byte, 64)
	if _, err := io.ReadFull(r, keys); err != nil {
		return nil, nil, err
	}
	return keys[:32], keys[32:64], nil
}

// DialStealthCarrier performs the initiator side of the Noise NNpsk0-style X25519 + ChaCha20-Poly1305
// handshake with randomized frame padding. On the wire, every byte is indistinguishable from random.
func DialStealthCarrier(dialCtx CarrierDialer, password string) (net.Conn, error) {
	psk, err := deriveStealthPSK(password)
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.New(psk)
	if err != nil {
		return nil, err
	}

	curve := ecdh.X25519()
	privC, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	pubC := privC.PublicKey().Bytes()

	conn, err := dialCtx()
	if err != nil {
		return nil, err
	}
	TuneTCPConn(conn)
	_ = conn.SetDeadline(time.Now().Add(6 * time.Second))

	// Build initiator flight: [12B nonce][2B maskedBodyLen][AEAD(32B pubC + 1B padLen + pad)]
	padLen := mathrand.IntN(stealthMaxPad + 1)
	plainC := make([]byte, 32+1+padLen)
	copy(plainC[:32], pubC)
	plainC[32] = byte(padLen)
	_, _ = rand.Read(plainC[33:])

	var nonceC [12]byte
	if _, err := io.ReadFull(rand.Reader, nonceC[:]); err != nil {
		_ = conn.Close()
		return nil, err
	}
	sealedC := aead.Seal(nil, nonceC[:], plainC, []byte(stealthPrologue))
	flightC := make([]byte, 14+len(sealedC))
	copy(flightC[:12], nonceC[:])
	maskC := binary.BigEndian.Uint16(nonceC[:2]) ^ binary.BigEndian.Uint16(psk[:2])
	binary.BigEndian.PutUint16(flightC[12:14], uint16(len(sealedC))^maskC)
	copy(flightC[14:], sealedC)

	if _, err := conn.Write(flightC); err != nil {
		_ = conn.Close()
		return nil, err
	}

	// Read responder flight: [12B nonceS][2B maskedSealedLenS][AEAD(32B pubS + 1B padLen + pad)]
	var hdrS [14]byte
	if _, err := io.ReadFull(conn, hdrS[:]); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("stealth read server header: %w", err)
	}
	maskS := binary.BigEndian.Uint16(hdrS[:2]) ^ binary.BigEndian.Uint16(psk[2:4])
	sealedLenS := int(binary.BigEndian.Uint16(hdrS[12:14]) ^ maskS)
	if sealedLenS < 32+1+16 || sealedLenS > 512 {
		_ = conn.Close()
		return nil, errors.New("stealth invalid server handshake length")
	}
	sealedS := make([]byte, sealedLenS)
	if _, err := io.ReadFull(conn, sealedS); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("stealth read server body: %w", err)
	}

	plainS, err := aead.Open(nil, hdrS[:12], sealedS, pubC)
	if err != nil || len(plainS) < 33 {
		_ = conn.Close()
		return nil, errors.New("stealth server authentication failed")
	}

	peerPubS, err := curve.NewPublicKey(plainS[:32])
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	shared, err := privC.ECDH(peerPubS)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}

	c2sKey, s2cKey, err := deriveStealthSessionKeys(psk, shared, pubC, plainS[:32])
	if err != nil {
		_ = conn.Close()
		return nil, err
	}

	_ = conn.SetDeadline(time.Time{})
	return newStealthConn(conn, c2sKey, s2cKey)
}

// InspectStealthTraffic inspects the initial bytes on Entry for a valid Stealth NNpsk0 handshake.
// If authentication fails and hasUserForwarder is true, it preserves the bytes in PrefixConn for user forwarding;
// otherwise it drops the unauthenticated probe silently so scanners see a dead port.
func InspectStealthTraffic(conn net.Conn, password string, hasUserForwarder bool) (InspectAction, net.Conn, error) {
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	var hdrC [14]byte
	nHdr, err := io.ReadFull(conn, hdrC[:])
	if err != nil {
		_ = conn.Close()
		return ActionDPIProbe, nil, err
	}

	psk, err := deriveStealthPSK(password)
	if err != nil {
		_ = conn.Close()
		return ActionDPIProbe, nil, err
	}
	maskC := binary.BigEndian.Uint16(hdrC[:2]) ^ binary.BigEndian.Uint16(psk[:2])
	sealedLenC := int(binary.BigEndian.Uint16(hdrC[12:14]) ^ maskC)
	if sealedLenC < 32+1+16 || sealedLenC > 512 {
		if hasUserForwarder {
			_ = conn.SetReadDeadline(time.Time{})
			return ActionUserClient, NewPrefixConn(conn, hdrC[:nHdr]), nil
		}
		_ = conn.Close()
		return ActionDPIProbe, nil, errors.New("non-stealth frame length")
	}

	sealedC := make([]byte, sealedLenC)
	nBody, err := io.ReadFull(conn, sealedC)
	if err != nil {
		if hasUserForwarder {
			captured := make([]byte, nHdr+nBody)
			copy(captured[:nHdr], hdrC[:nHdr])
			copy(captured[nHdr:], sealedC[:nBody])
			_ = conn.SetReadDeadline(time.Time{})
			return ActionUserClient, NewPrefixConn(conn, captured), nil
		}
		_ = conn.Close()
		return ActionDPIProbe, nil, err
	}

	if aead, aErr := chacha20poly1305.New(psk); aErr == nil {
		if plainC, oErr := aead.Open(nil, hdrC[:12], sealedC, []byte(stealthPrologue)); oErr == nil && len(plainC) >= 33 {
			pubC := plainC[:32]
			curve := ecdh.X25519()
			if peerPubC, pErr := curve.NewPublicKey(pubC); pErr == nil {
				if privS, gErr := curve.GenerateKey(rand.Reader); gErr == nil {
					pubS := privS.PublicKey().Bytes()
					if shared, eErr := privS.ECDH(peerPubC); eErr == nil {
						padLen := mathrand.IntN(stealthMaxPad + 1)
						plainS := make([]byte, 32+1+padLen)
						copy(plainS[:32], pubS)
						plainS[32] = byte(padLen)
						_, _ = rand.Read(plainS[33:])

						var nonceS [12]byte
						_, _ = io.ReadFull(rand.Reader, nonceS[:])
						sealedS := aead.Seal(nil, nonceS[:], plainS, pubC)
						flightS := make([]byte, 14+len(sealedS))
						copy(flightS[:12], nonceS[:])
						maskS := binary.BigEndian.Uint16(nonceS[:2]) ^ binary.BigEndian.Uint16(psk[2:4])
						binary.BigEndian.PutUint16(flightS[12:14], uint16(len(sealedS))^maskS)
						copy(flightS[14:], sealedS)

						_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
						if _, wErr := conn.Write(flightS); wErr == nil {
							c2sKey, s2cKey, kErr := deriveStealthSessionKeys(psk, shared, pubC, pubS)
							if kErr == nil {
								_ = conn.SetDeadline(time.Time{})
								sConn, sErr := newStealthConn(conn, s2cKey, c2sKey)
								if sErr == nil {
									return ActionReverseCarrier, sConn, nil
								}
							}
						}
					}
				}
			}
		}
	}

	if hasUserForwarder {
		captured := make([]byte, 14+sealedLenC)
		copy(captured[:14], hdrC[:])
		copy(captured[14:], sealedC)
		_ = conn.SetDeadline(time.Time{})
		return ActionUserClient, NewPrefixConn(conn, captured), nil
	}

	_ = conn.Close()
	return ActionDPIProbe, nil, errors.New("unauthenticated stealth probe dropped")
}

// StealthConn wraps a net.Conn with ChaCha20-Poly1305 AEAD record encryption and random length padding.
type StealthConn struct {
	net.Conn
	writeMu   sync.Mutex
	readMu    sync.Mutex
	writeAEAD interface {
		Seal(dst, nonce, plaintext, additionalData []byte) []byte
	}
	readAEAD interface {
		Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
	}
	writeMask uint16
	readMask  uint16
	writeSeq  uint64
	readSeq   uint64
	readBuf   []byte
	rawBuf    []byte
}

func newStealthConn(c net.Conn, writeKey, readKey []byte) (*StealthConn, error) {
	wAEAD, err := chacha20poly1305.New(writeKey)
	if err != nil {
		return nil, err
	}
	rAEAD, err := chacha20poly1305.New(readKey)
	if err != nil {
		return nil, err
	}
	return &StealthConn{
		Conn:      c,
		writeAEAD: wAEAD,
		readAEAD:  rAEAD,
		writeMask: binary.BigEndian.Uint16(writeKey[30:32]),
		readMask:  binary.BigEndian.Uint16(readKey[30:32]),
		rawBuf:    make([]byte, 2+stealthMaxFrameData+1+stealthMaxPad+16),
	}, nil
}

func (s *StealthConn) Write(p []byte) (int, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	total := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > stealthMaxFrameData {
			chunk = p[:stealthMaxFrameData]
		}
		p = p[len(chunk):]

		// Add random padding on small frames (< 1024B) to hide control/handshake frame lengths
		padLen := 0
		if len(chunk) < 1024 {
			padLen = mathrand.IntN(64)
		}
		plainLen := 1 + len(chunk) + padLen
		plain := make([]byte, plainLen)
		plain[0] = byte(padLen)
		copy(plain[1:1+len(chunk)], chunk)

		seq := s.writeSeq
		s.writeSeq++
		var nonce [12]byte
		binary.BigEndian.PutUint64(nonce[4:], seq)

		sealed := s.writeAEAD.Seal(nil, nonce[:], plain, nil)
		frame := make([]byte, 2+len(sealed))
		lenMask := s.writeMask ^ uint16((seq+1)*0x9E37)
		binary.BigEndian.PutUint16(frame[:2], uint16(len(sealed))^lenMask)
		copy(frame[2:], sealed)

		if _, err := s.Conn.Write(frame); err != nil {
			return total, err
		}
		total += len(chunk)
	}
	return total, nil
}

func (s *StealthConn) Read(p []byte) (int, error) {
	s.readMu.Lock()
	defer s.readMu.Unlock()

	if len(s.readBuf) > 0 {
		n := copy(p, s.readBuf)
		s.readBuf = s.readBuf[n:]
		return n, nil
	}

	var hdr [2]byte
	if _, err := io.ReadFull(s.Conn, hdr[:]); err != nil {
		return 0, err
	}

	seq := s.readSeq
	s.readSeq++
	var nonce [12]byte
	binary.BigEndian.PutUint64(nonce[4:], seq)

	lenMask := s.readMask ^ uint16((seq+1)*0x9E37)
	sealedLen := int(binary.BigEndian.Uint16(hdr[:]) ^ lenMask)
	if sealedLen < 17 || sealedLen > len(s.rawBuf) {
		return 0, errors.New("stealth invalid record length")
	}

	if _, err := io.ReadFull(s.Conn, s.rawBuf[:sealedLen]); err != nil {
		return 0, err
	}

	plain, err := s.readAEAD.Open(s.rawBuf[:0], nonce[:], s.rawBuf[:sealedLen], nil)
	if err != nil {
		return 0, err
	}
	if len(plain) < 1 {
		return 0, errors.New("stealth empty record")
	}
	padLen := int(plain[0])
	if 1+padLen > len(plain) {
		return 0, errors.New("stealth invalid record padding")
	}
	data := plain[1 : len(plain)-padLen]
	n := copy(p, data)
	if n < len(data) {
		s.readBuf = append(s.readBuf[:0], data[n:]...)
	}
	return n, nil
}

func (s *StealthConn) CloseWrite() error {
	if cw, ok := s.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

func (s *StealthConn) CloseRead() error {
	if cr, ok := s.Conn.(interface{ CloseRead() error }); ok {
		return cr.CloseRead()
	}
	return nil
}

package transport

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	defaultL3MTU = 1420
	greHeaderLen = 4
	l3HeaderLen  = 9 // [1B version=0x01][8B counter nonce]
	ifnamSize    = 16
)

// DeriveL3Subnet returns the deterministic /30 point-to-point tunnel IPs for a tunnel ID.
// Entry (Iran) gets 10.10.X.1/30, Exit (Kharej) gets 10.10.X.2/30.
func DeriveL3Subnet(tunnelID int, role string) (ifaceName, localCIDR, peerIP string) {
	octet := (tunnelID % 250) + 1
	if octet <= 0 || octet > 250 {
		octet = 1
	}
	// Benchmark sandbox engines use TunnelID >= 1000 (t.Id*1000 + candIndex).
	// Use a distinct prefix so they never collide with production "antun" interfaces.
	if tunnelID >= 1000 {
		ifaceName = fmt.Sprintf("antbs%d", tunnelID%10000)
	} else {
		ifaceName = fmt.Sprintf("antun%d", tunnelID%10000)
	}
	if len(ifaceName) >= ifnamSize {
		ifaceName = ifaceName[:ifnamSize-1]
	}
	if role == "entry" {
		localCIDR = fmt.Sprintf("10.10.%d.1/30", octet)
		peerIP = fmt.Sprintf("10.10.%d.2", octet)
	} else {
		localCIDR = fmt.Sprintf("10.10.%d.2/30", octet)
		peerIP = fmt.Sprintf("10.10.%d.1", octet)
	}
	return ifaceName, localCIDR, peerIP
}

// NewL3PacketCodec creates a standalone GRE + ChaCha20-Poly1305 AEAD packet codec
// (used by L3TUNDevice and unit tests).
func NewL3PacketCodec(password string) (cipher.AEAD, error) {
	key, err := DeriveRealityKey(password, "archnet-l3-gre-aead")
	if err != nil {
		return nil, err
	}
	return chacha20poly1305.New(key[:])
}

// SealL3GREPacket encapsulates a raw IPv4/IPv6 packet in a 4-byte RFC 2784 GRE header
// and encrypts it with ChaCha20-Poly1305 using an 8-byte monotonic counter nonce.
func SealL3GREPacket(aead cipher.AEAD, counter uint64, rawIP []byte) ([]byte, error) {
	if len(rawIP) < 20 {
		return nil, errors.New("l3: IP packet shorter than 20 bytes")
	}
	version := rawIP[0] >> 4
	var etherType uint16
	switch version {
	case 4:
		etherType = 0x0800 // IPv4
	case 6:
		etherType = 0x86DD // IPv6
	default:
		return nil, fmt.Errorf("l3: unsupported IP version %d", version)
	}

	// Build [4B GRE Header] + [Raw IP Packet]
	grePlain := make([]byte, greHeaderLen+len(rawIP))
	grePlain[0] = 0x00
	grePlain[1] = 0x00
	binary.BigEndian.PutUint16(grePlain[2:4], etherType)
	copy(grePlain[4:], rawIP)

	var nonce [12]byte
	nonce[0] = 0x01
	binary.BigEndian.PutUint64(nonce[4:12], counter)

	var aad [l3HeaderLen]byte
	aad[0] = 0x01
	binary.BigEndian.PutUint64(aad[1:9], counter)

	sealed := aead.Seal(nil, nonce[:], grePlain, aad[:])

	// Final Wire Format: [1B 0x01][8B Counter][Ciphertext+Tag]
	wire := make([]byte, l3HeaderLen+len(sealed))
	copy(wire[:l3HeaderLen], aad[:])
	copy(wire[l3HeaderLen:], sealed)
	return wire, nil
}

// OpenL3GREPacket decrypts an incoming wire packet and unstrips the 4-byte GRE header,
// returning the clean raw IPv4/IPv6 packet ready for TUN injection.
func OpenL3GREPacket(aead cipher.AEAD, wire []byte) ([]byte, error) {
	if len(wire) < l3HeaderLen+greHeaderLen+16 {
		return nil, errors.New("l3: packet too short")
	}
	if wire[0] != 0x01 {
		return nil, fmt.Errorf("l3: unsupported frame version 0x%02x", wire[0])
	}
	counter := binary.BigEndian.Uint64(wire[1:9])

	var nonce [12]byte
	nonce[0] = 0x01
	binary.BigEndian.PutUint64(nonce[4:12], counter)

	var aad [l3HeaderLen]byte
	copy(aad[:], wire[:l3HeaderLen])

	plain, err := aead.Open(nil, nonce[:], wire[l3HeaderLen:], aad[:])
	if err != nil {
		return nil, fmt.Errorf("l3: decrypt failed: %w", err)
	}
	if len(plain) < greHeaderLen+20 {
		return nil, errors.New("l3: decrypted packet too short")
	}
	etherType := binary.BigEndian.Uint16(plain[2:4])
	if etherType != 0x0800 && etherType != 0x86DD {
		return nil, fmt.Errorf("l3: unexpected GRE protocol 0x%04x", etherType)
	}
	return plain[greHeaderLen:], nil
}

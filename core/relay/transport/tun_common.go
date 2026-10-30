package transport

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	defaultL3MTU = 1420
	greHeaderLen = 4
	l3HeaderLen  = 9 // [1B version=0x01][8B counter nonce]
	ifnamSize    = 16

	maxL3OuterPayload = 1380 // Safe ceiling so outer packets never exceed Ethernet 1500 MTU (zero kernel IP fragmentation)
	l3FragVersion     = 0x02
	l3FragHeaderLen   = 13 // [1B 0x02][8B counter][2B fragIdx][2B totalFrags]
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
	subnetPrefix := "10.10"
	if tunnelID >= 1000 {
		subnetPrefix = "10.19"
	}
	if role == "entry" {
		localCIDR = fmt.Sprintf("%s.%d.1/30", subnetPrefix, octet)
		peerIP = fmt.Sprintf("%s.%d.2", subnetPrefix, octet)
	} else {
		localCIDR = fmt.Sprintf("%s.%d.2/30", subnetPrefix, octet)
		peerIP = fmt.Sprintf("%s.%d.1", subnetPrefix, octet)
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

// L3FragmentReassembler caches and reconstructs userspace-fragmented L3 packets.
type L3FragmentReassembler struct {
	mu      sync.Mutex
	entries map[uint64]*l3FragEntry
	lastGC  time.Time
}

type l3FragEntry struct {
	total   int
	chunks  [][]byte
	arrived int
	created time.Time
}

// NewL3FragmentReassembler creates a new userspace reassembly cache.
func NewL3FragmentReassembler() *L3FragmentReassembler {
	return &L3FragmentReassembler{
		entries: make(map[uint64]*l3FragEntry),
		lastGC:  time.Now(),
	}
}

// ProcessFrame processes an incoming L3 wire frame.
// If the frame is unfragmented (0x01), it decrypts and returns the raw IP packet immediately.
// If the frame is a fragment (0x02), it buffers the chunk and returns the complete IP packet
// once all chunks have arrived, or nil if more fragments are pending.
func (r *L3FragmentReassembler) ProcessFrame(aead cipher.AEAD, frame []byte) ([]byte, error) {
	if len(frame) < 1 {
		return nil, errors.New("l3: empty frame")
	}

	// 1. Unfragmented standard packet (0x01)
	if frame[0] == 0x01 {
		return OpenL3GREPacket(aead, frame)
	}

	// 2. Userspace Fragmented frame (0x02): [1B 0x02][8B counter][2B idx][2B total][chunk]
	if frame[0] == l3FragVersion {
		if len(frame) < l3FragHeaderLen {
			return nil, errors.New("l3: fragment header too short")
		}
		counter := binary.BigEndian.Uint64(frame[1:9])
		idx := int(binary.BigEndian.Uint16(frame[9:11]))
		total := int(binary.BigEndian.Uint16(frame[11:13]))
		if total <= 1 || idx >= total || total > 16 {
			return nil, errors.New("l3: invalid fragment bounds")
		}
		chunk := frame[l3FragHeaderLen:]

		r.mu.Lock()
		defer r.mu.Unlock()

		// Periodic expiry cleanup (every 5 seconds)
		now := time.Now()
		if now.Sub(r.lastGC) > 5*time.Second {
			for k, entry := range r.entries {
				if now.Sub(entry.created) > 5*time.Second {
					delete(r.entries, k)
				}
			}
			r.lastGC = now
		}

		entry, exists := r.entries[counter]
		if !exists {
			entry = &l3FragEntry{
				total:   total,
				chunks:  make([][]byte, total),
				created: now,
			}
			r.entries[counter] = entry
		}

		if entry.chunks[idx] == nil {
			entry.chunks[idx] = chunk
			entry.arrived++
		}

		if entry.arrived == entry.total {
			delete(r.entries, counter)
			// Reassemble full wire packet
			totalWireLen := 0
			for _, c := range entry.chunks {
				totalWireLen += len(c)
			}
			fullWire := make([]byte, totalWireLen)
			pos := 0
			for _, c := range entry.chunks {
				copy(fullWire[pos:], c)
				pos += len(c)
			}
			return OpenL3GREPacket(aead, fullWire)
		}
		return nil, nil // Waiting for remaining fragments
	}

	return nil, fmt.Errorf("l3: unknown frame version 0x%02x", frame[0])
}

// SealL3GREFragments seals a raw IP packet and, if the resulting wire packet exceeds
// maxL3OuterPayload (1380 bytes), splits it into userspace fragments so outer packets
// fit within standard 1500-byte Ethernet MTU without triggering kernel IP fragmentation.
func SealL3GREFragments(aead cipher.AEAD, counter uint64, rawIP []byte) ([][]byte, error) {
	fullWire, err := SealL3GREPacket(aead, counter, rawIP)
	if err != nil {
		return nil, err
	}
	if len(fullWire) <= maxL3OuterPayload {
		return [][]byte{fullWire}, nil
	}

	// Fragment into chunks
	const chunkSize = 1200
	chunks := make([][]byte, 0, (len(fullWire)+chunkSize-1)/chunkSize)
	for pos := 0; pos < len(fullWire); pos += chunkSize {
		end := pos + chunkSize
		if end > len(fullWire) {
			end = len(fullWire)
		}
		chunks = append(chunks, fullWire[pos:end])
	}

	total := uint16(len(chunks))
	frames := make([][]byte, len(chunks))
	for i, chunk := range chunks {
		f := make([]byte, l3FragHeaderLen+len(chunk))
		f[0] = l3FragVersion
		binary.BigEndian.PutUint64(f[1:9], counter)
		binary.BigEndian.PutUint16(f[9:11], uint16(i))
		binary.BigEndian.PutUint16(f[11:13], total)
		copy(f[l3FragHeaderLen:], chunk)
		frames[i] = f
	}
	return frames, nil
}

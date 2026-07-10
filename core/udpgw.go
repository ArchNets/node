package core

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

// udpgw protocol constants, matching github.com/ambrop72/badvpn's udpgw.
//
// Wire format per message:
//   | 2 byte size (LE) | 1 byte flags | 2 byte connID (LE) | 6 or 18 byte addr | payload |
// The "size" field covers everything after itself (flags + connID + addr + payload).
// Address is 6 bytes (4 byte IPv4 + 2 byte BE port) unless FlagIPv6 is set, then
// 18 bytes (16 byte IPv6 + 2 byte BE port).
const (
	udpgwFlagKeepalive = 1 << 0
	udpgwFlagRebind    = 1 << 1
	udpgwFlagDNS       = 1 << 2
	udpgwFlagIPv6      = 1 << 3

	udpgwMaxPreamble    = 23 // 2 (size, not counted in preambleSize below) + 1 flags + 2 connID + 18 addr
	udpgwMaxPayload     = 32768
	udpgwMaxMessageSize = udpgwMaxPreamble + udpgwMaxPayload

	udpgwPortForwardIdleTimeout = 60 * time.Second
	udpgwMaxPortForwardsPerConn = 512 // guard against a single client exhausting fds
)

// Note: the udpgw listen address is now configurable per-SSHCore (see
// SSHCore.udpgwAddr in ssh.go), defaulting to "127.0.0.1:7300" -- the
// address clients (HTTP Injector, NPV Tunnel, KPN Tunnel, etc.) expect a
// udpgw server to be listening on by convention.

type udpgwMultiplexer struct {
	sshCore    *SSHCore
	uid        int
	channel    ssh.Channel
	writeMu    sync.Mutex
	forwardsMu sync.Mutex
	forwards   map[uint16]*udpgwPortForward
}

type udpgwPortForward struct {
	connID       uint16
	conn         *net.UDPConn
	remoteIP     []byte
	remotePort   uint16
	preambleSize int
	lastUsed     atomicTime
}

// minimal monotonic-ish "last used" tracker without pulling in sync/atomic.Value ceremony
type atomicTime struct {
	mu sync.Mutex
	t  time.Time
}

func (a *atomicTime) touch() {
	a.mu.Lock()
	a.t = time.Now()
	a.mu.Unlock()
}

func (a *atomicTime) since() time.Duration {
	a.mu.Lock()
	defer a.mu.Unlock()
	return time.Since(a.t)
}

// handleUdpgwChannel takes over a direct-tcpip channel that was aimed at
// udpgwAddr and treats it as a udpgw control stream instead of a raw TCP
// forward. One channel multiplexes many UDP "connections" via connID.
func (s *SSHCore) handleUdpgwChannel(channel ssh.Channel, uid int) {
	defer channel.Close()

	mux := &udpgwMultiplexer{
		sshCore:  s,
		uid:      uid,
		channel:  channel,
		forwards: make(map[uint16]*udpgwPortForward),
	}
	defer mux.closeAll()

	buffer := make([]byte, udpgwMaxMessageSize)
	for {
		msg, err := readUdpgwMessage(channel, buffer)
		if err != nil {
			if err != io.EOF {
				log.WithError(err).Debug("udpgw read failed")
			}
			return
		}
		if msg == nil {
			continue // keepalive, nothing to do
		}

		mux.forwardsMu.Lock()
		pf := mux.forwards[msg.connID]
		mux.forwardsMu.Unlock()

		if pf != nil && (msg.rebind || !ipEqual(pf.remoteIP, msg.remoteIP) || pf.remotePort != msg.remotePort) {
			pf.conn.Close() // triggers relayDownstream to exit and clean up
			pf = nil
		}

		if pf == nil {
			pf, err = mux.newPortForward(msg)
			if err != nil {
				log.WithError(err).Debug("udpgw dial failed")
				continue // udpgw protocol has no error response; just drop
			}
		}

		n, err := pf.conn.Write(msg.packet)
		if err != nil {
			pf.conn.Close()
			continue
		}
		pf.lastUsed.touch()
		s.addTraffic(uid, int64(n), false) // upload
	}
}

func (mux *udpgwMultiplexer) newPortForward(msg *udpgwProtocolMessage) (*udpgwPortForward, error) {
	mux.forwardsMu.Lock()
	if len(mux.forwards) >= udpgwMaxPortForwardsPerConn {
		mux.forwardsMu.Unlock()
		return nil, fmt.Errorf("too many concurrent udpgw port forwards")
	}
	mux.forwardsMu.Unlock()

	var ip net.IP = msg.remoteIP
	udpConn, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: ip, Port: int(msg.remotePort)})
	if err != nil {
		return nil, err
	}

	preambleSize := 7 + len(msg.remoteIP) // flags(1) + connID(2) + addr

	pf := &udpgwPortForward{
		connID:       msg.connID,
		conn:         udpConn,
		remoteIP:     msg.remoteIP,
		remotePort:   msg.remotePort,
		preambleSize: preambleSize,
	}
	pf.lastUsed.touch()

	mux.forwardsMu.Lock()
	mux.forwards[msg.connID] = pf
	mux.forwardsMu.Unlock()

	go mux.relayDownstream(pf)

	return pf, nil
}

// relayDownstream reads UDP replies for one port forward and frames them
// back to the client over the shared udpgw SSH channel.
func (mux *udpgwMultiplexer) relayDownstream(pf *udpgwPortForward) {
	defer func() {
		mux.forwardsMu.Lock()
		delete(mux.forwards, pf.connID)
		mux.forwardsMu.Unlock()
		pf.conn.Close()
	}()

	buffer := make([]byte, udpgwMaxMessageSize)
	packetBuf := buffer[pf.preambleSize:]

	for {
		pf.conn.SetReadDeadline(time.Now().Add(udpgwPortForwardIdleTimeout))
		n, err := pf.conn.Read(packetBuf)
		if err != nil {
			return // timeout or closed; connID will be recreated on next client packet
		}
		if n > udpgwMaxPayload {
			continue
		}

		if err := writeUdpgwPreamble(pf.preambleSize, 0, pf.connID, pf.remoteIP, pf.remotePort, uint16(n), buffer); err != nil {
			continue
		}

		mux.writeMu.Lock()
		_, werr := mux.channel.Write(buffer[:pf.preambleSize+n])
		mux.writeMu.Unlock()
		if werr != nil {
			return
		}

		pf.lastUsed.touch()
		mux.sshCore.addTraffic(mux.uid, int64(n), true) // download
	}
}

func (mux *udpgwMultiplexer) closeAll() {
	mux.forwardsMu.Lock()
	defer mux.forwardsMu.Unlock()
	for _, pf := range mux.forwards {
		pf.conn.Close()
	}
}

func ipEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// --- wire format ---

type udpgwProtocolMessage struct {
	connID     uint16
	remoteIP   []byte
	remotePort uint16
	rebind     bool
	dns        bool
	packet     []byte
}

func readUdpgwMessage(r io.Reader, buffer []byte) (*udpgwProtocolMessage, error) {
	if _, err := io.ReadFull(r, buffer[0:2]); err != nil {
		return nil, err
	}
	size := binary.LittleEndian.Uint16(buffer[0:2])
	if size < 3 || int(size) > len(buffer)-2 {
		return nil, fmt.Errorf("invalid udpgw message size %d", size)
	}
	if _, err := io.ReadFull(r, buffer[2:2+size]); err != nil {
		return nil, err
	}

	flags := buffer[2]
	connID := binary.LittleEndian.Uint16(buffer[3:5])

	if flags&udpgwFlagKeepalive != 0 {
		return nil, nil // caller loops and reads the next message
	}

	var remoteIP []byte
	var remotePort uint16
	var packetStart, packetEnd int

	if flags&udpgwFlagIPv6 != 0 {
		if size < 21 {
			return nil, fmt.Errorf("invalid udpgw ipv6 message size %d", size)
		}
		remoteIP = append([]byte(nil), buffer[5:21]...)
		remotePort = binary.BigEndian.Uint16(buffer[21:23])
		packetStart, packetEnd = 23, 23+int(size)-21
	} else {
		if size < 9 {
			return nil, fmt.Errorf("invalid udpgw ipv4 message size %d", size)
		}
		remoteIP = append([]byte(nil), buffer[5:9]...)
		remotePort = binary.BigEndian.Uint16(buffer[9:11])
		packetStart, packetEnd = 11, 11+int(size)-9
	}

	return &udpgwProtocolMessage{
		connID:     connID,
		remoteIP:   remoteIP,
		remotePort: remotePort,
		rebind:     flags&udpgwFlagRebind != 0,
		dns:        flags&udpgwFlagDNS != 0,
		packet:     buffer[packetStart:packetEnd],
	}, nil
}

func writeUdpgwPreamble(preambleSize int, flags uint8, connID uint16, remoteIP []byte, remotePort uint16, packetSize uint16, buffer []byte) error {
	if preambleSize != 7+len(remoteIP) {
		return fmt.Errorf("invalid udpgw preamble size")
	}
	size := uint16(preambleSize-2) + packetSize
	binary.LittleEndian.PutUint16(buffer[0:2], size)
	buffer[2] = flags
	binary.LittleEndian.PutUint16(buffer[3:5], connID)
	copy(buffer[5:5+len(remoteIP)], remoteIP)
	binary.BigEndian.PutUint16(buffer[5+len(remoteIP):7+len(remoteIP)], remotePort)
	return nil
}

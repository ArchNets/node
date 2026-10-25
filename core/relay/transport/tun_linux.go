//go:build linux

package transport

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"unsafe"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/sys/unix"
)

const (
	// tunReadBuf is 64 KiB (65535) to safely accommodate kernel GRO/GSO coalesced segments
	// without buffer overrun (matching WaterWall tun_linux_reader.c & BackPack tun_linux.go).
	tunReadBuf     = 65535
	defaultL3MTU   = 1420
	defaultTxQueue = 4096

	greHeaderLen = 4
	l3HeaderLen  = 9 // [1B version=0x01][8B counter nonce]
)

type ifreqFlags struct {
	Name  [unix.IFNAMSIZ]byte
	Flags uint16
	Pad   [22]byte
}

// L3TUNDevice manages a Linux Layer-3 TUN interface (/dev/net/tun with IFF_TUN | IFF_NO_PI),
// GRE encapsulation, ChaCha20-Poly1305 AEAD encryption, fq_codel qdisc, and TCPMSS clamping.
type L3TUNDevice struct {
	file      *os.File
	name      string
	localIP   string
	peerIP    string
	mtu       int
	mss       int
	aead      cipher.AEAD
	txCounter atomic.Uint64
	closed    atomic.Bool
	closeOnce sync.Once
	txHook    atomic.Pointer[func([]byte) error]
}

// DeriveL3Subnet returns the deterministic /30 point-to-point tunnel IPs for a tunnel ID.
// Entry (Iran) gets 10.10.X.1/30, Exit (Kharej) gets 10.10.X.2/30.
func DeriveL3Subnet(tunnelID int, role string) (ifaceName, localCIDR, peerIP string) {
	octet := (tunnelID % 250) + 1
	if octet <= 0 || octet > 250 {
		octet = 1
	}
	ifaceName = fmt.Sprintf("antun%d", tunnelID%10000)
	if len(ifaceName) >= unix.IFNAMSIZ {
		ifaceName = ifaceName[:unix.IFNAMSIZ-1]
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

	out := make([]byte, l3HeaderLen, l3HeaderLen+len(grePlain)+aead.Overhead())
	copy(out[:l3HeaderLen], aad[:])
	out = aead.Seal(out, nonce[:], grePlain, aad[:])
	return out, nil
}

// OpenL3GREPacket decrypts and strips the 4-byte GRE header, returning the inner IPv4/IPv6 packet.
func OpenL3GREPacket(aead cipher.AEAD, wire []byte) ([]byte, error) {
	if len(wire) < l3HeaderLen+greHeaderLen+aead.Overhead() {
		return nil, errors.New("l3: wire frame too short")
	}
	if wire[0] != 0x01 {
		return nil, errors.New("l3: invalid wire version")
	}
	counter := binary.BigEndian.Uint64(wire[1:9])
	var nonce [12]byte
	nonce[0] = 0x01
	binary.BigEndian.PutUint64(nonce[4:12], counter)

	plain, err := aead.Open(nil, nonce[:], wire[l3HeaderLen:], wire[:l3HeaderLen])
	if err != nil {
		return nil, err
	}
	if len(plain) < greHeaderLen+20 {
		return nil, errors.New("l3: decrypted GRE frame too short")
	}
	etherType := binary.BigEndian.Uint16(plain[2:4])
	if etherType != 0x0800 && etherType != 0x86DD {
		return nil, fmt.Errorf("l3: unexpected GRE protocol 0x%04x", etherType)
	}
	return plain[greHeaderLen:], nil
}

// OpenL3TUN creates and configures a Linux Layer-3 TUN interface (/dev/net/tun).
func OpenL3TUN(tunnelID int, role, password string, mtu int) (*L3TUNDevice, error) {
	if os.Geteuid() != 0 {
		return nil, errors.New("l3: creating TUN device requires root or CAP_NET_ADMIN")
	}
	aead, err := NewL3PacketCodec(password)
	if err != nil {
		return nil, err
	}
	if mtu <= 0 || mtu > 1420 {
		mtu = defaultL3MTU
	}
	mss := mtu - 40

	ifaceName, localCIDR, peerIP := DeriveL3Subnet(tunnelID, role)

	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("l3: open /dev/net/tun: %w", err)
	}

	var ifr ifreqFlags
	copy(ifr.Name[:], ifaceName)
	ifr.Flags = unix.IFF_TUN | unix.IFF_NO_PI

	_, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL,
		uintptr(fd),
		uintptr(unix.TUNSETIFF),
		uintptr(unsafe.Pointer(&ifr)),
	)
	if errno != 0 {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("l3: TUNSETIFF(%s) failed: %v", ifaceName, errno)
	}
	_ = unix.SetNonblock(fd, true)

	actualName := strings.TrimRight(string(ifr.Name[:]), "\x00")
	if actualName == "" {
		actualName = ifaceName
	}

	tunFile := os.NewFile(uintptr(fd), "/dev/net/tun")
	dev := &L3TUNDevice{
		file:    tunFile,
		name:    actualName,
		localIP: localCIDR,
		peerIP:  peerIP,
		mtu:     mtu,
		mss:     mss,
		aead:    aead,
	}

	if err := dev.configureKernelInterface(); err != nil {
		_ = dev.Close()
		return nil, err
	}

	go dev.readPumpLoop()
	return dev, nil
}

func (d *L3TUNDevice) Name() string    { return d.name }
func (d *L3TUNDevice) LocalIP() string { return d.localIP }
func (d *L3TUNDevice) PeerIP() string  { return d.peerIP }

// SetSender sets the function that transmits sealed L3 GRE frames over the active carrier.
func (d *L3TUNDevice) SetSender(fn func([]byte) error) {
	d.txHook.Store(&fn)
}

// InjectWirePacket decrypts an incoming L3 GRE wire frame from the carrier and writes the IP packet to the TUN device.
func (d *L3TUNDevice) InjectWirePacket(wire []byte) error {
	if d.closed.Load() {
		return os.ErrClosed
	}
	ipPkt, err := OpenL3GREPacket(d.aead, wire)
	if err != nil {
		return err
	}
	_, err = d.file.Write(ipPkt)
	return err
}

func (d *L3TUNDevice) readPumpLoop() {
	buf := make([]byte, tunReadBuf)
	for !d.closed.Load() {
		n, err := d.file.Read(buf)
		if err != nil {
			if d.closed.Load() {
				return
			}
			continue
		}
		if n < 20 {
			continue
		}
		hook := d.txHook.Load()
		if hook == nil || *hook == nil {
			continue
		}
		seq := d.txCounter.Add(1)
		wire, sErr := SealL3GREPacket(d.aead, seq, buf[:n])
		if sErr == nil {
			_ = (*hook)(wire)
		}
	}
}

func (d *L3TUNDevice) configureKernelInterface() error {
	_ = exec.Command("ip", "addr", "flush", "dev", d.name).Run()
	steps := [][]string{
		{"addr", "add", d.localIP, "dev", d.name},
		{"link", "set", "dev", d.name, "mtu", strconv.Itoa(d.mtu)},
		{"link", "set", "dev", d.name, "txqueuelen", strconv.Itoa(defaultTxQueue)},
		{"link", "set", "dev", d.name, "up"},
	}
	for _, args := range steps {
		if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			return fmt.Errorf("l3: ip %s: %w (%s)", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
		}
	}

	// Best-effort fq_codel queueing discipline to eliminate bufferbloat jitter (from BackPack tun_linux.go)
	_ = exec.Command("tc", "qdisc", "replace", "dev", d.name, "root", "fq_codel").Run()

	// Enable IPv4 forwarding and loose rp_filter on the TUN device
	_ = os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1\n"), 0644)
	_ = os.WriteFile(fmt.Sprintf("/proc/sys/net/ipv4/conf/%s/rp_filter", d.name), []byte("2\n"), 0644)

	d.applyMSSClamp()
	return nil
}

func (d *L3TUNDevice) mssRules() [][]string {
	mssStr := strconv.Itoa(d.mss)
	return [][]string{
		{"FORWARD", "-i", d.name, "-p", "tcp", "-m", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--set-mss", mssStr},
		{"FORWARD", "-o", d.name, "-p", "tcp", "-m", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--set-mss", mssStr},
		{"POSTROUTING", "-o", d.name, "-p", "tcp", "-m", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--set-mss", mssStr},
	}
}

func (d *L3TUNDevice) applyMSSClamp() {
	if _, err := exec.LookPath("iptables"); err != nil {
		return
	}
	for _, r := range d.mssRules() {
		sweepIptablesRule("mangle", r)
		_ = exec.Command("iptables", append([]string{"-w", "2", "-t", "mangle", "-A"}, r...)...).Run()
	}
}

func (d *L3TUNDevice) removeMSSClamp() {
	if _, err := exec.LookPath("iptables"); err != nil {
		return
	}
	for _, r := range d.mssRules() {
		sweepIptablesRule("mangle", r)
	}
}

func (d *L3TUNDevice) Close() error {
	var err error
	d.closeOnce.Do(func() {
		d.closed.Store(true)
		d.removeMSSClamp()
		_ = exec.Command("ip", "link", "set", "dev", d.name, "down").Run()
		if d.file != nil {
			err = d.file.Close()
		}
	})
	return err
}

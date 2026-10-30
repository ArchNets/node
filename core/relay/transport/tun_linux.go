//go:build linux

package transport

import (
	"crypto/cipher"
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

	"golang.org/x/sys/unix"
)

const (
	// tunReadBuf is 64 KiB (65535) to safely accommodate kernel GRO/GSO coalesced segments
	// without buffer overrun (matching WaterWall tun_linux_reader.c & BackPack tun_linux.go).
	tunReadBuf     = 65535
	defaultTxQueue = 4096
)

type ifreqFlags struct {
	Name  [unix.IFNAMSIZ]byte
	Flags uint16
	Pad   [22]byte
}

// L3TUNDevice manages a Linux Layer-3 TUN interface (/dev/net/tun with IFF_TUN | IFF_NO_PI),
// GRE encapsulation, ChaCha20-Poly1305 AEAD encryption, fq_codel qdisc, and TCPMSS clamping.
type L3TUNDevice struct {
	file        *os.File
	name        string
	localIP     string
	peerIP      string
	mtu         int
	mss         int
	aead        cipher.AEAD
	reassembler *L3FragmentReassembler
	txCounter   atomic.Uint64
	closed      atomic.Bool
	closeOnce   sync.Once
	txHook      atomic.Pointer[func([]byte) error]
}

// OpenL3TUN creates and configures a Linux Layer-3 TUN interface (/dev/net/tun).
func OpenL3TUN(tunnelID int, role, password string, mtu int) (*L3TUNDevice, error) {
	return OpenL3TUNWithSubnet(tunnelID, role, password, mtu, "", "", "")
}

// OpenL3TUNWithSubnet creates and configures a Linux Layer-3 TUN interface (/dev/net/tun) with optional custom subnet.
func OpenL3TUNWithSubnet(tunnelID int, role, password string, mtu int, customIface, customLocalCIDR, customPeerIP string) (*L3TUNDevice, error) {
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
	if customIface != "" {
		ifaceName = customIface
		if len(ifaceName) >= unix.IFNAMSIZ {
			ifaceName = ifaceName[:unix.IFNAMSIZ-1]
		}
	}
	if customLocalCIDR != "" && customPeerIP != "" {
		localCIDR = customLocalCIDR
		peerIP = customPeerIP
	}

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
		file:        tunFile,
		name:        actualName,
		localIP:     localCIDR,
		peerIP:      peerIP,
		mtu:         mtu,
		mss:         mss,
		aead:        aead,
		reassembler: NewL3FragmentReassembler(),
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

// InjectWirePacket decrypts an incoming L3 GRE wire frame (or reassembles userspace fragments)
// and writes the complete IP packet to the TUN device.
func (d *L3TUNDevice) InjectWirePacket(wire []byte) error {
	if d.closed.Load() {
		return os.ErrClosed
	}
	ipPkt, err := d.reassembler.ProcessFrame(d.aead, wire)
	if err != nil {
		return err
	}
	if ipPkt == nil {
		return nil // Fragment buffered, waiting for remaining chunks
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
		frames, sErr := SealL3GREFragments(d.aead, seq, buf[:n])
		if sErr == nil {
			for _, frame := range frames {
				_ = (*hook)(frame)
			}
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

	if d.peerIP != "" {
		_ = exec.Command("ip", "route", "replace", d.peerIP, "dev", d.name).Run()
	}

	// Enable IPv4 forwarding and loose rp_filter on the TUN device (instant in-memory procfs writes)
	_ = os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1\n"), 0644)
	_ = os.WriteFile(fmt.Sprintf("/proc/sys/net/ipv4/conf/%s/rp_filter", d.name), []byte("2\n"), 0644)

	// Benchmark sandboxes (antbs...) need instant zero-lag setup without hundreds of synchronous iptables calls
	if strings.HasPrefix(d.name, "antbs") {
		return nil
	}

	// Best-effort fq_codel queueing discipline to eliminate bufferbloat jitter (from BackPack tun_linux.go)
	_ = exec.Command("tc", "qdisc", "replace", "dev", d.name, "root", "fq_codel").Run()

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
	if strings.HasPrefix(d.name, "antbs") {
		return
	}
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
		// Explicitly delete the interface so its subnet is fully released before
		// the next sandbox engine tries to assign the same /30 block.
		_ = exec.Command("ip", "link", "delete", d.name).Run()
	})
	return err
}

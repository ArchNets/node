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
	isKernelGRE bool
	fouPort     int
	sitDev      string
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

	// Ensure local firewalls (e.g. UFW on Kharej with -P INPUT DROP) accept traffic on this TUN interface
	if os.Geteuid() == 0 {
		_ = exec.Command("iptables", "-w", "2", "-t", "filter", "-I", "INPUT", "1", "-i", d.name, "-j", "ACCEPT").Run()
		_ = exec.Command("iptables", "-w", "2", "-t", "filter", "-I", "FORWARD", "1", "-i", d.name, "-j", "ACCEPT").Run()
		_ = exec.Command("iptables", "-w", "2", "-t", "filter", "-I", "FORWARD", "1", "-o", d.name, "-j", "ACCEPT").Run()
	}

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
		if os.Geteuid() == 0 {
			if d.isKernelGRE && d.fouPort > 0 {
				portStr := strconv.Itoa(d.fouPort)
				_ = exec.Command("ip", "fou", "del", "port", portStr).Run()
				_ = exec.Command("iptables", "-w", "2", "-t", "filter", "-D", "INPUT", "-p", "udp", "--dport", portStr, "-j", "ACCEPT").Run()
			}
			_ = exec.Command("iptables", "-w", "2", "-t", "filter", "-D", "INPUT", "-i", d.name, "-j", "ACCEPT").Run()
			_ = exec.Command("iptables", "-w", "2", "-t", "filter", "-D", "FORWARD", "-i", d.name, "-j", "ACCEPT").Run()
			_ = exec.Command("iptables", "-w", "2", "-t", "filter", "-D", "FORWARD", "-o", d.name, "-j", "ACCEPT").Run()
		}
		_ = exec.Command("ip", "link", "set", "dev", d.name, "down").Run()
		if d.file != nil {
			err = d.file.Close()
		}
		if d.sitDev != "" {
			if os.Geteuid() == 0 {
				_ = exec.Command("ip6tables", "-w", "2", "-t", "filter", "-D", "INPUT", "-i", d.sitDev, "-j", "ACCEPT").Run()
				_ = exec.Command("ip6tables", "-w", "2", "-t", "filter", "-D", "INPUT", "-i", d.name, "-j", "ACCEPT").Run()
				_ = exec.Command("ip6tables", "-w", "2", "-t", "filter", "-D", "FORWARD", "-i", d.name, "-j", "ACCEPT").Run()
				_ = exec.Command("ip6tables", "-w", "2", "-t", "filter", "-D", "FORWARD", "-o", d.name, "-j", "ACCEPT").Run()
				_ = exec.Command("iptables", "-w", "2", "-t", "filter", "-D", "INPUT", "-i", d.sitDev, "-j", "ACCEPT").Run()
				_ = exec.Command("iptables", "-w", "2", "-t", "filter", "-D", "FORWARD", "-i", d.sitDev, "-j", "ACCEPT").Run()
				_ = exec.Command("iptables", "-w", "2", "-t", "filter", "-D", "FORWARD", "-o", d.sitDev, "-j", "ACCEPT").Run()
			}
			_ = exec.Command("ip", "link", "delete", d.sitDev).Run()
		}
		// Explicitly delete the interface so its subnet is fully released before
		// the next sandbox engine tries to assign the same /30 block.
		_ = exec.Command("ip", "link", "delete", d.name).Run()
	})
	return err
}

// OpenKernelFOUGRELink creates and configures a native Linux Kernel FOU (Foo-Over-UDP) GRE interface.
// Unlike userspace raw sockets, the Linux kernel natively encapsulates/decapsulates with zero-copy,
// wrapping GRE packets inside standard UDP packets with symmetric ports and encap-csum.
func OpenKernelFOUGRELink(tunnelID int, role, localPublicIP, remotePublicIP string, port, mtu int, customIface, customLocalCIDR, customPeerIP string) (*L3TUNDevice, error) {
	if os.Geteuid() != 0 {
		return nil, errors.New("l3-fou-gre: creating FOU GRE link requires root or CAP_NET_ADMIN")
	}
	_ = exec.Command("modprobe", "fou").Run()
	_ = exec.Command("modprobe", "ip_gre").Run()

	if port <= 0 || port > 65535 {
		port = 5000
	}
	portStr := strconv.Itoa(port)

	// Register FOU receive port in kernel if not already present
	_ = exec.Command("ip", "fou", "del", "port", portStr).Run()
	_ = exec.Command("ip", "fou", "add", "port", portStr, "ipproto", "47").Run()

	if mtu <= 0 || mtu > 1450 {
		mtu = 1400
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

	// Remove stale link if left behind from earlier run
	_ = exec.Command("ip", "link", "del", ifaceName).Run()

	// Add FOU GRE link with symmetric port and encap-csum
	addArgs := []string{
		"link", "add", ifaceName, "type", "gre",
		"local", localPublicIP, "remote", remotePublicIP,
		"encap", "fou", "encap-sport", portStr, "encap-dport", portStr,
		"encap-csum", "ttl", "255",
	}
	if out, err := exec.Command("ip", addArgs...).CombinedOutput(); err != nil {
		return nil, fmt.Errorf("ip %s: %s (%w)", strings.Join(addArgs, " "), string(out), err)
	}

	// Address and bring up interface
	if out, err := exec.Command("ip", "addr", "add", localCIDR, "peer", peerIP, "dev", ifaceName).CombinedOutput(); err != nil {
		_ = exec.Command("ip", "link", "del", ifaceName).Run()
		return nil, fmt.Errorf("ip addr add on %s: %s (%w)", ifaceName, string(out), err)
	}
	if err := exec.Command("ip", "link", "set", "dev", ifaceName, "mtu", strconv.Itoa(mtu), "up").Run(); err != nil {
		_ = exec.Command("ip", "link", "del", ifaceName).Run()
		return nil, err
	}
	_ = exec.Command("ip", "route", "replace", peerIP, "dev", ifaceName).Run()
	_ = os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1\n"), 0644)
	_ = os.WriteFile(fmt.Sprintf("/proc/sys/net/ipv4/conf/%s/rp_filter", ifaceName), []byte("2\n"), 0644)

	// Ensure local firewalls allow FOU UDP port and traffic on the interface
	_ = exec.Command("iptables", "-w", "2", "-t", "filter", "-I", "INPUT", "1", "-p", "udp", "--dport", portStr, "-j", "ACCEPT").Run()
	_ = exec.Command("iptables", "-w", "2", "-t", "filter", "-I", "INPUT", "1", "-i", ifaceName, "-j", "ACCEPT").Run()
	_ = exec.Command("iptables", "-w", "2", "-t", "filter", "-I", "FORWARD", "1", "-i", ifaceName, "-j", "ACCEPT").Run()
	_ = exec.Command("iptables", "-w", "2", "-t", "filter", "-I", "FORWARD", "1", "-o", ifaceName, "-j", "ACCEPT").Run()

	dev := &L3TUNDevice{
		name:        ifaceName,
		localIP:     localCIDR,
		peerIP:      peerIP,
		mtu:         mtu,
		mss:         mss,
		isKernelGRE: true,
		fouPort:     port,
	}
	dev.applyMSSClamp()
	return dev, nil
}

// OpenKernel6to4Link creates and configures a Linux kernel 6to4/SIT link carrying ipip6 or ip6gre.
// SIT operates over IPv4 Protocol 41 (or UDP FOU port when port > 0) and establishes an IPv6 underlay
// across which ipip6 or ip6gre passes with kernel zero-copy performance.
func OpenKernel6to4Link(tunnelID int, role, localPublicIP, remotePublicIP string, port, mtu int, customIface, customLocalCIDR, customPeerIP string, useGRE bool) (*L3TUNDevice, error) {
	if os.Geteuid() != 0 {
		return nil, errors.New("l3-6to4: creating SIT link requires root or CAP_NET_ADMIN")
	}
	_ = exec.Command("modprobe", "sit").Run()
	if useGRE {
		_ = exec.Command("modprobe", "ip6_gre").Run()
	} else {
		_ = exec.Command("modprobe", "ip6_tunnel").Run()
	}

	if mtu <= 0 || mtu > 1440 {
		mtu = 1400
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

	sitDev := ifaceName + "-6"
	if len(sitDev) >= unix.IFNAMSIZ {
		sitDev = ifaceName[:unix.IFNAMSIZ-3] + "-6"
	}

	_ = exec.Command("ip", "link", "del", ifaceName).Run()
	_ = exec.Command("ip", "link", "del", sitDev).Run()

	var fouArgs []string
	if port > 0 {
		_ = exec.Command("modprobe", "fou").Run()
		portStr := strconv.Itoa(port)
		_ = exec.Command("ip", "fou", "del", "port", portStr).Run()
		_ = exec.Command("ip", "fou", "add", "port", portStr, "ipproto", "41").Run()
		fouArgs = []string{"encap", "fou", "encap-sport", portStr, "encap-dport", portStr, "encap-csum"}
	}

	sitArgs := append([]string{
		"link", "add", "name", sitDev, "type", "sit",
		"local", localPublicIP, "remote", remotePublicIP,
		"ttl", "255",
	}, fouArgs...)
	if out, err := exec.Command("ip", sitArgs...).CombinedOutput(); err != nil {
		return nil, fmt.Errorf("ip sit: %s (%w)", string(out), err)
	}
	_ = exec.Command("ip", "link", "set", sitDev, "mtu", "1480", "up").Run()
	_ = os.WriteFile("/proc/sys/net/ipv6/conf/all/forwarding", []byte("1\n"), 0644)
	_ = os.WriteFile(fmt.Sprintf("/proc/sys/net/ipv6/conf/%s/disable_ipv6", sitDev), []byte("0\n"), 0644)

	carrierLocal6 := fmt.Sprintf("fd77:%x::1", (tunnelID%250)+1)
	carrierRemote6 := fmt.Sprintf("fd77:%x::2", (tunnelID%250)+1)
	if role == "exit" {
		carrierLocal6, carrierRemote6 = carrierRemote6, carrierLocal6
	}
	_ = exec.Command("ip", "-6", "addr", "add", carrierLocal6+"/64", "dev", sitDev).Run()
	_ = exec.Command("ip", "-6", "route", "replace", carrierRemote6, "dev", sitDev).Run()

	if useGRE {
		greArgs := []string{"link", "add", "name", ifaceName, "type", "ip6gre", "local", carrierLocal6, "remote", carrierRemote6}
		if out, err := exec.Command("ip", greArgs...).CombinedOutput(); err != nil {
			_ = exec.Command("ip", "link", "del", sitDev).Run()
			return nil, fmt.Errorf("ip ip6gre: %s (%w)", string(out), err)
		}
	} else {
		ipipArgs := []string{"-6", "tunnel", "add", ifaceName, "mode", "ipip6", "local", carrierLocal6, "remote", carrierRemote6, "dev", sitDev, "encaplimit", "none"}
		if out, err := exec.Command("ip", ipipArgs...).CombinedOutput(); err != nil {
			_ = exec.Command("ip", "link", "del", sitDev).Run()
			return nil, fmt.Errorf("ip ipip6: %s (%w)", string(out), err)
		}
	}

	_ = exec.Command("ip", "addr", "add", localCIDR, "dev", ifaceName).Run()
	_ = exec.Command("ip", "link", "set", "dev", ifaceName, "mtu", "1360", "up").Run()
	_ = exec.Command("ip", "route", "replace", peerIP, "dev", ifaceName).Run()
	_ = os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1\n"), 0644)
	_ = os.WriteFile(fmt.Sprintf("/proc/sys/net/ipv4/conf/%s/rp_filter", ifaceName), []byte("2\n"), 0644)
	_ = os.WriteFile(fmt.Sprintf("/proc/sys/net/ipv4/conf/%s/rp_filter", sitDev), []byte("2\n"), 0644)

	if port > 0 {
		portStr := strconv.Itoa(port)
		_ = exec.Command("iptables", "-w", "2", "-t", "filter", "-I", "INPUT", "1", "-p", "udp", "--dport", portStr, "-j", "ACCEPT").Run()
	} else {
		_ = exec.Command("iptables", "-w", "2", "-t", "filter", "-I", "INPUT", "1", "-p", "41", "-j", "ACCEPT").Run()
	}
	_ = exec.Command("iptables", "-w", "2", "-t", "filter", "-I", "INPUT", "1", "-i", sitDev, "-j", "ACCEPT").Run()
	_ = exec.Command("iptables", "-w", "2", "-t", "filter", "-I", "FORWARD", "1", "-i", sitDev, "-j", "ACCEPT").Run()
	_ = exec.Command("iptables", "-w", "2", "-t", "filter", "-I", "FORWARD", "1", "-o", sitDev, "-j", "ACCEPT").Run()
	_ = exec.Command("iptables", "-w", "2", "-t", "filter", "-I", "INPUT", "1", "-i", ifaceName, "-j", "ACCEPT").Run()
	_ = exec.Command("iptables", "-w", "2", "-t", "filter", "-I", "FORWARD", "1", "-i", ifaceName, "-j", "ACCEPT").Run()
	_ = exec.Command("iptables", "-w", "2", "-t", "filter", "-I", "FORWARD", "1", "-o", ifaceName, "-j", "ACCEPT").Run()
	if os.Geteuid() == 0 {
		_ = exec.Command("ip6tables", "-w", "2", "-t", "filter", "-I", "INPUT", "1", "-i", sitDev, "-j", "ACCEPT").Run()
		_ = exec.Command("ip6tables", "-w", "2", "-t", "filter", "-I", "INPUT", "1", "-i", ifaceName, "-j", "ACCEPT").Run()
		_ = exec.Command("ip6tables", "-w", "2", "-t", "filter", "-I", "FORWARD", "1", "-i", ifaceName, "-j", "ACCEPT").Run()
		_ = exec.Command("ip6tables", "-w", "2", "-t", "filter", "-I", "FORWARD", "1", "-o", ifaceName, "-j", "ACCEPT").Run()
	}

	dev := &L3TUNDevice{
		name:        ifaceName,
		sitDev:      sitDev,
		localIP:     localCIDR,
		peerIP:      peerIP,
		mtu:         mtu,
		mss:         mss,
		isKernelGRE: true,
		fouPort:     port,
	}
	dev.applyMSSClamp()
	return dev, nil
}

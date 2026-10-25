//go:build !linux

package transport

import "errors"

var errL3NotSupported = errors.New("l3: layer-3 TUN interface is only supported on Linux")

// L3TUNDevice stub for non-Linux platforms (darwin, windows, freebsd).
type L3TUNDevice struct{}

func (d *L3TUNDevice) Name() string                       { return "" }
func (d *L3TUNDevice) LocalIP() string                    { return "" }
func (d *L3TUNDevice) PeerIP() string                     { return "" }
func (d *L3TUNDevice) SetSender(fn func([]byte) error)    {}
func (d *L3TUNDevice) InjectWirePacket(wire []byte) error { return errL3NotSupported }
func (d *L3TUNDevice) Close() error                       { return nil }

// OpenL3TUN creates and configures a Linux Layer-3 TUN interface (/dev/net/tun).
func OpenL3TUN(tunnelID int, role, password string, mtu int) (*L3TUNDevice, error) {
	return nil, errL3NotSupported
}

// OpenL3TUNWithSubnet creates and configures a Linux Layer-3 TUN interface with optional custom subnet.
func OpenL3TUNWithSubnet(tunnelID int, role, password string, mtu int, customIface, customLocalCIDR, customPeerIP string) (*L3TUNDevice, error) {
	return nil, errL3NotSupported
}

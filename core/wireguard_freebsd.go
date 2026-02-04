//go:build freebsd

package core

import (
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/archnets/node/api/panel"
	"github.com/archnets/node/limiter"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// WireGuardCore manages a WireGuard VPN server (Stub for FreeBSD)
type WireGuardCore struct {
	Tag           string
	Port          int
	InterfaceName string
	PrivateKey    wgtypes.Key
	PublicKey     wgtypes.Key
	Address       string
	MTU           int
	DNS           string

	// wgClient removed as it depends on wgctrl which is broken on FreeBSD
	peers      sync.Map
	limiterRef *limiter.Limiter
	running    atomic.Bool

	trafficMu sync.RWMutex
	traffic   map[int]*UserTraffic
}

// NewWireGuardCore creates a new WireGuard VPN server
func NewWireGuardCore(tag string, port int, address string, interfaceName string, mtu int, dns string, privateKeyStr string) (*WireGuardCore, error) {
	return nil, fmt.Errorf("WireGuard is not supported on FreeBSD in this version")
}

// Start starts the WireGuard server
func (w *WireGuardCore) Start() error {
	return fmt.Errorf("WireGuard is not supported on FreeBSD")
}

// Stop stops the WireGuard server
func (w *WireGuardCore) Stop() error {
	return nil
}

// AddUsers adds users as peers to the WireGuard interface
func (w *WireGuardCore) AddUsers(users []panel.UserInfo) {
}

// DelUsers removes users from the WireGuard interface
func (w *WireGuardCore) DelUsers(users []panel.UserInfo) {
}

// GetTrafficAndReset returns traffic stats and resets counters
func (w *WireGuardCore) GetTrafficAndReset() map[int]*UserTraffic {
	return make(map[int]*UserTraffic)
}

// GetOnlineUsers returns list of currently connected users
func (w *WireGuardCore) GetOnlineUsers() []panel.OnlineUser {
	return []panel.OnlineUser{}
}

// SetLimiter sets the limiter reference for device/speed limiting
func (w *WireGuardCore) SetLimiter(l *limiter.Limiter) {
	w.limiterRef = l
}

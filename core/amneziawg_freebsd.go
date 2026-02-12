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

// AmneziaWGCore manages a AmneziaWG VPN server (Stub for FreeBSD)
type AmneziaWGCore struct {
	Tag           string
	Port          int
	InterfaceName string
	PrivateKey    wgtypes.Key
	PublicKey     wgtypes.Key
	Address       string
	MTU           int
	DNS           string

	// Amnezia Params
	Jc   int
	Jmin int
	Jmax int
	S1   int
	S2   int
	H1   int
	H2   int
	H3   int
	H4   int

	peers      sync.Map
	limiterRef *limiter.Limiter
	running    atomic.Bool

	trafficMu sync.RWMutex
	traffic   map[int]*UserTraffic
}

// NewAmneziaWGCore creates a new AmneziaWG VPN server
func NewAmneziaWGCore(tag string, port int, address string, interfaceName string, mtu int, dns string, privateKeyStr string, jc, jmin, jmax, s1, s2, h1, h2, h3, h4 int) (*AmneziaWGCore, error) {
	return nil, fmt.Errorf("AmneziaWG is not supported on FreeBSD")
}

// Start starts the AmneziaWG server
func (w *AmneziaWGCore) Start() error {
	return fmt.Errorf("AmneziaWG is not supported on FreeBSD")
}

// Stop stops the AmneziaWG server
func (w *AmneziaWGCore) Stop() error {
	return nil
}

// AddUsers adds users as peers to the AmneziaWG interface
func (w *AmneziaWGCore) AddUsers(users []panel.UserInfo) {
}

// DelUsers removes users from the AmneziaWG interface
func (w *AmneziaWGCore) DelUsers(users []panel.UserInfo) {
}

// GetTrafficAndReset returns traffic stats and resets counters
func (w *AmneziaWGCore) GetTrafficAndReset() map[int]*UserTraffic {
	return make(map[int]*UserTraffic)
}

// GetOnlineUsers returns list of currently connected users
func (w *AmneziaWGCore) GetOnlineUsers() []panel.OnlineUser {
	return []panel.OnlineUser{}
}

// SetLimiter sets the limiter reference for device/speed limiting
func (w *AmneziaWGCore) SetLimiter(l *limiter.Limiter) {
	w.limiterRef = l
}

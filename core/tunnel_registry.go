package core

import (
	"sync"
)

// TunnelUser stores identity attributes for a user connecting through a tunnel
// interface (WireGuard, OpenVPN, IPsec) intercepted via TPROXY.
type TunnelUser struct {
	UID  int
	UUID string
	Tag  string
}

var (
	tunnelIPMap sync.Map // key: string (IP literal), value: TunnelUser
)

// RegisterTunnelUser records an internal tunnel IP to user mapping.
func RegisterTunnelUser(ip string, uid int, uuid string, tag string) {
	if ip == "" {
		return
	}
	tunnelIPMap.Store(ip, TunnelUser{
		UID:  uid,
		UUID: uuid,
		Tag:  tag,
	})
}

// UnregisterTunnelUser removes an internal tunnel IP mapping.
func UnregisterTunnelUser(ip string) {
	if ip == "" {
		return
	}
	tunnelIPMap.Delete(ip)
}

// LookupTunnelUser looks up user identity attributes for an internal tunnel IP.
func LookupTunnelUser(ip string) (TunnelUser, bool) {
	if ip == "" {
		return TunnelUser{}, false
	}
	if v, ok := tunnelIPMap.Load(ip); ok {
		return v.(TunnelUser), true
	}
	return TunnelUser{}, false
}

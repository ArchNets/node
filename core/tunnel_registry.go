package core

import (
	"sync"
)

// TunnelUser stores identity attributes for a user connecting through a tunnel
// interface (WireGuard, OpenVPN, IPsec) intercepted via TPROXY.
type TunnelUser struct {
	UID      int
	UUID     string
	Tag      string
	ClientIP string // Real external IP of the connecting client (e.g. from WireGuard endpoint or OpenVPN remote)
}

var (
	tunnelIPMap sync.Map // key: string (internal IP literal), value: TunnelUser
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

// UpdateTunnelUserEndpoint updates the real external client IP for an internal tunnel IP.
func UpdateTunnelUserEndpoint(internalIP string, externalClientIP string) {
	if internalIP == "" || externalClientIP == "" {
		return
	}
	if v, ok := tunnelIPMap.Load(internalIP); ok {
		tu := v.(TunnelUser)
		tu.ClientIP = externalClientIP
		tunnelIPMap.Store(internalIP, tu)
	}
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

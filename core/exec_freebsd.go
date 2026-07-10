//go:build freebsd

package core

import (
	"fmt"
	"sync"
)

// execMu is a no-op on FreeBSD — the functions below always return an error,
// but the variable must exist so openvpn.go compiles.
var execMu sync.Mutex

// execCommand is a stub on FreeBSD where iptables/ip-link are unavailable.
func execCommand(cmd string) error {
	return fmt.Errorf("execCommand not supported on FreeBSD: %s", cmd)
}

// getDefaultInterface is a stub on FreeBSD.
func getDefaultInterface() (string, error) {
	return "", fmt.Errorf("getDefaultInterface not supported on FreeBSD")
}

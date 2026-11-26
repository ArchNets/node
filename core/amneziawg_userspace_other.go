//go:build !linux && !freebsd

package core

import "fmt"

func createAWGUserspace(interfaceName string, mtu int) (awgUserspace, error) {
	return nil, fmt.Errorf("userspace amneziawg-go is only supported on Linux")
}

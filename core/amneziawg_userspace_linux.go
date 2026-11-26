//go:build linux

package core

import (
	"fmt"
	"net"
	"os"
	"sync"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/ipc"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
)

type linuxAWGUserspace struct {
	dev      *device.Device
	uapi     net.Listener
	iface    string
	closeOnce sync.Once
}

func createAWGUserspace(interfaceName string, mtu int) (awgUserspace, error) {
	if mtu <= 0 {
		mtu = device.DefaultMTU
	}
	tdev, err := tun.CreateTUN(interfaceName, mtu)
	if err != nil {
		return nil, fmt.Errorf("create TUN %s: %w", interfaceName, err)
	}

	logger := device.NewLogger(device.LogLevelError, fmt.Sprintf("(%s) ", interfaceName))
	dev := device.NewDevice(tdev, conn.NewDefaultBind(), logger)

	// Expose UAPI unix socket (best-effort) so external tools like `awg show` also work
	var uapi net.Listener
	if fileUAPI, err := ipc.UAPIOpen(interfaceName); err == nil {
		if ln, err := ipc.UAPIListen(interfaceName, fileUAPI); err == nil {
			uapi = ln
			go func() {
				for {
					c, err := ln.Accept()
					if err != nil {
						return
					}
					go dev.IpcHandle(c)
				}
			}()
		} else {
			_ = fileUAPI.Close()
		}
	}

	return &linuxAWGUserspace{
		dev:   dev,
		uapi:  uapi,
		iface: interfaceName,
	}, nil
}

func (u *linuxAWGUserspace) ipcSet(conf string) error {
	return u.dev.IpcSet(conf)
}

func (u *linuxAWGUserspace) ipcGet() (string, error) {
	return u.dev.IpcGet()
}

func (u *linuxAWGUserspace) up() error {
	return u.dev.Up()
}

func (u *linuxAWGUserspace) close() {
	u.closeOnce.Do(func() {
		if u.uapi != nil {
			_ = u.uapi.Close()
		}
		if u.dev != nil {
			u.dev.Close()
		}
		_ = os.Remove(fmt.Sprintf("/var/run/amneziawg/%s.sock", u.iface))
	})
}

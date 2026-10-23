package node

import (
	"sync"

	"github.com/archnets/node/api/panel"
)

// TunnelDriver defines the pluggable lifecycle and metrics collection interface
// for any current or future tunnel method in archnet-node.
type TunnelDriver interface {
	// Start initializes and launches the tunnel instance.
	Start(t panel.TunnelInfo) error

	// Stop cleanly terminates a running tunnel instance by ID.
	Stop(tunnelId int) error

	// CollectStats retrieves real-time metrics, throughput, and status for the tunnel.
	CollectStats(t panel.TunnelInfo, pingLatency int, pingOnline bool) (panel.TunnelStatus, bool)

	// StopAll cleanly tears down all active instances managed by this driver.
	StopAll()
}

var (
	driversMu sync.RWMutex
	drivers   = make(map[string]TunnelDriver)
)

// RegisterTunnelDriver registers a pluggable driver for a given method identifier.
func RegisterTunnelDriver(method string, driver TunnelDriver) {
	driversMu.Lock()
	defer driversMu.Unlock()
	drivers[method] = driver
}

// GetTunnelDriver retrieves the registered driver for a method name.
func GetTunnelDriver(method string) TunnelDriver {
	driversMu.RLock()
	defer driversMu.RUnlock()
	if d, ok := drivers[method]; ok {
		return d
	}
	return nil
}

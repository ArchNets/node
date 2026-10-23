//go:build !linux

package transport

import "fmt"

type ProcessHolder struct {
	PID     int
	Comm    string
	Cmdline string
}

func DiagnosePortOccupant(port int) (*ProcessHolder, error) {
	return nil, nil
}

func FormatPortConflictError(port int, bindErr error) error {
	return fmt.Errorf("port %d already in use: %w", port, bindErr)
}

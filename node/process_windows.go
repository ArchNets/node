//go:build windows
// +build windows

package node

import (
	"os/exec"
)

func setProcessGroup(cmd *exec.Cmd) {
	// Windows doesn't use PGID in the same way as Unix.
	// For now, this is a no-op to fix build errors.
}

func killProcessGroup(cmd *exec.Cmd) {
	if cmd != nil && cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
}

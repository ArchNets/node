//go:build windows
// +build windows

package core

import (
	"errors"
	"os"
)

func (m *NipovpnManager) Start() error {
	// NipoVPN is not supported on Windows
	return errors.New("nipovpn is not supported on Windows")
}

func (m *NipovpnManager) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.cmd != nil && m.cmd.Process != nil {
		_ = m.cmd.Process.Kill()
		_ = m.cmd.Wait()
		m.cmd = nil
	}
	m.started = false
	if m.cfgPath != "" {
		_ = os.Remove(m.cfgPath)
	}
}

func (m *NipovpnManager) IsAlive() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.started
}

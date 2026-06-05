//go:build !windows
// +build !windows

package core

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

func (m *NipovpnManager) Start() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, err := os.Stat(NipovpnBinary); os.IsNotExist(err) {
		return fmt.Errorf("nipovpn binary not found at %s", NipovpnBinary)
	}

	// The database role is entry or exit, but nipovpn expects agent or server
	mode := "agent"
	if m.tunnel.Role == "exit" {
		mode = "server"
	}

	m.cmd = exec.Command(NipovpnBinary, mode, m.cfgPath)
	m.cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	if err := m.cmd.Start(); err != nil {
		return err
	}
	m.started = true

	go func() {
		_ = m.cmd.Wait()
		m.mu.Lock()
		m.started = false
		m.mu.Unlock()
	}()

	return nil
}

func (m *NipovpnManager) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.cmd != nil && m.cmd.Process != nil {
		pgid, err := syscall.Getpgid(m.cmd.Process.Pid)
		if err == nil {
			_ = syscall.Kill(-pgid, syscall.SIGTERM)
		}
		m.cmd.Process.Kill()
		m.cmd.Wait()
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
	if !m.started || m.cmd == nil || m.cmd.Process == nil {
		return false
	}
	return m.cmd.Process.Signal(syscall.Signal(0)) == nil
}

//go:build linux

package transport

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// ProcessHolder describes a process holding a local network port.
type ProcessHolder struct {
	PID     int
	Comm    string
	Cmdline string
}

// DiagnosePortOccupant searches Linux /proc to find which process is listening on the given TCP port.
func DiagnosePortOccupant(port int) (*ProcessHolder, error) {
	if port <= 0 || port > 65535 {
		return nil, fmt.Errorf("invalid port %d", port)
	}

	hexPort := fmt.Sprintf(":%04X", port)
	inodes := findSocketInodes(hexPort)
	if len(inodes) == 0 {
		return nil, nil
	}

	return findProcessBySocketInodes(inodes)
}

func findSocketInodes(hexPort string) map[string]struct{} {
	inodes := make(map[string]struct{})
	for _, procFile := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		f, err := os.Open(procFile)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			fields := strings.Fields(line)
			if len(fields) >= 10 {
				localAddr := fields[1]
				if strings.HasSuffix(localAddr, hexPort) {
					inode := fields[9]
					if inode != "0" && inode != "" {
						inodes[inode] = struct{}{}
					}
				}
			}
		}
		_ = f.Close()
	}
	return inodes
}

func findProcessBySocketInodes(inodes map[string]struct{}) (*ProcessHolder, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}

		fdDir := filepath.Join("/proc", entry.Name(), "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}

		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil {
				continue
			}
			for inode := range inodes {
				target := "socket:[" + inode + "]"
				if link == target {
					commBytes, _ := os.ReadFile(filepath.Join("/proc", entry.Name(), "comm"))
					cmdlineBytes, _ := os.ReadFile(filepath.Join("/proc", entry.Name(), "cmdline"))
					comm := strings.TrimSpace(string(commBytes))
					cmdline := strings.ReplaceAll(strings.TrimSpace(string(cmdlineBytes)), "\x00", " ")
					return &ProcessHolder{
						PID:     pid,
						Comm:    comm,
						Cmdline: cmdline,
					}, nil
				}
			}
		}
	}
	return nil, nil
}

// FormatPortConflictError generates a user-friendly diagnostic message when a port bind fails.
func FormatPortConflictError(port int, bindErr error) error {
	holder, _ := DiagnosePortOccupant(port)
	if holder != nil {
		return fmt.Errorf("port %d already in use by process %q (PID: %d, cmd: %q): %w",
			port, holder.Comm, holder.PID, holder.Cmdline, bindErr)
	}
	return fmt.Errorf("port %d already in use (bind refused): %w", port, bindErr)
}

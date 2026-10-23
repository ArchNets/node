package transport

import (
	"net"
	"strconv"
	"strings"
	"testing"
)

func TestPortConflictDiagnosis(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen on test port: %v", err)
	}
	defer ln.Close()

	port := ln.Addr().(*net.TCPAddr).Port

	// Diagnose process occupying the port
	holder, err := DiagnosePortOccupant(port)
	if err != nil {
		t.Logf("DiagnosePortOccupant returned error (non-fatal if /proc unreadable): %v", err)
	} else if holder != nil {
		t.Logf("Successfully diagnosed port %d occupant: PID %d, Comm %q", port, holder.PID, holder.Comm)
	}

	// Try listening again to induce bind error
	_, bindErr := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(port))
	if bindErr == nil {
		t.Fatal("expected bind error on already used port")
	}

	formattedErr := FormatPortConflictError(port, bindErr)
	if !strings.Contains(formattedErr.Error(), "already in use") {
		t.Fatalf("expected formatted error to mention already in use, got: %v", formattedErr)
	}
	t.Logf("Formatted conflict error: %v", formattedErr)
}

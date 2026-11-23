package filesystem

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

func TestSanitizePath(t *testing.T) {
	tests := []struct {
		name             string
		raw              string
		allowEmptyAsRoot bool
		want             string
		wantErr          bool
	}{
		{name: "empty disallowed", raw: "", allowEmptyAsRoot: false, wantErr: true},
		{name: "empty allowed as root", raw: "", allowEmptyAsRoot: true, want: "/"},
		{name: "relative path rejected", raw: "etc/passwd", wantErr: true},
		{name: "dotdot traversal rejected", raw: "/etc/../etc/passwd", wantErr: true},
		{name: "nul byte rejected", raw: "/tmp/a\x00b", wantErr: true},
		{name: "double dot inside filename allowed", raw: "/tmp/file..bak", want: "/tmp/file..bak"},
		{name: "root path", raw: "/", want: "/"},
		{name: "clean trailing slash", raw: "/var/log/", want: "/var/log"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := sanitizePath(tt.raw, tt.allowEmptyAsRoot)
			if (err != nil) != tt.wantErr {
				t.Fatalf("sanitizePath(%q) err=%v, wantErr=%v", tt.raw, err, tt.wantErr)
			}
			if !tt.wantErr && got != tt.want {
				t.Fatalf("sanitizePath(%q) = %q, want %q", tt.raw, got, tt.want)
			}
		})
	}
}

func TestListReadWriteDelete(t *testing.T) {
	tmpDir := t.TempDir()

	// Empty directory returns non-nil slice
	items, err := ListDirectory(tmpDir)
	if err != nil {
		t.Fatalf("ListDirectory empty failed: %v", err)
	}
	if items == nil || len(items) != 0 {
		t.Fatalf("expected non-nil empty slice, got %#v", items)
	}

	// Write text file in nested dir
	target := filepath.Join(tmpDir, "nested", "hello.txt")
	if err := WriteFile(target, "hello world", false); err != nil {
		t.Fatalf("WriteFile text failed: %v", err)
	}

	content, isBin, err := ReadFile(target)
	if err != nil {
		t.Fatalf("ReadFile text failed: %v", err)
	}
	if isBin || content != "hello world" {
		t.Fatalf("unexpected ReadFile result: isBin=%v content=%q", isBin, content)
	}

	// Preserve existing 0600 permissions on overwrite
	if err := os.Chmod(target, 0600); err != nil {
		t.Fatalf("Chmod failed: %v", err)
	}
	if err := WriteFile(target, "updated secret", false); err != nil {
		t.Fatalf("WriteFile overwrite failed: %v", err)
	}
	info, err := os.Stat(target)
	if err != nil {
		t.Fatalf("Stat failed: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("expected mode 0600 preserved, got %o", info.Mode().Perm())
	}

	// Binary base64 roundtrip
	binTarget := filepath.Join(tmpDir, "bin.dat")
	rawBin := []byte{0x00, 0x01, 0x02, 0xff}
	if err := WriteFile(binTarget, base64.StdEncoding.EncodeToString(rawBin), true); err != nil {
		t.Fatalf("WriteFile binary failed: %v", err)
	}
	gotBin, isBin, err := ReadFile(binTarget)
	if err != nil || !isBin || gotBin != base64.StdEncoding.EncodeToString(rawBin) {
		t.Fatalf("ReadFile binary mismatch: err=%v isBin=%v got=%q", err, isBin, gotBin)
	}

	// Reject deleting protected directories
	for _, p := range []string{"/", "/etc", "/etc/archnets", "/usr/local/archnets", "/var"} {
		if err := DeletePath(p); err == nil {
			t.Fatalf("expected DeletePath(%q) to fail", p)
		}
	}

	// Reject writing to /proc and /
	if err := WriteFile("/proc/test", "x", false); err == nil {
		t.Fatal("expected WriteFile to /proc/test to fail")
	}
	if err := WriteFile("/", "x", false); err == nil {
		t.Fatal("expected WriteFile to / to fail")
	}

	// Delete file succeeds
	if err := DeletePath(target); err != nil {
		t.Fatalf("DeletePath failed: %v", err)
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatalf("expected %s to be deleted", target)
	}
}

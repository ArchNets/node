package filesystem

import (
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	maxReadBytes = 5 * 1024 * 1024 // 5MB limit for inline viewing/editing
	maxListItems = 5000
)

// protectedDeletePaths cannot be deleted via the remote filesystem API.
var protectedDeletePaths = map[string]struct{}{
	"/":                   {},
	"/bin":                {},
	"/boot":               {},
	"/dev":                {},
	"/etc":                {},
	"/etc/archnets":       {},
	"/etc/systemd":        {},
	"/home":               {},
	"/lib":                {},
	"/lib64":              {},
	"/opt":                {},
	"/proc":               {},
	"/root":               {},
	"/run":                {},
	"/sbin":               {},
	"/sys":                {},
	"/tmp":                {},
	"/usr":                {},
	"/usr/local":          {},
	"/usr/local/archnets": {},
	"/var":                {},
	"/var/log":            {},
}

var blockedWritePrefixes = []string{
	"/proc/",
	"/sys/",
	"/dev/",
}

// sanitizePath validates and normalizes a caller-supplied filesystem path.
// It rejects NUL bytes, relative paths, and any ".." traversal segments,
// and ensures the resulting cleaned path stays anchored under "/".
func sanitizePath(rawPath string, allowEmptyAsRoot bool) (string, error) {
	if rawPath == "" {
		if allowEmptyAsRoot {
			return "/", nil
		}
		return "", fmt.Errorf("path cannot be empty")
	}
	if strings.ContainsRune(rawPath, 0) {
		return "", fmt.Errorf("path contains NUL byte")
	}
	if !filepath.IsAbs(rawPath) {
		return "", fmt.Errorf("path must be absolute: %q", rawPath)
	}
	for _, seg := range strings.Split(filepath.ToSlash(rawPath), "/") {
		if seg == ".." {
			return "", fmt.Errorf("path traversal ('..') is not allowed")
		}
	}

	cleanPath := filepath.Clean(rawPath)
	rel, err := filepath.Rel("/", cleanPath)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("invalid path outside root")
	}
	if rel == "." {
		return "/", nil
	}
	safePath := filepath.Join("/", rel)
	if !strings.HasPrefix(safePath, "/") {
		return "", fmt.Errorf("invalid resolved path")
	}
	return safePath, nil
}

// FileItem describes a file or directory entry.
type FileItem struct {
	Name       string `json:"name"`
	Path       string `json:"path"`
	IsDir      bool   `json:"is_dir"`
	Size       int64  `json:"size"`
	Mode       string `json:"mode"`
	ModifiedAt int64  `json:"modified_at"`
}

// ListDirectory lists files in the given path (defaults to "/").
func ListDirectory(dirPath string) ([]FileItem, error) {
	safePath, err := sanitizePath(dirPath, true)
	if err != nil {
		return nil, err
	}

	entries, err := os.ReadDir(safePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read directory: %w", err)
	}

	items := make([]FileItem, 0, min(len(entries), maxListItems))
	for _, entry := range entries {
		if len(items) >= maxListItems {
			break
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}

		items = append(items, FileItem{
			Name:       entry.Name(),
			Path:       filepath.Join(safePath, entry.Name()),
			IsDir:      entry.IsDir(),
			Size:       info.Size(),
			Mode:       info.Mode().String(),
			ModifiedAt: info.ModTime().Unix(),
		})
	}
	return items, nil
}

// ReadFile reads up to 5MB of a regular file and returns its contents.
func ReadFile(filePath string) (content string, isBinary bool, err error) {
	safePath, err := sanitizePath(filePath, false)
	if err != nil {
		return "", false, err
	}

	info, err := os.Stat(safePath)
	if err != nil {
		return "", false, err
	}
	if info.IsDir() {
		return "", false, fmt.Errorf("path is a directory")
	}
	if !info.Mode().IsRegular() {
		return "", false, fmt.Errorf("path is not a regular file")
	}
	if info.Size() > maxReadBytes {
		return "", false, fmt.Errorf("file size exceeds 5MB limit for preview/editing")
	}

	f, err := os.Open(safePath)
	if err != nil {
		return "", false, err
	}
	defer f.Close()

	data, err := io.ReadAll(io.LimitReader(f, maxReadBytes+1))
	if err != nil {
		return "", false, err
	}
	if len(data) > maxReadBytes {
		return "", false, fmt.Errorf("file size exceeds 5MB limit for preview/editing")
	}

	// Check if binary
	for i, b := range data {
		if i > 512 {
			break
		}
		if b == 0 {
			return base64.StdEncoding.EncodeToString(data), true, nil
		}
	}

	return string(data), false, nil
}

// WriteFile writes string or base64 data atomically to an absolute file path.
func WriteFile(filePath string, content string, isBase64 bool) error {
	safePath, err := sanitizePath(filePath, false)
	if err != nil {
		return err
	}
	if safePath == "/" {
		return fmt.Errorf("refusing to write to root directory")
	}
	for _, prefix := range blockedWritePrefixes {
		if safePath == strings.TrimSuffix(prefix, "/") || strings.HasPrefix(safePath, prefix) {
			return fmt.Errorf("refusing to write to virtual filesystem path %q", safePath)
		}
	}

	var data []byte
	if isBase64 {
		data, err = base64.StdEncoding.DecodeString(content)
		if err != nil {
			return fmt.Errorf("invalid base64 content: %w", err)
		}
	} else {
		data = []byte(content)
	}

	parentDir := filepath.Dir(safePath)
	if parentDir == "" || parentDir == "." {
		return fmt.Errorf("invalid parent directory")
	}
	if err := os.MkdirAll(parentDir, 0755); err != nil {
		return err
	}

	// Preserve existing regular-file permissions (e.g. 0600 keys or 0755 scripts)
	fileMode := os.FileMode(0644)
	if info, statErr := os.Stat(safePath); statErr == nil {
		if info.IsDir() {
			return fmt.Errorf("target path is a directory")
		}
		if info.Mode().IsRegular() {
			fileMode = info.Mode().Perm()
		}
	}

	tmpFile, err := os.CreateTemp(parentDir, fmt.Sprintf(".archnet-%d-*.tmp", time.Now().UnixNano()))
	if err != nil {
		return err
	}
	tmpPath := tmpFile.Name()
	cleanupTmp := true
	defer func() {
		if cleanupTmp {
			_ = os.Remove(tmpPath)
		}
	}()

	if _, err := tmpFile.Write(data); err != nil {
		_ = tmpFile.Close()
		return err
	}
	if err := tmpFile.Chmod(fileMode); err != nil {
		_ = tmpFile.Close()
		return err
	}
	if err := tmpFile.Sync(); err != nil {
		_ = tmpFile.Close()
		return err
	}
	if err := tmpFile.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, safePath); err != nil {
		return err
	}
	cleanupTmp = false
	return nil
}

// DeletePath removes a file or directory, refusing protected system directories.
func DeletePath(filePath string) error {
	safePath, err := sanitizePath(filePath, false)
	if err != nil {
		return err
	}
	if _, protected := protectedDeletePaths[safePath]; protected {
		return fmt.Errorf("refusing to delete protected system directory %q", safePath)
	}
	if resolved, evalErr := filepath.EvalSymlinks(safePath); evalErr == nil {
		if _, protected := protectedDeletePaths[resolved]; protected {
			return fmt.Errorf("refusing to delete protected system directory %q", resolved)
		}
	}
	return os.RemoveAll(safePath)
}

package filesystem

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// FileItem describes a file or directory entry
type FileItem struct {
	Name       string `json:"name"`
	Path       string `json:"path"`
	IsDir      bool   `json:"is_dir"`
	Size       int64  `json:"size"`
	Mode       string `json:"mode"`
	ModifiedAt int64  `json:"modified_at"`
}

// ListDirectory lists files in the given path (defaults to /)
func ListDirectory(dirPath string) ([]FileItem, error) {
	if dirPath == "" {
		dirPath = "/"
	}
	cleanPath := filepath.Clean(dirPath)

	entries, err := os.ReadDir(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read directory: %w", err)
	}

	var items []FileItem
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			continue
		}

		fullPath := filepath.Join(cleanPath, entry.Name())
		items = append(items, FileItem{
			Name:       entry.Name(),
			Path:       fullPath,
			IsDir:      entry.IsDir(),
			Size:       info.Size(),
			Mode:       info.Mode().String(),
			ModifiedAt: info.ModTime().Unix(),
		})
	}
	return items, nil
}

// ReadFile reads up to 5MB of a file and returns contents
func ReadFile(filePath string) (content string, isBinary bool, err error) {
	cleanPath := filepath.Clean(filePath)
	info, err := os.Stat(cleanPath)
	if err != nil {
		return "", false, err
	}
	if info.IsDir() {
		return "", false, fmt.Errorf("path is a directory")
	}

	// 5MB limit for inline viewing/editing
	if info.Size() > 5*1024*1024 {
		return "", false, fmt.Errorf("file size exceeds 5MB limit for preview/editing")
	}

	data, err := os.ReadFile(cleanPath)
	if err != nil {
		return "", false, err
	}

	// Check if binary
	for i, b := range data {
		if i > 512 {
			break
		}
		if b == 0 {
			// Binary file - return base64 encoded
			return base64.StdEncoding.EncodeToString(data), true, nil
		}
	}

	return string(data), false, nil
}

// WriteFile writes string or base64 data to a file path
func WriteFile(filePath string, content string, isBase64 bool) error {
	cleanPath := filepath.Clean(filePath)

	var data []byte
	var err error
	if isBase64 {
		data, err = base64.StdEncoding.DecodeString(content)
		if err != nil {
			return fmt.Errorf("invalid base64 content: %w", err)
		}
	} else {
		data = []byte(content)
	}

	// Ensure parent directory exists
	if err := os.MkdirAll(filepath.Dir(cleanPath), 0755); err != nil {
		return err
	}

	// Write atomically via temporary file
	tmpFile := cleanPath + fmt.Sprintf(".tmp-%d", time.Now().UnixNano())
	if err := os.WriteFile(tmpFile, data, 0644); err != nil {
		return err
	}
	return os.Rename(tmpFile, cleanPath)
}

// DeletePath removes a file or empty directory
func DeletePath(filePath string) error {
	cleanPath := filepath.Clean(filePath)
	if cleanPath == "/" || cleanPath == "/root" || cleanPath == "/etc" || cleanPath == "/bin" {
		return fmt.Errorf("refusing to delete protected system root directory")
	}
	return os.RemoveAll(cleanPath)
}

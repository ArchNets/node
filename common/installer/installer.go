package installer

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	log "github.com/sirupsen/logrus"
)

// Binary URLs
const (
	GostInstallURL = "https://github.com/go-gost/gost/releases/latest/download/gost-linux-amd64.gz"
)

// getLatestWaterwallVersion fetches the latest version tag from GitHub API
func getLatestWaterwallVersion() (string, error) {
	resp, err := http.Get("https://api.github.com/repos/radkesvat/WaterWall/releases/latest")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GitHub API returned status %d", resp.StatusCode)
	}

	var release struct {
		TagName string `json:"tag_name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return "", err
	}
	return release.TagName, nil // Keep the v prefix for WaterWall URLs
}

// getLatestNodepassVersion fetches the latest version tag from GitHub API
func getLatestNodepassVersion() (string, error) {
	resp, err := http.Get("https://api.github.com/repos/NodePassProject/nodepass/releases/latest")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GitHub API returned status %d", resp.StatusCode)
	}

	var release struct {
		TagName string `json:"tag_name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return "", err
	}

	// Remove 'v' prefix if present
	version := strings.TrimPrefix(release.TagName, "v")
	return version, nil
}

// getLatestPaqetVersion fetches the latest version tag from GitHub API
func getLatestPaqetVersion() (string, error) {
	resp, err := http.Get("https://api.github.com/repos/hanselime/paqet/releases/latest")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GitHub API returned status %d", resp.StatusCode)
	}

	var release struct {
		TagName string `json:"tag_name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return "", err
	}
	return release.TagName, nil
}

// detectWaterwallVariant detects the appropriate WaterWall variant for this system
// Returns: "clang-x64", "gcc-x64-old-cpu", or "gcc-arm64"
func detectWaterwallVariant() string {
	arch := runtime.GOARCH

	if arch == "arm64" {
		return "gcc-arm64"
	}

	// For amd64, check if CPU supports AVX (old CPUs don't)
	if hasAVXSupport() {
		return "clang-x64"
	}
	return "gcc-x64-old-cpu"
}

// hasAVXSupport checks if the CPU supports AVX instructions
func hasAVXSupport() bool {
	// Read /proc/cpuinfo and check for avx flag
	data, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		log.Warnf("Could not read /proc/cpuinfo, assuming old CPU: %v", err)
		return false // Assume old CPU if we cant detect
	}

	content := string(data)
	// Check for AVX in the flags line
	for _, line := range strings.Split(content, "\n") {
		if strings.HasPrefix(line, "flags") {
			return strings.Contains(line, " avx ")
		}
	}
	return false
}

// InstallWaterwall downloads and installs Waterwall to the specified directory
func InstallWaterwall(destDir string) error {
	log.Infof("Installing Waterwall to %s", destDir)
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return err
	}

	// Get latest version
	version, err := getLatestWaterwallVersion()
	if err != nil {
		log.Warnf("Failed to fetch latest WaterWall version, using fallback: %v", err)
		version = "v1.41" // Fallback version
	}

	// Detect appropriate variant
	variant := detectWaterwallVariant()
	log.Infof("Detected WaterWall variant: %s", variant)

	// Build download URL: https://github.com/radkesvat/WaterWall/releases/download/v1.41/Waterwall-linux-clang-x64.zip
	downloadURL := fmt.Sprintf("https://github.com/radkesvat/WaterWall/releases/download/%s/Waterwall-linux-%s.zip", version, variant)
	log.Infof("Downloading WaterWall %s from %s", version, downloadURL)

	zipPath := filepath.Join(destDir, "waterwall.zip")
	if err := DownloadFile(downloadURL, zipPath); err != nil {
		return err
	}
	defer os.Remove(zipPath)

	if err := Unzip(zipPath, destDir); err != nil {
		return err
	}

	// Ensure permissions
	binaryPath := filepath.Join(destDir, "Waterwall")
	return os.Chmod(binaryPath, 0755)
}

// InstallGost downloads and installs Gost to /usr/local/bin
func InstallGost() error {
	dest := "/usr/local/bin/gost"
	log.Infof("Installing Gost to %s", dest)

	gzPath := dest + ".gz"
	if err := DownloadFile(GostInstallURL, gzPath); err != nil {
		return err
	}
	defer os.Remove(gzPath)

	if err := Ungzip(gzPath, dest); err != nil {
		return err
	}

	return os.Chmod(dest, 0755)
}

// InstallNodepass downloads and installs the latest Nodepass to /usr/local/bin
func InstallNodepass() error {
	dest := "/usr/local/bin/nodepass"
	log.Infof("Installing Nodepass to %s", dest)

	// Fetch latest version from GitHub API
	version, err := getLatestNodepassVersion()
	if err != nil {
		log.Warnf("Failed to fetch latest nodepass version, using fallback: %v", err)
		version = "1.15.0" // Fallback version
	}

	nodepassURL := fmt.Sprintf("https://github.com/NodePassProject/nodepass/releases/download/v%s/nodepass_%s_linux_amd64.tar.gz", version, version)
	log.Infof("Downloading NodePass v%s", version)

	tarGzPath := dest + ".tar.gz"
	if err := DownloadFile(nodepassURL, tarGzPath); err != nil {
		return err
	}
	defer os.Remove(tarGzPath)

	// Extract nodepass from tar.gz
	file, err := os.Open(tarGzPath)
	if err != nil {
		return err
	}
	defer file.Close()

	gr, err := gzip.NewReader(file)
	if err != nil {
		return err
	}
	defer gr.Close()

	// Simple extraction for nodepass (expecting it at the root of tar)
	// In a real scenario we'd use archive/tar, but for a single file this is often simpler if we know the structure.
	// However, let's just use a proper Ungzip or Untar if needed.
	// Nodepass is usually a tar.gz containing the binary.

	// For simplicity and robustness, let's use a temporary directory for extraction
	tmpDir, err := os.MkdirTemp("", "nodepass-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpDir)

	// Actually Nodepass tar.gz contains multiple files. We need the one named 'nodepass'
	// I'll implement a helper to extract a specific file from tar.gz
	return ExtractFromTarGz(tarGzPath, "nodepass", dest)
}

// InstallPaqet downloads and installs Paqet to /usr/local/bin
func InstallPaqet() error {
	dest := "/usr/local/bin/paqet"
	log.Infof("Installing Paqet to %s", dest)

	version, err := getLatestPaqetVersion()
	if err != nil {
		log.Warnf("Failed to fetch latest Paqet version, using fallback: %v", err)
		version = "v1.0.0"
	}

	// Detect architecture
	var archName string
	switch runtime.GOARCH {
	case "amd64":
		archName = "amd64"
	case "arm64":
		archName = "arm64"
	case "arm":
		archName = "arm32"
	case "386":
		archName = "386"
	default:
		return fmt.Errorf("unsupported architecture: %s", runtime.GOARCH)
	}

	// URL format: https://github.com/hanselime/paqet/releases/download/${version}/paqet-linux-${arch}-${version}.tar.gz
	filename := fmt.Sprintf("paqet-linux-%s-%s.tar.gz", archName, version)
	downloadURL := fmt.Sprintf("https://github.com/hanselime/paqet/releases/download/%s/%s", version, filename)

	log.Infof("Downloading Paqet %s from %s", version, downloadURL)

	tarGzPath := dest + ".tar.gz"
	if err := DownloadFile(downloadURL, tarGzPath); err != nil {
		return err
	}
	defer os.Remove(tarGzPath)

	// Extract to temp dir to find the binary
	tmpDir, err := os.MkdirTemp("", "paqet-install-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpDir)

	if err := UntarGz(tarGzPath, tmpDir); err != nil {
		return fmt.Errorf("failed to extract paqet archive: %v", err)
	}

	// Find binary
	// Script looks for paqet_${os}_${arch} or paqet
	possibleNames := []string{
		fmt.Sprintf("paqet_linux_%s", archName),
		"paqet",
	}

	var foundPath string

	// First check direct matches in root of extraction
	for _, name := range possibleNames {
		p := filepath.Join(tmpDir, name)
		if _, err := os.Stat(p); err == nil {
			foundPath = p
			break
		}
	}

	// If not found, search recursively (like 'find' in the script)
	if foundPath == "" {
		err = filepath.Walk(tmpDir, func(path string, info os.FileInfo, err error) error {
			if foundPath != "" {
				return filepath.SkipDir // Stop if found
			}
			if err != nil {
				return err
			}
			if info.IsDir() {
				return nil
			}

			name := info.Name()
			if name == "paqet" || name == fmt.Sprintf("paqet_linux_%s", archName) {
				foundPath = path
				return filepath.SkipDir
			}
			return nil
		})
		if err != nil {
			log.Warnf("Error walking temp dir: %v", err)
		}
	}

	if foundPath == "" {
		return fmt.Errorf("paqet binary not found in downloaded archive")
	}

	// Move to dest
	// Check if dest exists
	if _, err := os.Stat(dest); err == nil {
		os.Remove(dest)
	}

	if err := CopyFile(foundPath, dest); err != nil {
		return err
	}

	return os.Chmod(dest, 0755)
}

// CopyFile copies a file from src to dst
func CopyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	return err
}

// UntarGz extracts a .tar.gz file to a destination directory
func UntarGz(src string, dest string) error {
	file, err := os.Open(src)
	if err != nil {
		return err
	}
	defer file.Close()

	gr, err := gzip.NewReader(file)
	if err != nil {
		return err
	}
	defer gr.Close()

	tr := tar.NewReader(gr)

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		target := filepath.Join(dest, header.Name)

		// Prevent Zip Slip
		if !strings.HasPrefix(target, filepath.Clean(dest)+string(os.PathSeparator)) {
			return fmt.Errorf("illegal file path: %s", target)
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				return err
			}
			f, err := os.OpenFile(target, os.O_CREATE|os.O_RDWR, os.FileMode(header.Mode))
			if err != nil {
				return err
			}
			if _, err := io.Copy(f, tr); err != nil {
				f.Close()
				return err
			}
			f.Close()
		}
	}
	return nil
}

// DownloadFile downloads a URL to a local file
func DownloadFile(url string, filepath string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to download: status %d", resp.StatusCode)
	}

	out, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	return err
}

// Unzip extracts a zip file to the destination directory
func Unzip(src string, dest string) error {
	r, err := zip.OpenReader(src)
	if err != nil {
		return err
	}
	defer r.Close()

	for _, f := range r.File {
		fpath := filepath.Join(dest, f.Name)
		if !strings.HasPrefix(fpath, filepath.Clean(dest)+string(os.PathSeparator)) {
			return fmt.Errorf("illegal file path: %s", fpath)
		}

		if f.FileInfo().IsDir() {
			os.MkdirAll(fpath, os.ModePerm)
			continue
		}

		if err := os.MkdirAll(filepath.Dir(fpath), os.ModePerm); err != nil {
			return err
		}

		outFile, err := os.OpenFile(fpath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
		if err != nil {
			return err
		}

		rc, err := f.Open()
		if err != nil {
			outFile.Close()
			return err
		}

		_, err = io.Copy(outFile, rc)
		outFile.Close()
		rc.Close()

		if err != nil {
			return err
		}
	}
	return nil
}

// Ungzip extracts a .gz file to the destination path
func Ungzip(src string, dest string) error {
	file, err := os.Open(src)
	if err != nil {
		return err
	}
	defer file.Close()

	gr, err := gzip.NewReader(file)
	if err != nil {
		return err
	}
	defer gr.Close()

	out, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, gr)
	return err
}

// ExtractFromTarGz extracts a specific file from a .tar.gz archive
func ExtractFromTarGz(src string, targetFile string, dest string) error {
	file, err := os.Open(src)
	if err != nil {
		return err
	}
	defer file.Close()

	gr, err := gzip.NewReader(file)
	if err != nil {
		return err
	}
	defer gr.Close()

	tr := tar.NewReader(gr)

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		// Check if it's the target file (handle potential paths inside tar)
		if header.Typeflag == tar.TypeReg && (header.Name == targetFile || strings.HasSuffix(header.Name, "/"+targetFile)) {
			out, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0755)
			if err != nil {
				return err
			}
			defer out.Close()

			_, err = io.Copy(out, tr)
			return err
		}
	}

	return fmt.Errorf("target file %s not found in %s", targetFile, src)
}

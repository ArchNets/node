package installer

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	log "github.com/sirupsen/logrus"
)

// Binary URLs (Latest releases as of now)
const (
	WaterwallZipURL = "https://github.com/radkesvat/WaterWall/releases/latest/download/Waterwall-linux-amd64.zip"
	NodepassURL     = "https://github.com/NodePassProject/nodepass/releases/download/v1.15.0/nodepass_1.15.0_linux_amd64.tar.gz"
	GostInstallURL  = "https://github.com/go-gost/gost/releases/latest/download/gost-linux-amd64.gz"
)

// InstallWaterwall downloads and installs Waterwall to the specified directory
func InstallWaterwall(destDir string) error {
	log.Infof("Installing Waterwall to %s", destDir)
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return err
	}

	zipPath := filepath.Join(destDir, "waterwall.zip")
	if err := DownloadFile(WaterwallZipURL, zipPath); err != nil {
		return err
	}
	defer os.Remove(zipPath)

	if err := Unzip(zipPath, destDir); err != nil {
		return err
	}

	// Rename according to usage in tunnel_controller (Waterwall with capital W)
	// The zip contains 'Waterwall' so it should be fine, but let's ensure permissions
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

// InstallNodepass downloads and installs Nodepass to /usr/local/bin
func InstallNodepass() error {
	dest := "/usr/local/bin/nodepass"
	log.Infof("Installing Nodepass to %s", dest)

	tarGzPath := dest + ".tar.gz"
	if err := DownloadFile(NodepassURL, tarGzPath); err != nil {
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

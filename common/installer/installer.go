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
	"os/exec"
	"path/filepath"
	"strings"

	log "github.com/sirupsen/logrus"
)

// Binary URLs
const (
	GostInstallURL = "https://github.com/go-gost/gost/releases/latest/download/gost-linux-amd64.gz"
)

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

	version, err := getLatestNodepassVersion()
	if err != nil {
		log.Warnf("Failed to fetch latest nodepass version, using fallback: %v", err)
		version = "1.15.0"
	}

	nodepassURL := fmt.Sprintf("https://github.com/NodePassProject/nodepass/releases/download/v%s/nodepass_%s_linux_amd64.tar.gz", version, version)
	log.Infof("Downloading NodePass v%s", version)

	tarGzPath := dest + ".tar.gz"
	if err := DownloadFile(nodepassURL, tarGzPath); err != nil {
		return err
	}
	defer os.Remove(tarGzPath)

	return ExtractFromTarGz(tarGzPath, "nodepass", dest)
}

// InstallSniSpoofing downloads and installs SNI-Spoofing to /usr/local/bin
func InstallSniSpoofing() error {
	dest := "/usr/local/bin/sni-spoofing"
	log.Infof("Installing SNI-Spoofing to %s", dest)

	// Since we only install sni-spoofing on the Iran side, we use the specific mirror
	downloadURL := "https://storage.archnets.com/linux/mirror/sni/sni-spoofing-linux-amd64"
	log.Infof("Downloading SNI-Spoofing from mirror: %s", downloadURL)

	if err := DownloadFile(downloadURL, dest); err != nil {
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

// InstallNipovpn downloads and installs NipoVPN from a .deb package
func InstallNipovpn() error {
	// Check if already installed
	if _, err := os.Stat("/usr/bin/nipovpn"); err == nil {
		log.Info("NipoVPN already installed at /usr/bin/nipovpn, skipping")
		return nil
	}
	if _, err := os.Stat("/usr/local/bin/nipovpn"); err == nil {
		log.Info("NipoVPN found at /usr/local/bin/nipovpn (old location), skipping")
		return nil
	}

	const version = "1.1.57"
	url := fmt.Sprintf("https://github.com/MortezaBashsiz/nipovpn/releases/download/v%s/nipovpn_%s_amd64.deb", version, version)
	log.Infof("Downloading NipoVPN v%s from %s", version, url)

	debPath := "/tmp/nipovpn.deb"
	if err := DownloadFile(url, debPath); err != nil {
		return fmt.Errorf("failed to download nipovpn .deb: %w", err)
	}
	defer os.Remove(debPath)

	cmd := exec.Command("apt", "install", "-y", debPath)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to install nipovpn .deb: %s, output: %s", err, string(out))
	}

	log.Info("NipoVPN installed successfully from .deb package")
	return nil
}

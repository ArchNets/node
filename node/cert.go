package node

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/archnets/node/api/panel"
	certutil "github.com/archnets/node/common/cert"
	"github.com/archnets/node/common/file"
	log "github.com/sirupsen/logrus"
)

func (c *Controller) renewCertTask() error {
	l, err := NewLego(c.info)
	if err != nil {
		log.WithField("node", c.tag).Info("new lego error: ", err)
		return nil
	}
	err = l.RenewCert()
	if err != nil {
		log.WithField("node", c.tag).Info("renew cert error: ", err)
		return nil
	}
	return nil
}

func (c *Controller) requestCert() error {
	_, _, err := EnsureNodeCertificate(c.info, c.tag)
	return err
}

// findExistingDomainCert checks if a certificate for the same SNI domain has already been
// provisioned in /etc/archnets/ by another protocol or tunnel on this server.
func findExistingDomainCert(sni string) (string, string, bool) {
	if sni == "" {
		return "", "", false
	}
	prefix := filepath.Join(certutil.CertDir, certutil.SanitizeDomain(sni)+"-*.crt")
	matches, err := filepath.Glob(prefix)
	if err != nil || len(matches) == 0 {
		return "", "", false
	}
	for _, crt := range matches {
		key := crt[:len(crt)-4] + ".key"
		if file.IsExist(crt) && file.IsExist(key) {
			return crt, key, true
		}
	}
	return "", "", false
}

// EnsureNodeCertificate provisions, writes, or validates the TLS certificate and key
// for any server protocol or relay tunnel according to info.Protocol.CertMode.
// It returns the resolved filesystem paths (certFile, keyFile).
func EnsureNodeCertificate(info *panel.NodeInfo, tag string) (string, string, error) {
	if info == nil || info.Protocol == nil {
		return "", "", nil
	}
	certFile, keyFile := certutil.GetCertPaths(info.Protocol.SNI, info.Type, info.Id)

	switch info.Protocol.CertMode {
	case "none", "":
		return "", "", nil
	case "file":
		// Write inline certificate content from API to files
		if info.Protocol.CertFile != "" && info.Protocol.KeyFile != "" {
			dir := filepath.Dir(certFile)
			if !file.IsExist(dir) {
				if err := os.MkdirAll(dir, 0755); err != nil {
					return "", "", fmt.Errorf("create cert directory error: %s", err)
				}
			}
			if err := os.WriteFile(certFile, []byte(info.Protocol.CertFile), 0644); err != nil {
				return "", "", fmt.Errorf("write cert file error: %s", err)
			}
			log.WithField("node", tag).Info("Certificate file written: ", certFile)
			if err := os.WriteFile(keyFile, []byte(info.Protocol.KeyFile), 0600); err != nil {
				return "", "", fmt.Errorf("write key file error: %s", err)
			}
			log.WithField("node", tag).Info("Key file written: ", keyFile)
		} else if !file.IsExist(certFile) || !file.IsExist(keyFile) {
			if existingCrt, existingKey, ok := findExistingDomainCert(info.Protocol.SNI); ok {
				return existingCrt, existingKey, nil
			}
			return "", "", fmt.Errorf("cert_mode is 'file' but no certificate content provided and files do not exist")
		}
		return certFile, keyFile, nil
	case "path":
		// Use cert_file and key_file as direct filesystem paths — validate they exist
		if info.Protocol.CertFile == "" || info.Protocol.KeyFile == "" {
			return "", "", fmt.Errorf("cert_mode is 'path' but cert_file or key_file is empty")
		}
		if !file.IsExist(info.Protocol.CertFile) {
			return "", "", fmt.Errorf("cert_mode is 'path' but cert file does not exist: %s", info.Protocol.CertFile)
		}
		if !file.IsExist(info.Protocol.KeyFile) {
			return "", "", fmt.Errorf("cert_mode is 'path' but key file does not exist: %s", info.Protocol.KeyFile)
		}
		log.WithField("node", tag).Infof("Using cert path: %s, key path: %s", info.Protocol.CertFile, info.Protocol.KeyFile)
		return info.Protocol.CertFile, info.Protocol.KeyFile, nil
	case "dns", "http":
		if file.IsExist(certFile) && file.IsExist(keyFile) {
			return certFile, keyFile, nil
		}
		if existingCrt, existingKey, ok := findExistingDomainCert(info.Protocol.SNI); ok {
			log.WithField("node", tag).Infof("Reusing existing domain certificate for %s: %s", info.Protocol.SNI, existingCrt)
			return existingCrt, existingKey, nil
		}
		l, err := NewLego(info)
		if err != nil {
			return "", "", fmt.Errorf("create lego object error: %s", err)
		}
		if err := l.CreateCert(); err != nil {
			return "", "", fmt.Errorf("create lego cert error: %s", err)
		}
		return certFile, keyFile, nil
	case "self":
		if file.IsExist(certFile) && file.IsExist(keyFile) {
			return certFile, keyFile, nil
		}
		if err := generateSelfSslCertificate(info.Protocol.SNI, certFile, keyFile); err != nil {
			return "", "", fmt.Errorf("generate self cert error: %s", err)
		}
		return certFile, keyFile, nil
	default:
		return "", "", fmt.Errorf("unsupported certmode: %s", info.Protocol.CertMode)
	}
}

func generateSelfSslCertificate(domain, certPath, keyPath string) error {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{
		Version:      3,
		SerialNumber: big.NewInt(time.Now().Unix()),
		Subject: pkix.Name{
			CommonName: domain,
		},
		DNSNames:              []string{domain},
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(30, 0, 0),
	}
	cert, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(certPath, os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		return err
	}
	err = pem.Encode(f, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert,
	})
	if err != nil {
		return err
	}
	f, err = os.OpenFile(keyPath, os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		return err
	}
	err = pem.Encode(f, &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	if err != nil {
		return err
	}
	return nil
}

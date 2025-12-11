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
	certFile, keyFile := certutil.GetCertPaths(c.info.Protocol.SNI, c.info.Type, c.info.Id)

	switch c.info.Protocol.CertMode {
	case "none", "":
		// No certificate needed
	case "file":
		// Write inline certificate content from API to files
		if c.info.Protocol.CertFile != "" && c.info.Protocol.KeyFile != "" {
			// Ensure the directory exists
			dir := filepath.Dir(certFile)
			if !file.IsExist(dir) {
				if err := os.MkdirAll(dir, 0755); err != nil {
					return fmt.Errorf("create cert directory error: %s", err)
				}
			}
			// Write cert file
			if err := os.WriteFile(certFile, []byte(c.info.Protocol.CertFile), 0644); err != nil {
				return fmt.Errorf("write cert file error: %s", err)
			}
			log.WithField("node", c.tag).Info("Certificate file written: ", certFile)
			// Write key file
			if err := os.WriteFile(keyFile, []byte(c.info.Protocol.KeyFile), 0600); err != nil {
				return fmt.Errorf("write key file error: %s", err)
			}
			log.WithField("node", c.tag).Info("Key file written: ", keyFile)
		} else if !file.IsExist(certFile) || !file.IsExist(keyFile) {
			return fmt.Errorf("cert_mode is 'file' but no certificate content provided and files do not exist")
		}
	case "dns", "http":
		if file.IsExist(certFile) && file.IsExist(keyFile) {
			return nil
		}
		l, err := NewLego(c.info)
		if err != nil {
			return fmt.Errorf("create lego object error: %s", err)
		}
		err = l.CreateCert()
		if err != nil {
			return fmt.Errorf("create lego cert error: %s", err)
		}
	case "self":
		if file.IsExist(certFile) && file.IsExist(keyFile) {
			return nil
		}
		err := generateSelfSslCertificate(
			c.info.Protocol.SNI,
			certFile,
			keyFile)
		if err != nil {
			return fmt.Errorf("generate self cert error: %s", err)
		}
	default:
		return fmt.Errorf("unsupported certmode: %s", c.info.Protocol.CertMode)
	}
	return nil
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

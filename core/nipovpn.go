package core

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"github.com/archnets/node/api/panel"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

const NipovpnBinary = "/usr/bin/nipovpn"

type NipovpnManager struct {
	mu      sync.Mutex
	cmd     *exec.Cmd
	tunnel  panel.TunnelInfo
	logger  *log.Entry
	cfgPath string
	started bool
}

func NewNipovpnManager(t panel.TunnelInfo, logger *log.Entry) *NipovpnManager {
	return &NipovpnManager{
		tunnel: t,
		logger: logger.WithField("subsystem", "nipovpn"),
	}
}

// GenerateConfig generates a NipoVPN config.yaml and writes it to a file
func (m *NipovpnManager) GenerateConfig(dir string) error {
	cfg := m.tunnel.NipovpnConfig
	if cfg == nil {
		return fmt.Errorf("missing nipovpn_config")
	}
	type General struct {
		Token           string   `yaml:"token"`
		Protocol        string   `yaml:"protocol"`
		FakeUrls        []string `yaml:"fakeUrls"`
		Methods         []string `yaml:"methods"`
		EndPoints       []string `yaml:"endPoints"`
		Timeout         int      `yaml:"timeout"`
		PullTimeout     int      `yaml:"pullTimeout"`
		TunnelEnable    bool     `yaml:"tunnelEnable"`
		ConnectionReuse bool     `yaml:"connectionReuse"`
		TlsEnable       bool     `yaml:"tlsEnable"`
		TlsVerifyPeer   bool     `yaml:"tlsVerifyPeer"`
		TlsCertFile     string   `yaml:"tlsCertFile"`
		TlsKeyFile      string   `yaml:"tlsKeyFile"`
		TlsCaFile       string   `yaml:"tlsCaFile"`
	}
	type Log struct {
		LogLevel string `yaml:"logLevel"`
		LogFile  string `yaml:"logFile"`
	}
	type Server struct {
		Threads    int    `yaml:"threads"`
		ListenIp   string `yaml:"listenIp"`
		ListenPort int    `yaml:"listenPort"`
	}
	type Agent struct {
		Threads     int    `yaml:"threads"`
		ListenIp    string `yaml:"listenIp"`
		ListenPort  int    `yaml:"listenPort"`
		ServerIp    string `yaml:"serverIp"`
		ServerPort  int    `yaml:"serverPort"`
		HttpVersion string `yaml:"httpVersion"`
		UserAgent   string `yaml:"userAgent"`
	}
	type Config struct {
		General General `yaml:"general"`
		Log     Log     `yaml:"log"`
		Server  Server  `yaml:"server"`
		Agent   Agent   `yaml:"agent"`
	}
	var certPath, keyPath string
	if cfg.TlsEnable {
		// Use new custom path fields if provided; fallback to backwards-compatible paths
		certPath = cfg.TlsCertFile
		if certPath == "" {
			certPath = cfg.TlsCertPath
		}
		keyPath = cfg.TlsKeyFile
		if keyPath == "" {
			keyPath = cfg.TlsKeyPath
		}
		if certPath == "" {
			certPath = filepath.Join(dir, fmt.Sprintf("nipovpn_%d.crt", m.tunnel.Id))
		}
		if keyPath == "" {
			keyPath = filepath.Join(dir, fmt.Sprintf("nipovpn_%d.key", m.tunnel.Id))
		}
		if err := os.MkdirAll(filepath.Dir(certPath), 0755); err != nil {
			return fmt.Errorf("failed to create cert directory: %w", err)
		}
		if err := os.MkdirAll(filepath.Dir(keyPath), 0755); err != nil {
			return fmt.Errorf("failed to create key directory: %w", err)
		}
		if _, err := os.Stat(certPath); os.IsNotExist(err) {
			m.logger.Infof("TLS enabled but certificate files not found. Generating self-signed certificates at %s", certPath)
			if err := generateSelfSignedCert(certPath, keyPath); err != nil {
				return fmt.Errorf("failed to generate self-signed certificate: %w", err)
			}
		}
	}
	// Map backend parameters with default fallbacks for unassigned fields
	connectionReuse := true
	if cfg.ConnectionReuse != nil {
		connectionReuse = *cfg.ConnectionReuse
	}
	logLevel := "INFO"
	if cfg.LogLevel != "" {
		logLevel = cfg.LogLevel
	}
	serverThreads := 8
	if cfg.ServerThreads > 0 {
		serverThreads = cfg.ServerThreads
	}
	agentThreads := 8
	if cfg.AgentThreads > 0 {
		agentThreads = cfg.AgentThreads
	}
	httpVersion := "1.1"
	if cfg.HttpVersion != "" {
		httpVersion = cfg.HttpVersion
	}
	userAgent := "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0"
	if cfg.UserAgent != "" {
		userAgent = cfg.UserAgent
	}
	protocol := "http"
	if cfg.Protocol != "" {
		protocol = cfg.Protocol
	}
	c := Config{
		General: General{
			Token:           cfg.Token,
			Protocol:        protocol,
			FakeUrls:        cfg.FakeUrls,
			Methods:         cfg.Methods,
			EndPoints:       cfg.Endpoints,
			Timeout:         cfg.Timeout,
			PullTimeout:     cfg.PullTimeout,
			TunnelEnable:    true,
			ConnectionReuse: connectionReuse,
			TlsEnable:       cfg.TlsEnable,
			TlsVerifyPeer:   false,
			TlsCertFile:     certPath,
			TlsKeyFile:      keyPath,
			TlsCaFile:       cfg.TlsCaFile,
		},
		Log: Log{
			LogLevel: logLevel,
			LogFile:  filepath.Join(dir, fmt.Sprintf("log/nipovpn_%d.log", m.tunnel.Id)),
		},
		Server: Server{
			Threads:    serverThreads,
			ListenIp:   "0.0.0.0",
			ListenPort: cfg.ServerPort,
		},
		Agent: Agent{
			Threads:     agentThreads,
			ListenIp:    "127.0.0.1",
			ListenPort:  cfg.AgentPort,
			ServerIp:    m.tunnel.ExitServerIP,
			ServerPort:  cfg.ServerPort,
			HttpVersion: httpVersion,
			UserAgent:   userAgent,
		},
	}
	data, err := yaml.Marshal(&c)
	if err != nil {
		return err
	}
	m.cfgPath = filepath.Join(dir, fmt.Sprintf("nipovpn_%d.yaml", m.tunnel.Id))
	return os.WriteFile(m.cfgPath, data, 0644)
}

func generateSelfSignedCert(certPath, keyPath string) error {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(3650 * 24 * time.Hour) // 10 years

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "nipovpn",
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return err
	}

	certOut, err := os.Create(certPath)
	if err != nil {
		return err
	}
	defer certOut.Close()
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return err
	}

	keyOut, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer keyOut.Close()

	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return err
	}
	if err := pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}); err != nil {
		return err
	}

	return nil
}

func (m *NipovpnManager) GetPID() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cmd != nil && m.cmd.Process != nil {
		return m.cmd.Process.Pid
	}
	return 0
}



package core

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"

	"github.com/archnets/node/api/panel"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

const NipovpnBinary = "/usr/local/bin/nipovpn"

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

	// Default template configs to satisfy parser constraints
	c := Config{
		General: General{
			Token:           cfg.Token,
			FakeUrls:        cfg.FakeUrls,
			Methods:         cfg.Methods,
			EndPoints:       cfg.Endpoints,
			Timeout:         cfg.Timeout,
			PullTimeout:     cfg.PullTimeout,
			TunnelEnable:    true,
			ConnectionReuse: true,
			TlsEnable:       cfg.TlsEnable,
			TlsVerifyPeer:   false,
		},
		Log: Log{
			LogLevel: "DEBUG",
			LogFile:  filepath.Join(dir, fmt.Sprintf("log/nipovpn_%d.log", m.tunnel.Id)),
		},
		Server: Server{
			Threads:    8,
			ListenIp:   "0.0.0.0",
			ListenPort: cfg.ServerPort,
		},
		Agent: Agent{
			Threads:     8,
			ListenIp:    "127.0.0.1",
			ListenPort:  cfg.AgentPort,
			ServerIp:    m.tunnel.ExitServerIP,
			ServerPort:  cfg.ServerPort,
			HttpVersion: "1.1",
			UserAgent:   "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0",
		},
	}

	data, err := yaml.Marshal(&c)
	if err != nil {
		return err
	}

	m.cfgPath = filepath.Join(dir, fmt.Sprintf("nipovpn_%d.yaml", m.tunnel.Id))
	return os.WriteFile(m.cfgPath, data, 0644)
}



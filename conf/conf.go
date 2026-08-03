package conf

import (
	"fmt"
	"os"
	"strconv"

	"github.com/spf13/viper"
)

type Conf struct {
	LogConfig LogConfig       `mapstructure:"Log"`
	ApiConfig ServerApiConfig `mapstructure:"Api"`
}

type LogConfig struct {
	Level  string `mapstructure:"Level"`
	Output string `mapstructure:"Output"`
	Access string `mapstructure:"Access"`
}

type ServerApiConfig struct {
	ApiHost             string `mapstructure:"ApiHost"`
	ServerId            int    `mapstructure:"ServerID"`
	SecretKey           string `mapstructure:"SecretKey"`
	Timeout             int    `mapstructure:"Timeout"`
	PerProtocolUserList bool   `mapstructure:"PerProtocolUserList"`
}

type NodeApiConfig struct {
	APIHost   string `mapstructure:"ApiHost"`
	NodeID    int    `mapstructure:"NodeID"`
	SecretKey string `mapstructure:"SecretKey"`
	NodeType  string `mapstructure:"NodeType"`
	Timeout   int    `mapstructure:"Timeout"`
}

func New() *Conf {
	return &Conf{
		LogConfig: LogConfig{
			Level:  "info",
			Output: "",
			Access: "none",
		},
	}
}

func (p *Conf) LoadFromPath(filePath string) error {
	v := viper.New()
	v.SetConfigFile(filePath)
	if err := v.ReadInConfig(); err == nil {
		if err := v.Unmarshal(p); err != nil {
			return fmt.Errorf("unmarshal config error: %s", err)
		}
	}

	// Environment variable overrides for Docker & Railway
	if apiHost := os.Getenv("API_HOST"); apiHost != "" {
		p.ApiConfig.ApiHost = apiHost
	}
	if serverID := os.Getenv("SERVER_ID"); serverID != "" {
		if id, err := strconv.Atoi(serverID); err == nil {
			p.ApiConfig.ServerId = id
		}
	}
	if secretKey := os.Getenv("SECRET_KEY"); secretKey != "" {
		p.ApiConfig.SecretKey = secretKey
	}

	if p.ApiConfig.ApiHost == "" {
		return fmt.Errorf("ApiHost is required in %s or via API_HOST environment variable", filePath)
	}

	return nil
}

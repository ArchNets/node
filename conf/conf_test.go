package conf

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPerProtocolUserList_DefaultTrue(t *testing.T) {
	// Case 1: New() defaults to true
	c := New()
	assert.True(t, c.ApiConfig.PerProtocolUserList, "New() should initialize PerProtocolUserList to true")

	// Case 2: LoadFromPath with minimal config (no PerProtocolUserList key)
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yml")
	configContent := `
Log:
  Level: info
Api:
  ApiHost: "https://api.example.com"
  ServerID: 10
  SecretKey: "secret"
`
	err := os.WriteFile(configPath, []byte(configContent), 0644)
	assert.NoError(t, err)

	conf := New()
	err = conf.LoadFromPath(configPath)
	assert.NoError(t, err)
	assert.True(t, conf.ApiConfig.PerProtocolUserList, "LoadFromPath should default PerProtocolUserList to true when omitted")

	// Case 3: Explicitly set to false in config
	configContentFalse := `
Log:
  Level: info
Api:
  ApiHost: "https://api.example.com"
  ServerID: 10
  SecretKey: "secret"
  PerProtocolUserList: false
`
	configPathFalse := filepath.Join(tmpDir, "config_false.yml")
	err = os.WriteFile(configPathFalse, []byte(configContentFalse), 0644)
	assert.NoError(t, err)

	confFalse := New()
	err = confFalse.LoadFromPath(configPathFalse)
	assert.NoError(t, err)
	assert.False(t, confFalse.ApiConfig.PerProtocolUserList, "LoadFromPath should respect explicit PerProtocolUserList: false")
}

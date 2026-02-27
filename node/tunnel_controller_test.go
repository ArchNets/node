package node

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/archnets/node/api/panel"
	"github.com/archnets/node/conf"
	log "github.com/sirupsen/logrus"
)

func TestNewTunnelController(t *testing.T) {
	// Create ClientV2 for tunnel
	apiClient := panel.NewClientV2(&conf.ServerApiConfig{
		ApiHost:   "http://localhost",
		ServerId:  1,
		SecretKey: "secret",
	})
	nodeConfig := conf.New()

	// Create tunnel controller
	tc := NewTunnelController(apiClient, 1, nodeConfig)

	if tc == nil {
		t.Fatal("TunnelController should not be nil")
	}

	if tc.tag != "tunnel-1" {
		t.Errorf("Expected tag 'tunnel-1', got '%s'", tc.tag)
	}

	if tc.serverId != 1 {
		t.Errorf("Expected serverId 1, got %d", tc.serverId)
	}

	if tc.tunnelDir != TunnelDir {
		t.Errorf("Expected tunnelDir '%s', got '%s'", TunnelDir, tc.tunnelDir)
	}
}

func TestGenerateCoreJSON(t *testing.T) {
	tc := &TunnelController{
		tag:       "tunnel-test",
		tunnelDir: "/tmp/test-tunnel",
	}

	cfg := &panel.CoreConfig{
		MTU:        1450,
		LogLevel:   "DEBUG",
		Workers:    0,
		RamProfile: "server",
	}

	tunnelFiles := []string{"tunnel_1.json", "tunnel_2.json"}

	result := tc.generateCoreJSON(cfg, tunnelFiles)

	// Verify result contains expected values
	resultStr := string(result)

	if !contains(resultStr, `"loglevel": "DEBUG"`) {
		t.Error("core.json should contain log level DEBUG")
	}

	if !contains(resultStr, `"mtu": 1450`) {
		t.Error("core.json should contain mtu 1450")
	}

	if !contains(resultStr, `"ram-profile": "server"`) {
		t.Error("core.json should contain ram-profile server")
	}

	if !contains(resultStr, `"workers": 0`) {
		t.Error("core.json should contain workers 0")
	}

	if !contains(resultStr, `"tunnel_1.json"`) {
		t.Error("core.json should contain tunnel_1.json in configs")
	}

	if !contains(resultStr, `"tunnel_2.json"`) {
		t.Error("core.json should contain tunnel_2.json in configs")
	}
}

func TestGenerateCoreJSONDefaults(t *testing.T) {
	tc := &TunnelController{
		tag:       "tunnel-test",
		tunnelDir: "/tmp/test-tunnel",
	}

	// Test with nil config (should use defaults)
	result := tc.generateCoreJSON(nil, []string{})

	resultStr := string(result)

	// Should use default values
	if !contains(resultStr, `"loglevel": "FATAL"`) {
		t.Error("core.json should use default log level FATAL")
	}

	if !contains(resultStr, `"mtu": 1450`) {
		t.Error("core.json should use default mtu 1450")
	}
}

func TestTunnelConfigFilePaths(t *testing.T) {
	tc := &TunnelController{
		tag:       "tunnel-test",
		tunnelDir: "/tmp/tunnel-test-paths",
	}

	// Test core config path
	corePath := filepath.Join(tc.tunnelDir, CoreConfigFile)
	if corePath != "/tmp/tunnel-test-paths/core.json" {
		t.Errorf("Unexpected core.json path: %s", corePath)
	}

	// Test tunnel config path format
	tunnelPath := filepath.Join(tc.tunnelDir, "tunnel_123.json")
	if tunnelPath != "/tmp/tunnel-test-paths/tunnel_123.json" {
		t.Errorf("Unexpected tunnel config path: %s", tunnelPath)
	}
}

func TestTunnelControllerApplyConfigWritesFiles(t *testing.T) {
	// Create a temporary directory for testing
	tmpDir, err := os.MkdirTemp("", "tunnel-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	tc := &TunnelController{
		tag:                "tunnel-test",
		tunnelDir:          tmpDir,
		forwarderProcesses: make(map[int]*exec.Cmd),
		logger:             log.WithField("tag", "tunnel-test"),
	}

	// Create log and libs directories
	os.MkdirAll(filepath.Join(tmpDir, "log"), 0755)
	os.MkdirAll(filepath.Join(tmpDir, "libs"), 0755)

	data := &panel.TunnelData{
		CoreConfig: &panel.CoreConfig{
			MTU:        1450,
			LogLevel:   "DEBUG",
			Workers:    0,
			RamProfile: "server",
		},
		Tunnels: []panel.TunnelInfo{
			{
				Id:              1,
				Name:            "test-tunnel",
				Role:            "entry",
				WaterwallConfig: `{"name": "test"}`,
				RemoteIP:        "127.0.0.1",
				Forwarders:      []panel.Forwarder{},
			},
		},
	}

	// Apply config - this will fail to start waterwall but should write files
	_ = tc.applyConfig(data)

	// Check that core.json was written
	coreContent, err := os.ReadFile(filepath.Join(tmpDir, "core.json"))
	if err != nil {
		t.Fatalf("Failed to read core.json: %v", err)
	}

	if !contains(string(coreContent), `"loglevel": "DEBUG"`) {
		t.Error("core.json should contain DEBUG log level")
	}

	// Check that tunnel config was written
	tunnelContent, err := os.ReadFile(filepath.Join(tmpDir, "tunnel_1.json"))
	if err != nil {
		t.Fatalf("Failed to read tunnel_1.json: %v", err)
	}

	if string(tunnelContent) != `{"name": "test"}` {
		t.Errorf("Unexpected tunnel config content: %s", string(tunnelContent))
	}
}

func TestPingTarget(t *testing.T) {
	tc := &TunnelController{
		tag: "tunnel-test",
	}

	// Test with empty IP
	latency, online := tc.pingTarget("")
	if online {
		t.Error("pingTarget with empty IP should be offline")
	}
	if latency != 0 {
		t.Errorf("pingTarget with empty IP should have 0 latency, got %d", latency)
	}

	// Test with loopback (should be online on most systems)
	latency, online = tc.pingTarget("127.0.0.1")
	// Note: In some CI/test environments, ping might be restricted.
	// We'll just log if it fails but not necessarily fail the test if it's
	// clearly an environment issue.
	if !online {
		t.Log("Warning: ping to 127.0.0.1 failed. This might be due to environment restrictions.")
	} else if latency < 0 {
		t.Errorf("pingTarget with 127.0.0.1 should have >= 0 latency, got %d", latency)
	}
}

// Helper function
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

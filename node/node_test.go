package node

import (
	"testing"

	"github.com/archnets/node/api/panel"
	"github.com/archnets/node/conf"
	"github.com/archnets/node/core"
)

func TestNew(t *testing.T) {
	// Mock configuration
	config := &conf.Conf{
		ApiConfig: conf.ServerApiConfig{
			ServerId:  1,
			ApiHost:   "http://localhost",
			SecretKey: "secret",
		},
	}

	// Mock server response with one enabled and one disabled protocol
	enabledProtocol := panel.Protocol{
		Type:     "shadowsocks",
		Port:     10001,
		Enable:   true,
		Security: "none",
	}
	disabledProtocol := panel.Protocol{
		Type:     "vmess",
		Port:     10002,
		Enable:   false,
		Security: "none",
	}

	serverConfig := &panel.ServerConfigResponse{
		Data: &panel.Data{
			Protocols: &[]panel.Protocol{enabledProtocol, disabledProtocol},
		},
	}

	// Mock core (can be nil for this test as we don't start the node)
	var mockCore *core.XrayCore

	// Create node
	n, err := New(mockCore, config, serverConfig)
	if err != nil {
		t.Fatalf("Failed to create node: %v", err)
	}

	// Verify that only the enabled protocol was added (as Xray controller)
	if len(n.xrayControllers) != 1 {
		t.Errorf("Expected 1 xray controller, got %d", len(n.xrayControllers))
	}

	if n.xrayControllers[0].info.Type != "shadowsocks" {
		t.Errorf("Expected controller type shadowsocks, got %s", n.xrayControllers[0].info.Type)
	}

	// Verify no SSH controllers were created
	if len(n.sshControllers) != 0 {
		t.Errorf("Expected 0 ssh controllers, got %d", len(n.sshControllers))
	}
}

func TestNewWithSSH(t *testing.T) {
	// Mock configuration
	config := &conf.Conf{
		ApiConfig: conf.ServerApiConfig{
			ServerId:  1,
			ApiHost:   "http://localhost",
			SecretKey: "secret",
		},
	}

	// Mock server response with SSH protocol
	sshProtocol := panel.Protocol{
		Type:   "ssh",
		Port:   2222,
		Enable: true,
	}
	xrayProtocol := panel.Protocol{
		Type:     "vless",
		Port:     443,
		Enable:   true,
		Security: "reality",
	}

	serverConfig := &panel.ServerConfigResponse{
		Data: &panel.Data{
			Protocols: &[]panel.Protocol{sshProtocol, xrayProtocol},
		},
	}

	// Mock core (can be nil for this test as we don't start the node)
	var mockCore *core.XrayCore

	// Create node
	n, err := New(mockCore, config, serverConfig)
	if err != nil {
		t.Fatalf("Failed to create node: %v", err)
	}

	// Verify SSH and Xray controllers are separated
	if len(n.sshControllers) != 1 {
		t.Errorf("Expected 1 ssh controller, got %d", len(n.sshControllers))
	}

	if len(n.xrayControllers) != 1 {
		t.Errorf("Expected 1 xray controller, got %d", len(n.xrayControllers))
	}
}

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
		ApiConfig: conf.ApiConfig{
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

	// Verify that only the enabled protocol was added
	if len(n.controllers) != 1 {
		t.Errorf("Expected 1 controller, got %d", len(n.controllers))
	}

	if n.controllers[0].info.Type != "shadowsocks" {
		t.Errorf("Expected controller type shadowsocks, got %s", n.controllers[0].info.Type)
	}
}

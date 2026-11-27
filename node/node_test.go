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

func TestNewWithListenIP(t *testing.T) {
	// Mock configuration
	config := &conf.Conf{
		ApiConfig: conf.ServerApiConfig{
			ServerId:  1,
			ApiHost:   "http://localhost",
			SecretKey: "secret",
		},
	}

	// Mock server response with two Xray protocols with different ListenIPs
	protocol1 := panel.Protocol{
		Type:     "vless",
		Port:     5000,
		ListenIP: "127.0.0.1",
		Enable:   true,
	}
	protocol2 := panel.Protocol{
		Type:     "vmess",
		Port:     6000,
		ListenIP: "192.168.1.1",
		Enable:   true,
	}

	serverConfig := &panel.ServerConfigResponse{
		Data: &panel.Data{
			Protocols: &[]panel.Protocol{protocol1, protocol2},
		},
	}

	// Create node
	n, err := New(nil, config, serverConfig)
	if err != nil {
		t.Fatalf("Failed to create node: %v", err)
	}

	if len(n.xrayControllers) != 2 {
		t.Fatalf("Expected 2 xray controllers, got %d", len(n.xrayControllers))
	}

	// Verify protocol1
	if n.xrayControllers[0].info.Protocol.ListenIP != "127.0.0.1" {
		t.Errorf("Expected ListenIP 127.0.0.1, got %s", n.xrayControllers[0].info.Protocol.ListenIP)
	}
	if n.xrayControllers[0].info.Protocol.Port != 5000 {
		t.Errorf("Expected Port 5000, got %d", n.xrayControllers[0].info.Protocol.Port)
	}

	// Verify protocol2
	if n.xrayControllers[1].info.Protocol.ListenIP != "192.168.1.1" {
		t.Errorf("Expected ListenIP 192.168.1.1, got %s", n.xrayControllers[1].info.Protocol.ListenIP)
	}
	if n.xrayControllers[1].info.Protocol.Port != 6000 {
		t.Errorf("Expected Port 6000, got %d", n.xrayControllers[1].info.Protocol.Port)
	}
}

func TestNodeStart_ShadowTLSFailureDoesNotAbortOthers(t *testing.T) {
	n := &Node{
		shadowtlsControllers: []*ShadowTLSController{
			{
				tag: "failing-shadowtls",
				info: &panel.NodeInfo{
					Protocol: &panel.Protocol{
						ShadowTLSVersion: 99, // Invalid version, will make Start() error
					},
				},
			},
		},
	}

	err := n.Start()
	if err != nil {
		t.Fatalf("expected node.Start() to succeed (ignoring ShadowTLS failure), got: %v", err)
	}
}

func TestFilterOnlineUsersByTraffic(t *testing.T) {
	online := []panel.OnlineUser{
		{UID: 1, IP: "1.1.1.1"}, // 0 bytes -> must NOT report
		{UID: 2, IP: "2.2.2.2"}, // 2 KB url-test probe -> must NOT report
		{UID: 3, IP: "3.3.3.3"}, // 20 KB drained -> MUST report
		{UID: 4, IP: "4.4.4.4"}, // 100 KB below 1MB TrafficReportThreshold -> MUST report via snapshot delta
	}
	snap := map[int]int64{
		2: 2000,
		3: 20000,
		4: 100000,
	}
	drained := []panel.UserTraffic{
		{UID: 2, Upload: 500, Download: 1500},
		{UID: 3, Upload: 4000, Download: 16000},
	}

	deltas, nextPrev := computeTickTrafficDeltas(snap, drained, nil)
	got := filterOnlineUsersByTraffic(online, deltas)
	if len(got) != 2 || got[0].UID != 3 || got[1].UID != 4 {
		t.Fatalf("expected UIDs 3 and 4 (> 8KB) to be reported online, got %+v", got)
	}

	// Next tick: UID 4 stayed idle at 100000 -> delta is 0 -> must NOT report
	deltas2, _ := computeTickTrafficDeltas(map[int]int64{4: 100000}, nil, nextPrev)
	got2 := filterOnlineUsersByTraffic([]panel.OnlineUser{{UID: 4, IP: "4.4.4.4"}}, deltas2)
	if len(got2) != 0 {
		t.Fatalf("expected idle UID 4 with 0 delta not to report, got %+v", got2)
	}
}

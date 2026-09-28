package core

import (
	"encoding/json"
	"testing"

	"github.com/archnets/node/api/panel"
	coreConf "github.com/xtls/xray-core/infra/conf"
)

func TestCleanInboundXHTTPExtra(t *testing.T) {
	input := `{
		"xmux": {"maxConcurrency": 16},
		"downloadSettings": {"address": "1.2.3.4"},
		"uplinkChunkSize": 1024,
		"noGRPCHeader": true,
		"xPaddingBytes": "100-1000",
		"scMaxEachPostBytes": "1000000"
	}`

	cleaned := cleanInboundXHTTPExtra(input)
	var m map[string]interface{}
	if err := json.Unmarshal([]byte(cleaned), &m); err != nil {
		t.Fatalf("failed to unmarshal cleaned extra: %v", err)
	}

	for _, stripped := range []string{"xmux", "downloadSettings", "uplinkChunkSize", "noGRPCHeader"} {
		if _, exists := m[stripped]; exists {
			t.Errorf("expected %s to be stripped from inbound extra, but it was present", stripped)
		}
	}

	if m["xPaddingBytes"] != "100-1000" {
		t.Errorf("expected xPaddingBytes to be preserved, got %v", m["xPaddingBytes"])
	}
	if m["scMaxEachPostBytes"] != "1000000" {
		t.Errorf("expected scMaxEachPostBytes to be preserved, got %v", m["scMaxEachPostBytes"])
	}
}

func TestBuildInboundXHTTP(t *testing.T) {
	nodeInfo := &panel.NodeInfo{
		Protocol: &panel.Protocol{
			Transport:  "xhttp",
			Host:       "example.com",
			Path:       "/endpoint",
			XHTTPMode:  "packet-up",
			XHTTPExtra: `{"xPaddingBytes":"100-1000","xmux":{"maxConcurrency":16}}`,
		},
	}

	// Test VLESS
	inboundVLess := &coreConf.InboundDetourConfig{}
	if err := buildVLess(nodeInfo, inboundVLess); err != nil {
		t.Fatalf("buildVLess failed: %v", err)
	}
	if inboundVLess.StreamSetting.SplitHTTPSettings == nil {
		t.Fatal("expected SplitHTTPSettings to be set for VLESS")
	}
	if inboundVLess.StreamSetting.SplitHTTPSettings.Extra == nil {
		t.Fatal("expected SplitHTTPSettings.Extra to be set for VLESS")
	}

	// Test VMess
	inboundVMess := &coreConf.InboundDetourConfig{}
	if err := buildVMess(nodeInfo, inboundVMess); err != nil {
		t.Fatalf("buildVMess failed: %v", err)
	}
	if inboundVMess.StreamSetting.SplitHTTPSettings == nil {
		t.Fatal("expected SplitHTTPSettings to be set for VMess")
	}
	if inboundVMess.StreamSetting.SplitHTTPSettings.Extra == nil {
		t.Fatal("expected SplitHTTPSettings.Extra to be set for VMess")
	}

	// Test Trojan
	inboundTrojan := &coreConf.InboundDetourConfig{}
	if err := buildTrojan(nodeInfo, inboundTrojan); err != nil {
		t.Fatalf("buildTrojan failed: %v", err)
	}
	if inboundTrojan.StreamSetting.SplitHTTPSettings == nil {
		t.Fatal("expected SplitHTTPSettings to be set for Trojan")
	}
	if inboundTrojan.StreamSetting.SplitHTTPSettings.Extra == nil {
		t.Fatal("expected SplitHTTPSettings.Extra to be set for Trojan")
	}

	// Verify xmux was stripped from inbound Extra in all three
	for name, ib := range map[string]*coreConf.InboundDetourConfig{
		"VLESS":  inboundVLess,
		"VMess":  inboundVMess,
		"Trojan": inboundTrojan,
	} {
		var extraMap map[string]interface{}
		if err := json.Unmarshal(ib.StreamSetting.SplitHTTPSettings.Extra, &extraMap); err != nil {
			t.Fatalf("[%s] failed to unmarshal extra: %v", name, err)
		}
		if _, has := extraMap["xmux"]; has {
			t.Errorf("[%s] xmux should have been stripped from inbound Extra", name)
		}
		if extraMap["xPaddingBytes"] != "100-1000" {
			t.Errorf("[%s] xPaddingBytes should have been preserved", name)
		}
	}
}

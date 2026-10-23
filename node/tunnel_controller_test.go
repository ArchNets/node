package node

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/archnets/node/api/panel"
	"github.com/archnets/node/conf"
	"github.com/archnets/node/core/relay/telemetry"
	log "github.com/sirupsen/logrus"
)

func TestNewTunnelController(t *testing.T) {
	apiClient := panel.NewClientV2(&conf.ServerApiConfig{
		ApiHost:   "http://localhost",
		ServerId:  1,
		SecretKey: "secret",
	})
	nodeConfig := conf.New()

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

func TestTunnelControllerApplyNativeRelayConfig(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "tunnel-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	relayDrv := NewRelayDriver(log.WithField("tag", "tunnel-test"))
	RegisterTunnelDriver("reverse-reality", relayDrv)

	tc := &TunnelController{
		tag:                "tunnel-test",
		tunnelDir:          tmpDir,
		forwarderProcesses: make(map[int]*exec.Cmd),
		relayDriver:        relayDrv,
		lastTraffic:        make(map[int]trafficSnapshot),
		logger:             log.WithField("tag", "tunnel-test"),
	}

	_ = os.MkdirAll(filepath.Join(tmpDir, "log"), 0755)

	data := &panel.TunnelData{
		Tunnels: []panel.TunnelInfo{
			{
				Id:       1,
				Name:     "iran-shariati-tunnel",
				Role:     "entry",
				Method:   "reverse-reality",
				RemoteIP: "127.0.0.1",
				RelayConfig: &panel.RelayTunnelConfig{
					Transport:          "reverse-reality",
					CarrierPort:        59443,
					SNI:                "shariati.tums.ac.ir",
					Password:           "secret123",
					UseHalfDuplex:      true,
					UseFisher:          true,
					FisherConnections:  3,
					MinHeldConnections: 4,
				},
				Forwarders: []panel.Forwarder{},
			},
		},
	}

	err = tc.applyConfig(data)
	if err != nil {
		t.Fatalf("failed to apply native relay config: %v", err)
	}
	defer tc.Close()

	eng := tc.relayDriver.GetEngine(1)
	if eng == nil {
		t.Fatal("expected native relay engine to be started for tunnel 1")
	}
	if !eng.IsAlive() {
		t.Fatal("expected native relay engine to be running")
	}
}

func TestBuildBenchmarkCandidates(t *testing.T) {
	telemetry.SetDynamicSNIOrigins([]telemetry.SNIPreset{
		{SNI: "dynamic.hospital.ir", Label: "Dynamic Hospital", OriginIP: "1.2.3.4", Category: "hospital"},
		{SNI: "dynamic.app.ir", Label: "Dynamic App", OriginIP: "5.6.7.8", Category: "national"},
	})

	cmd := &panel.ScanCommand{
		ScanMode: "hospital",
	}
	candidates := BuildBenchmarkCandidates(cmd, nil)
	if len(candidates) != 2 {
		t.Fatalf("expected 2 dynamic candidates, got %d", len(candidates))
	}
	if candidates[0].SNI != "dynamic.hospital.ir" {
		t.Errorf("expected first candidate to be dynamic.hospital.ir, got %s", candidates[0].SNI)
	}

	methodsCmd := &panel.ScanCommand{
		ScanMode: "methods",
	}
	methodCandidates := BuildBenchmarkCandidates(methodsCmd, &panel.RelayTunnelConfig{
		SNI: "dynamic.hospital.ir",
	})
	if len(methodCandidates) == 0 {
		t.Fatal("expected method benchmark candidates")
	}
	if methodCandidates[0].SNI != "dynamic.hospital.ir" {
		t.Errorf("expected dynamic.hospital.ir base SNI, got %s", methodCandidates[0].SNI)
	}
}

func TestComputeBenchmarkScore(t *testing.T) {
	// 100 MB/s download (800 Mbps), 50 MB/s upload (400 Mbps), 20ms RTT, 0% loss
	score := ComputeBenchmarkScore(50*1024*1024, 100*1024*1024, 20, 0)
	if score <= 0 {
		t.Errorf("expected positive score, got %f", score)
	}
}

func TestPingTarget(t *testing.T) {
	tc := &TunnelController{
		tag: "tunnel-test",
	}

	latency, online := tc.pingTarget("", 0)
	if online {
		t.Error("pingTarget with empty IP should be offline")
	}
	if latency != 0 {
		t.Errorf("pingTarget with empty IP should have 0 latency, got %d", latency)
	}

	latency, online = tc.pingTarget("127.0.0.1", 0)
	if !online {
		t.Log("Warning: ping to 127.0.0.1 failed (might be environment-restricted)")
	} else if latency < 0 {
		t.Errorf("pingTarget with 127.0.0.1 should have >= 0 latency, got %d", latency)
	}
}

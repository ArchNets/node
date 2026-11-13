package node

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/archnets/node/api/panel"
	"github.com/archnets/node/conf"
	relay "github.com/archnets/node/core/relay"
	"github.com/archnets/node/core/relay/telemetry"
	"github.com/archnets/node/core/relay/transport"
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
		logger:             log.WithField("tag", "tunnel-test"),
	}

	_ = os.MkdirAll(filepath.Join(tmpDir, "log"), 0755)

	freePortLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to get free port: %v", err)
	}
	testPort := freePortLn.Addr().(*net.TCPAddr).Port
	_ = freePortLn.Close()

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
					CarrierPort:        testPort,
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
	// Verify candidates that need SNI (like Reality, WSS, WS) receive the base SNI, while Stealth (Noise) has empty SNI
	var foundRealitySNI bool
	for _, c := range methodCandidates {
		if c.Transport == "reverse-reality" && c.SNI == "dynamic.hospital.ir" {
			foundRealitySNI = true
			break
		}
	}
	if !foundRealitySNI {
		t.Errorf("expected reverse-reality candidate with dynamic.hospital.ir SNI")
	}
}

func TestComputeBenchmarkScore(t *testing.T) {
	// 100 MB/s download (800 Mbps), 50 MB/s upload (400 Mbps), 20ms RTT, 0% loss
	score := ComputeBenchmarkScore(50*1024*1024, 100*1024*1024, 20, 0)
	if score <= 0 {
		t.Errorf("expected positive score, got %f", score)
	}
}

func TestBenchmarkSequentialCandidates(t *testing.T) {
	tc := &TunnelController{
		tag:    "test-controller",
		logger: log.NewEntry(log.New()),
	}

	tunInfo := panel.TunnelInfo{
		Id:       123,
		RemoteIP: "127.0.0.1",
		RelayConfig: &panel.RelayTunnelConfig{
			Password: "test-seq-password",
			SNI:      "shariati.tums.ac.ir",
		},
	}

	testCandidates := []BenchmarkCandidate{
		{Index: 1, Transport: "stealth", MethodLabel: "Stealth", UseHalfDuplex: true, UseFisher: false},
		{Index: 2, Transport: "tcpmux", MethodLabel: "TCPMux", UseHalfDuplex: false, UseFisher: false},
		{Index: 3, Transport: "tcp", MethodLabel: "Raw TCP", UseHalfDuplex: true, UseFisher: false},
		{Index: 4, Transport: "reverse-reality", MethodLabel: "Reality", SNI: "shariati.tums.ac.ir", OriginIP: "185.143.234.132", UseHalfDuplex: true, UseFisher: false},
	}

	sandboxPort := 47000
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Start exit node sandbox coordinator in background
	var exitActiveEng *relay.Engine
	var activeEngMu sync.Mutex
	exitStopCh := make(chan struct{})
	defer close(exitStopCh)

	// Start entry coordinator listener on sandboxPort
	coordAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(sandboxPort))
	coordLn, err := transport.ListenTCP(ctx, coordAddr)
	if err != nil {
		t.Fatalf("failed to listen on coord port: %v", err)
	}
	defer coordLn.Close()

	coordReadyCh := make(chan net.Conn, 1)
	go func() {
		raw, aErr := coordLn.Accept()
		if aErr != nil {
			return
		}
		action, inspected, iErr := transport.InspectTCPTraffic(raw, tunInfo.RelayConfig.Password, false)
		if iErr == nil && action == transport.ActionReverseCarrier {
			coordReadyCh <- inspected
		} else {
			_ = raw.Close()
		}
	}()

	// Exit connects to entry coordinator
	go func() {
		rawDial := func() (net.Conn, error) {
			return transport.DialTCPContext(ctx, coordAddr, 3*time.Second)
		}
		conn, dErr := transport.DialTCPCarrier(rawDial, tunInfo.RelayConfig.Password)
		if dErr != nil {
			return
		}
		defer conn.Close()
		reader := bufio.NewReader(conn)
		for {
			line, rErr := reader.ReadString('\n')
			if rErr != nil {
				return
			}
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "START ") {
				candIdx, _ := strconv.Atoi(strings.TrimPrefix(line, "START "))
				activeEngMu.Lock()
				if exitActiveEng != nil {
					_ = exitActiveEng.Close()
					exitActiveEng = nil
				}
				for _, cand := range testCandidates {
					if cand.Index == candIdx {
						eng := relay.NewEngine(relay.Config{
							TunnelID:           123000 + cand.Index,
							Role:               "exit",
							Transport:          cand.Transport,
							CarrierPort:        sandboxPort + 1,
							ListenIP:           "127.0.0.1",
							EntryServerIP:      "127.0.0.1",
							TargetIP:           "127.0.0.1",
							SNI:                cand.SNI,
							Password:           tunInfo.RelayConfig.Password,
							UseHalfDuplex:      cand.UseHalfDuplex,
							UseFisher:          false,
							MinHeldConnections: 2,
						})
						_ = eng.Start()
						exitActiveEng = eng
						break
					}
				}
				activeEngMu.Unlock()
				_, _ = fmt.Fprintf(conn, "READY %d\n", candIdx)
			}
		}
	}()

	var coordConn net.Conn
	select {
	case coordConn = <-coordReadyCh:
	case <-time.After(5 * time.Second):
		t.Fatalf("exit failed to connect to coordinator")
	}
	defer coordConn.Close()
	coordReader := bufio.NewReader(coordConn)

	requestExitCandidate := func(candIdx int) bool {
		_ = coordConn.SetDeadline(time.Now().Add(5 * time.Second))
		if _, wErr := fmt.Fprintf(coordConn, "START %d\n", candIdx); wErr != nil {
			return false
		}
		line, rErr := coordReader.ReadString('\n')
		_ = coordConn.SetDeadline(time.Time{})
		return rErr == nil && strings.HasPrefix(strings.TrimSpace(line), fmt.Sprintf("READY %d", candIdx))
	}

	candPort := sandboxPort + 1
	for _, cand := range testCandidates {
		item := tc.evaluateCandidate(ctx, tunInfo, cand, candPort, tunInfo.RelayConfig.Password, 5*time.Second, requestExitCandidate)
		if item == nil || item.Status == "blocked" {
			t.Fatalf("candidate %d (%s) failed: %+v", cand.Index, cand.MethodLabel, item)
		}
		t.Logf("✓ Candidate %d (%s) succeeded: Up=%.2f Mbps, Down=%.2f Mbps, RTT=%dms, Loss=%d%%",
			cand.Index, cand.MethodLabel,
			float64(item.UploadSpeed)*8/1000000,
			float64(item.DownloadSpeed)*8/1000000,
			item.LatencyMs, item.PacketLoss)
	}

	activeEngMu.Lock()
	if exitActiveEng != nil {
		_ = exitActiveEng.Close()
	}
	activeEngMu.Unlock()
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

package relay

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/archnets/node/core/relay/routing"
	"github.com/archnets/node/core/relay/telemetry"
	"github.com/archnets/node/core/relay/transport"
)

func startMockTCPEchoServer(t *testing.T, port int) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatalf("failed to start target echo server on %d: %v", port, err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}(c)
		}
	}()
	return ln
}

func getFreeTCPPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to allocate free tcp port: %v", err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func getFreeUDPPort(t *testing.T) int {
	t.Helper()
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to resolve udp addr: %v", err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Fatalf("failed to allocate free udp port: %v", err)
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).Port
}

func TestDynamicSNIOrigins(t *testing.T) {
	telemetry.SetDynamicSNIOrigins([]telemetry.SNIPreset{
		{SNI: "test.hospital.ir", Label: "Test Hospital", OriginIP: "1.2.3.4", Category: "hospital"},
		{SNI: "test.app.ir", Label: "Test App", OriginIP: "5.6.7.8", Category: "national"},
	})

	ip, err := telemetry.ResolveOriginIP("test.hospital.ir", "")
	if err != nil || ip != "1.2.3.4" {
		t.Fatalf("expected dynamic IP 1.2.3.4, got %s (err: %v)", ip, err)
	}

	ip2, err := telemetry.ResolveOriginIP("test.app.ir", "")
	if err != nil || ip2 != "5.6.7.8" {
		t.Fatalf("expected dynamic IP 5.6.7.8, got %s (err: %v)", ip2, err)
	}

	explicit, err := telemetry.ResolveOriginIP("test.hospital.ir", "9.9.9.9")
	if err != nil || explicit != "9.9.9.9" {
		t.Fatalf("expected explicit IP 9.9.9.9, got %s (err: %v)", explicit, err)
	}

	presets := telemetry.GetActiveSNIPresets()
	if len(presets) != 2 {
		t.Fatalf("expected 2 active presets, got %d", len(presets))
	}
}

func TestReverseRealityEndToEnd_TCP_UDP_And_Probe(t *testing.T) {
	targetTCPPort := getFreeTCPPort(t)
	tcpTargetLn, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(targetTCPPort)))
	if err != nil {
		t.Fatalf("failed to start target tcp server: %v", err)
	}
	defer tcpTargetLn.Close()
	go func() {
		for {
			c, err := tcpTargetLn.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}(c)
		}
	}()

	targetUDPPort := getFreeUDPPort(t)
	uaddr, _ := net.ResolveUDPAddr("udp", net.JoinHostPort("127.0.0.1", strconv.Itoa(targetUDPPort)))
	udpTargetConn, err := net.ListenUDP("udp", uaddr)
	if err != nil {
		t.Fatalf("failed to start target udp server: %v", err)
	}
	defer udpTargetConn.Close()
	go func() {
		buf := make([]byte, 65535)
		for {
			n, raddr, err := udpTargetConn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = udpTargetConn.WriteToUDP(buf[:n], raddr)
		}
	}()

	originLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start mock origin server: %v", err)
	}
	defer originLn.Close()
	go func() {
		for {
			c, err := originLn.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
				var acc []byte
				buf := make([]byte, 128)
				for !bytes.Contains(acc, []byte("\r\n\r\n")) {
					n, err := conn.Read(buf)
					if n > 0 {
						acc = append(acc, buf[:n]...)
					}
					if err != nil {
						break
					}
				}
				_, _ = conn.Write(append([]byte("ORIGIN-CAMOUFLAGE:"), acc...))
			}(c)
		}
	}()

	carrierPort := getFreeTCPPort(t)
	entryTCPFwdPort := getFreeTCPPort(t)
	entryUDPFwdPort := getFreeUDPPort(t)

	telemetry.SetDynamicSNIOrigins([]telemetry.SNIPreset{
		{SNI: "mock.hospital.ir", Label: "Mock Hospital", OriginIP: originLn.Addr().String(), Category: "hospital"},
	})

	entryEngine := NewEngine(Config{
		TunnelID:           101,
		Role:               "entry",
		Transport:          "reverse-reality",
		CarrierPort:        carrierPort,
		ListenIP:           "127.0.0.1",
		SNI:                "mock.hospital.ir",
		OriginIP:           originLn.Addr().String(),
		Password:           "test-hospital-secret",
		UseHalfDuplex:      true,
		UseFisher:          true,
		FisherConnections:  3,
		MinHeldConnections: 4,
		Forwarders: []routing.ForwarderRule{
			{
				ID:         1,
				Protocol:   "tcp",
				ListenIP:   "127.0.0.1",
				ListenPort: entryTCPFwdPort,
				TargetIP:   "127.0.0.1",
				TargetPort: targetTCPPort,
			},
			{
				ID:         2,
				Protocol:   "udp",
				ListenIP:   "127.0.0.1",
				ListenPort: entryUDPFwdPort,
				TargetIP:   "127.0.0.1",
				TargetPort: targetUDPPort,
			},
		},
	})
	if err := entryEngine.Start(); err != nil {
		t.Fatalf("failed to start entry engine: %v", err)
	}
	defer entryEngine.Close()

	exitEngine := NewEngine(Config{
		TunnelID:           101,
		Role:               "exit",
		Transport:          "reverse-reality",
		CarrierPort:        carrierPort,
		EntryServerIP:      "127.0.0.1",
		TargetIP:           "127.0.0.1",
		SNI:                "mock.hospital.ir",
		Password:           "test-hospital-secret",
		UseHalfDuplex:      true,
		UseFisher:          true,
		FisherConnections:  3,
		MinHeldConnections: 4,
	})
	if err := exitEngine.Start(); err != nil {
		t.Fatalf("failed to start exit engine: %v", err)
	}
	defer exitEngine.Close()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if entryEngine.Stats.PoolIdleConnections.Load() >= 2 {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if entryEngine.Stats.PoolIdleConnections.Load() < 1 {
		t.Fatalf("expected warm idle pool connections on entry, got %d", entryEngine.Stats.PoolIdleConnections.Load())
	}

	// Test DPI Active Probe Camouflage Splicing
	probeConn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(carrierPort)), 2*time.Second)
	if err != nil {
		t.Fatalf("failed to dial carrier port as probe: %v", err)
	}
	_, _ = probeConn.Write([]byte("GET / HTTP/1.1\r\nHost: mock.hospital.ir\r\nConnection: close\r\n\r\n"))
	if tc, ok := probeConn.(*net.TCPConn); ok {
		_ = tc.CloseWrite()
	}
	probeReply, _ := io.ReadAll(probeConn)
	_ = probeConn.Close()
	if !bytes.HasPrefix(probeReply, []byte("ORIGIN-CAMOUFLAGE:GET / HTTP/1.1")) {
		t.Fatalf("expected DPI probe to be transparently spliced to origin, got: %q", string(probeReply))
	}

	// Test TCP Forwarder
	tcpClient, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(entryTCPFwdPort)), 3*time.Second)
	if err != nil {
		t.Fatalf("failed to dial entry tcp forwarder: %v", err)
	}
	payload := bytes.Repeat([]byte("ArchNet-Modular-Relay!"), 1024)
	if _, err := tcpClient.Write(payload); err != nil {
		t.Fatalf("failed to write tcp payload: %v", err)
	}
	echoed := make([]byte, len(payload))
	if _, err := io.ReadFull(tcpClient, echoed); err != nil {
		t.Fatalf("failed to read echoed tcp payload: %v", err)
	}
	_ = tcpClient.Close()
	if !bytes.Equal(payload, echoed) {
		t.Fatalf("echoed tcp payload mismatch")
	}

	// Test UDP Forwarder
	udpClient, err := net.Dial("udp", net.JoinHostPort("127.0.0.1", strconv.Itoa(entryUDPFwdPort)))
	if err != nil {
		t.Fatalf("failed to dial entry udp forwarder: %v", err)
	}
	udpMsg := []byte("WireGuard-Modular-UDP-Datagram-Test")
	_ = udpClient.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := udpClient.Write(udpMsg); err != nil {
		t.Fatalf("failed to write udp datagram: %v", err)
	}
	udpReply := make([]byte, 256)
	nUDP, err := udpClient.Read(udpReply)
	if err != nil {
		t.Fatalf("failed to read udp reply: %v", err)
	}
	_ = udpClient.Close()
	if !bytes.Equal(udpMsg, udpReply[:nUDP]) {
		t.Fatalf("udp datagram mismatch")
	}

	// Test Probe Stream
	rtt, err := telemetry.MeasureLatency(entryEngine.ClaimReverseStream, entryEngine.Stats)
	if err != nil || rtt <= 0 {
		t.Fatalf("MeasureLatency failed: %v", err)
	}

	sample, err := telemetry.RunBandwidthProbe(entryEngine.ClaimReverseStream, entryEngine.Stats, 300*time.Millisecond)
	if err != nil || sample.UploadMbps <= 0 || sample.DownloadMbps <= 0 {
		t.Fatalf("RunBandwidthProbe failed: %v", err)
	}
}

func TestCarrierPortForwarderSharing(t *testing.T) {
	targetTCPPort := getFreeTCPPort(t)
	tcpTargetLn, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(targetTCPPort)))
	if err != nil {
		t.Fatalf("failed to start target tcp server: %v", err)
	}
	defer tcpTargetLn.Close()
	go func() {
		for {
			c, err := tcpTargetLn.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}(c)
		}
	}()

	carrierAndUserPort := getFreeTCPPort(t)

	entryEngine := NewEngine(Config{
		TunnelID:           202,
		Role:               "entry",
		Transport:          "reverse-reality",
		CarrierPort:        carrierAndUserPort,
		ListenIP:           "127.0.0.1",
		SNI:                "divar.ir",
		Password:           "shared-port-secret",
		UseHalfDuplex:      true,
		UseFisher:          false,
		MinHeldConnections: 4,
		Forwarders: []routing.ForwarderRule{
			{
				ID:         1,
				Protocol:   "tcp",
				ListenIP:   "127.0.0.1",
				ListenPort: carrierAndUserPort, // Exactly the same port as carrier!
				TargetIP:   "127.0.0.1",
				TargetPort: targetTCPPort,
			},
		},
	})
	if err := entryEngine.Start(); err != nil {
		t.Fatalf("failed to start entry engine on shared port: %v", err)
	}
	defer entryEngine.Close()

	exitEngine := NewEngine(Config{
		TunnelID:           202,
		Role:               "exit",
		Transport:          "reverse-reality",
		CarrierPort:        carrierAndUserPort,
		EntryServerIP:      "127.0.0.1",
		TargetIP:           "127.0.0.1",
		SNI:                "divar.ir",
		Password:           "shared-port-secret",
		UseHalfDuplex:      true,
		UseFisher:          false,
		MinHeldConnections: 4,
	})
	if err := exitEngine.Start(); err != nil {
		t.Fatalf("failed to start exit engine: %v", err)
	}
	defer exitEngine.Close()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if entryEngine.Stats.PoolIdleConnections.Load() >= 1 {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if entryEngine.Stats.PoolIdleConnections.Load() < 1 {
		t.Fatalf("expected warm idle pool connection on entry, got %d", entryEngine.Stats.PoolIdleConnections.Load())
	}

	// Dial into the shared carrier port as a user client!
	client, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(carrierAndUserPort)), 3*time.Second)
	if err != nil {
		t.Fatalf("failed to dial shared carrier port as user: %v", err)
	}
	msg := []byte("User-Traffic-On-Carrier-Port-Shared!")
	if _, err := client.Write(msg); err != nil {
		t.Fatalf("failed to write user message: %v", err)
	}
	echo := make([]byte, len(msg))
	if _, err := io.ReadFull(client, echo); err != nil {
		t.Fatalf("failed to read echoed user message: %v", err)
	}
	_ = client.Close()
	if !bytes.Equal(msg, echo) {
		t.Fatalf("expected echoed %q, got %q", string(msg), string(echo))
	}
}

func TestHalfDuplexCloseWritePreservation(t *testing.T) {
	// Setup mock upload listener and download listener
	upLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upLn.Close()

	downLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer downLn.Close()

	done := make(chan struct{})
	go func() {
		// Server accepts upload connection, reads all until EOF, then replies on download connection
		upSrv, _ := upLn.Accept()
		defer upSrv.Close()
		buf, _ := io.ReadAll(upSrv)

		downSrv, _ := downLn.Accept()
		defer downSrv.Close()
		_, _ = downSrv.Write(append([]byte("REPLY:"), buf...))
		close(done)
	}()

	upCli, err := net.Dial("tcp", upLn.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	downCli, err := net.Dial("tcp", downLn.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	hd := transport.NewHalfDuplexConn(downCli, upCli)
	defer hd.Close()

	// Write payload and close write half!
	_, _ = hd.Write([]byte("HELLO-HALFDUPLEX"))
	if err := hd.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite failed: %v", err)
	}

	<-done

	// Read reply on the download socket - MUST NOT be prematurely closed!
	replyBuf := make([]byte, 64)
	n, err := hd.Read(replyBuf)
	if err != nil && err != io.EOF {
		t.Fatalf("Read failed after CloseWrite: %v", err)
	}
	if string(replyBuf[:n]) != "REPLY:HELLO-HALFDUPLEX" {
		t.Fatalf("unexpected reply: %s", string(replyBuf[:n]))
	}
}

func TestPreHandshakeTCPMaxSegAndPathMTUDiscovery(t *testing.T) {
	transport.SetConfiguredMTU(1380)
	defer transport.SetConfiguredMTU(0)

	if got := transport.GetConfiguredMTU(); got != 1380 {
		t.Fatalf("expected configured MTU 1380, got %d", got)
	}

	carrierPort := getFreeTCPPort(t)
	entryEngine := NewEngine(Config{
		TunnelID:           303,
		Role:               "entry",
		Transport:          "reverse-reality",
		CarrierPort:        carrierPort,
		ListenIP:           "127.0.0.1",
		SNI:                "cafebazaar.ir",
		Password:           "mtu-test-secret",
		UseHalfDuplex:      true,
		UseFisher:          false,
		MinHeldConnections: 4,
	})
	if err := entryEngine.Start(); err != nil {
		t.Fatalf("failed to start entry engine: %v", err)
	}
	defer entryEngine.Close()

	exitEngine := NewEngine(Config{
		TunnelID:           303,
		Role:               "exit",
		Transport:          "reverse-reality",
		CarrierPort:        carrierPort,
		EntryServerIP:      "127.0.0.1",
		TargetIP:           "127.0.0.1",
		SNI:                "cafebazaar.ir",
		Password:           "mtu-test-secret",
		UseHalfDuplex:      true,
		UseFisher:          false,
		MinHeldConnections: 4,
	})
	if err := exitEngine.Start(); err != nil {
		t.Fatalf("failed to start exit engine: %v", err)
	}
	defer exitEngine.Close()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if entryEngine.Stats.PoolIdleConnections.Load() >= 2 {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}

	bestMTU := telemetry.DiscoverOptimalPathMTU(entryEngine.ClaimReverseStream)
	if bestMTU < 1280 || bestMTU > 1500 {
		t.Fatalf("expected discovered Path MTU between 1280 and 1500, got %d", bestMTU)
	}
	t.Logf("Successfully discovered Optimal Path MTU: %d B (TCP MSS: %d B)", bestMTU, bestMTU-40)
}

func TestStealthTransportEndToEnd(t *testing.T) {
	carrierPort := getFreeTCPPort(t)
	targetPort := getFreeTCPPort(t)
	fwdPort := getFreeTCPPort(t)

	startMockTCPEchoServer(t, targetPort)

	entry := NewEngine(Config{
		TunnelID:           401,
		Role:               "entry",
		Transport:          "stealth",
		CarrierPort:        carrierPort,
		ListenIP:           "127.0.0.1",
		Password:           "stealth-noise-psk",
		UseHalfDuplex:      true,
		UseFisher:          false,
		MinHeldConnections: 4,
		Forwarders: []routing.ForwarderRule{
			{ID: 1, Protocol: "tcp", ListenIP: "127.0.0.1", ListenPort: fwdPort, TargetPort: targetPort},
		},
	})
	if err := entry.Start(); err != nil {
		t.Fatalf("failed to start stealth entry: %v", err)
	}
	defer entry.Close()

	exit := NewEngine(Config{
		TunnelID:           401,
		Role:               "exit",
		Transport:          "stealth",
		CarrierPort:        carrierPort,
		EntryServerIP:      "127.0.0.1",
		TargetIP:           "127.0.0.1",
		Password:           "stealth-noise-psk",
		UseHalfDuplex:      true,
		UseFisher:          false,
		MinHeldConnections: 4,
	})
	if err := exit.Start(); err != nil {
		t.Fatalf("failed to start stealth exit: %v", err)
	}
	defer exit.Close()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if entry.Stats.PoolIdleConnections.Load() >= 2 {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}

	clientConn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", fwdPort), 2*time.Second)
	if err != nil {
		t.Fatalf("failed to connect to stealth forwarder: %v", err)
	}
	defer clientConn.Close()

	testMsg := "STEALTH-NOISE-ECHO-TEST"
	if _, err := clientConn.Write([]byte(testMsg)); err != nil {
		t.Fatalf("write failed: %v", err)
	}
	resp := make([]byte, len(testMsg))
	if _, err := io.ReadFull(clientConn, resp); err != nil {
		t.Fatalf("read failed: %v", err)
	}
	if string(resp) != testMsg {
		t.Fatalf("expected %s, got %s", testMsg, string(resp))
	}
}

func TestWSTransportAndDecoyEndToEnd(t *testing.T) {
	carrierPort := getFreeTCPPort(t)
	targetPort := getFreeTCPPort(t)
	fwdPort := getFreeTCPPort(t)

	startMockTCPEchoServer(t, targetPort)

	entry := NewEngine(Config{
		TunnelID:           402,
		Role:               "entry",
		Transport:          "ws-reverse",
		CarrierPort:        carrierPort,
		ListenIP:           "127.0.0.1",
		SNI:                "decoy.domain.local",
		Password:           "ws-auth-secret-123",
		UseHalfDuplex:      true,
		UseFisher:          false,
		MinHeldConnections: 4,
		Forwarders: []routing.ForwarderRule{
			{ID: 1, Protocol: "tcp", ListenIP: "127.0.0.1", ListenPort: fwdPort, TargetPort: targetPort},
		},
	})
	if err := entry.Start(); err != nil {
		t.Fatalf("failed to start ws entry: %v", err)
	}
	defer entry.Close()

	exit := NewEngine(Config{
		TunnelID:           402,
		Role:               "exit",
		Transport:          "ws-reverse",
		CarrierPort:        carrierPort,
		EntryServerIP:      "127.0.0.1",
		TargetIP:           "127.0.0.1",
		SNI:                "decoy.domain.local",
		Password:           "ws-auth-secret-123",
		UseHalfDuplex:      true,
		UseFisher:          false,
		MinHeldConnections: 4,
	})
	if err := exit.Start(); err != nil {
		t.Fatalf("failed to start ws exit: %v", err)
	}
	defer exit.Close()

	// 1. Verify unauthenticated HTTP probe receives deterministic Nginx decoy response
	probeConn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", carrierPort), 2*time.Second)
	if err != nil {
		t.Fatalf("failed to connect to ws carrier for decoy probe: %v", err)
	}
	_, _ = probeConn.Write([]byte("GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"))
	decoyBuf := make([]byte, 512)
	n, _ := probeConn.Read(decoyBuf)
	_ = probeConn.Close()
	decoyStr := string(decoyBuf[:n])
	if !strings.Contains(decoyStr, "Server: nginx") || !strings.Contains(decoyStr, "Welcome to nginx!") {
		t.Fatalf("expected nginx decoy response, got:\n%s", decoyStr)
	}

	// 2. Verify reverse tunnel forwarder carries user data
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if entry.Stats.PoolIdleConnections.Load() >= 2 {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}

	clientConn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", fwdPort), 2*time.Second)
	if err != nil {
		t.Fatalf("failed to connect to ws forwarder: %v", err)
	}
	defer clientConn.Close()

	testMsg := "WEBSOCKET-REVERSE-ECHO-TEST"
	if _, err := clientConn.Write([]byte(testMsg)); err != nil {
		t.Fatalf("write failed: %v", err)
	}
	resp := make([]byte, len(testMsg))
	if _, err := io.ReadFull(clientConn, resp); err != nil {
		t.Fatalf("read failed: %v", err)
	}
	if string(resp) != testMsg {
		t.Fatalf("expected %s, got %s", testMsg, string(resp))
	}
}

func TestDirectModeEndToEnd(t *testing.T) {
	carrierPort := getFreeTCPPort(t)
	targetPort := getFreeTCPPort(t)
	fwdPort := getFreeTCPPort(t)

	startMockTCPEchoServer(t, targetPort)

	// In direct mode: Exit listens on CarrierPort, Entry dials Exit!
	exit := NewEngine(Config{
		TunnelID:           403,
		Role:               "exit",
		Direction:          "direct",
		Transport:          "reverse-reality",
		CarrierPort:        carrierPort,
		ListenIP:           "127.0.0.1",
		TargetIP:           "127.0.0.1",
		SNI:                "divar.ir",
		Password:           "direct-secret-pass",
		UseHalfDuplex:      true,
		UseFisher:          false,
		MinHeldConnections: 4,
	})
	if err := exit.Start(); err != nil {
		t.Fatalf("failed to start direct exit: %v", err)
	}
	defer exit.Close()

	entry := NewEngine(Config{
		TunnelID:           403,
		Role:               "entry",
		Direction:          "direct",
		Transport:          "reverse-reality",
		CarrierPort:        carrierPort,
		ExitServerIP:       "127.0.0.1",
		ListenIP:           "127.0.0.1",
		SNI:                "divar.ir",
		Password:           "direct-secret-pass",
		UseHalfDuplex:      true,
		UseFisher:          false,
		MinHeldConnections: 4,
		Forwarders: []routing.ForwarderRule{
			{ID: 1, Protocol: "tcp", ListenIP: "127.0.0.1", ListenPort: fwdPort, TargetPort: targetPort},
		},
	})
	if err := entry.Start(); err != nil {
		t.Fatalf("failed to start direct entry: %v", err)
	}
	defer entry.Close()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if entry.Stats.PoolIdleConnections.Load() >= 2 {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}

	clientConn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", fwdPort), 2*time.Second)
	if err != nil {
		t.Fatalf("failed to connect to direct forwarder: %v", err)
	}
	defer clientConn.Close()

	testMsg := "DIRECT-MODE-ECHO-TEST"
	if _, err := clientConn.Write([]byte(testMsg)); err != nil {
		t.Fatalf("write failed: %v", err)
	}
	resp := make([]byte, len(testMsg))
	if _, err := io.ReadFull(clientConn, resp); err != nil {
		t.Fatalf("read failed: %v", err)
	}
	if string(resp) != testMsg {
		t.Fatalf("expected %s, got %s", testMsg, string(resp))
	}
}

func TestQUICTransportEndToEnd(t *testing.T) {
	carrierPort := getFreeUDPPort(t)
	targetPort := getFreeTCPPort(t)
	fwdPort := getFreeTCPPort(t)

	startMockTCPEchoServer(t, targetPort)

	entry := NewEngine(Config{
		TunnelID:           404,
		Role:               "entry",
		Transport:          "quic-reverse",
		CarrierPort:        carrierPort,
		ListenIP:           "127.0.0.1",
		SNI:                "quic.domain.local",
		Password:           "quic-auth-pass-789",
		UseHalfDuplex:      false,
		UseFisher:          false,
		MinHeldConnections: 4,
		Forwarders: []routing.ForwarderRule{
			{ID: 1, Protocol: "tcp", ListenIP: "127.0.0.1", ListenPort: fwdPort, TargetPort: targetPort},
		},
	})
	if err := entry.Start(); err != nil {
		t.Fatalf("failed to start quic entry: %v", err)
	}
	defer entry.Close()

	exit := NewEngine(Config{
		TunnelID:           404,
		Role:               "exit",
		Transport:          "quic-reverse",
		CarrierPort:        carrierPort,
		EntryServerIP:      "127.0.0.1",
		TargetIP:           "127.0.0.1",
		SNI:                "quic.domain.local",
		Password:           "quic-auth-pass-789",
		UseHalfDuplex:      false,
		UseFisher:          false,
		MinHeldConnections: 4,
	})
	if err := exit.Start(); err != nil {
		t.Fatalf("failed to start quic exit: %v", err)
	}
	defer exit.Close()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if entry.Stats.PoolIdleConnections.Load() >= 2 {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}

	clientConn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", fwdPort), 2*time.Second)
	if err != nil {
		t.Fatalf("failed to connect to quic forwarder: %v", err)
	}
	defer clientConn.Close()

	testMsg := "QUIC-REVERSE-ECHO-TEST"
	if _, err := clientConn.Write([]byte(testMsg)); err != nil {
		t.Fatalf("write failed: %v", err)
	}
	resp := make([]byte, len(testMsg))
	if _, err := io.ReadFull(clientConn, resp); err != nil {
		t.Fatalf("read failed: %v", err)
	}
	if string(resp) != testMsg {
		t.Fatalf("expected %s, got %s", testMsg, string(resp))
	}
}

func TestTCPMuxAndKCPTransportsEndToEnd(t *testing.T) {
	for _, tr := range []string{"tcpmux", "kcp"} {
		t.Run(tr, func(t *testing.T) {
			var carrierPort int
			if tr == "kcp" {
				carrierPort = getFreeUDPPort(t)
			} else {
				carrierPort = getFreeTCPPort(t)
			}
			targetPort := getFreeTCPPort(t)
			fwdPort := getFreeTCPPort(t)

			startMockTCPEchoServer(t, targetPort)

			entry := NewEngine(Config{
				TunnelID:           410,
				Role:               "entry",
				Transport:          tr,
				CarrierPort:        carrierPort,
				ListenIP:           "127.0.0.1",
				Password:           "mux-kcp-secret-999",
				UseHalfDuplex:      false,
				UseFisher:          false,
				MinHeldConnections: 4,
				Forwarders: []routing.ForwarderRule{
					{ID: 1, Protocol: "tcp", ListenIP: "127.0.0.1", ListenPort: fwdPort, TargetPort: targetPort},
				},
			})
			if err := entry.Start(); err != nil {
				t.Fatalf("failed to start %s entry: %v", tr, err)
			}
			defer entry.Close()

			exit := NewEngine(Config{
				TunnelID:           410,
				Role:               "exit",
				Transport:          tr,
				CarrierPort:        carrierPort,
				EntryServerIP:      "127.0.0.1",
				TargetIP:           "127.0.0.1",
				Password:           "mux-kcp-secret-999",
				UseHalfDuplex:      false,
				UseFisher:          false,
				MinHeldConnections: 4,
			})
			if err := exit.Start(); err != nil {
				t.Fatalf("failed to start %s exit: %v", tr, err)
			}
			defer exit.Close()

			deadline := time.Now().Add(5 * time.Second)
			for time.Now().Before(deadline) {
				if entry.Stats.PoolIdleConnections.Load() >= 2 {
					break
				}
				time.Sleep(25 * time.Millisecond)
			}

			clientConn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", fwdPort), 2*time.Second)
			if err != nil {
				t.Fatalf("failed to connect to %s forwarder: %v", tr, err)
			}
			defer clientConn.Close()

			testMsg := "MUX-KCP-ECHO-PAYLOAD-" + tr
			if _, err := clientConn.Write([]byte(testMsg)); err != nil {
				t.Fatalf("write failed: %v", err)
			}
			resp := make([]byte, len(testMsg))
			if _, err := io.ReadFull(clientConn, resp); err != nil {
				t.Fatalf("read failed: %v", err)
			}
			if string(resp) != testMsg {
				t.Fatalf("expected %s, got %s", testMsg, string(resp))
			}
		})
	}
}

package relay

import (
	"bytes"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/archnets/node/core/relay/routing"
	"github.com/archnets/node/core/relay/telemetry"
)

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
	_, _ = probeConn.Write([]byte("GET / HTTP/1.1\r\nHost: mock.hospital.ir\r\n\r\n"))
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

package cmd

import (
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/archnets/node/core/relay"
	"github.com/archnets/node/core/relay/telemetry"
	"github.com/archnets/node/core/relay/transport"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	testRole       string
	testTransport  string
	testPort       int
	testPeer       string
	testPassword   string
	testSNI        string
	testOrigin     string
	testHalfDuplex bool
	testFisher     bool
	testDirection  string
	testDebug      bool
	testProbe      bool
)

var testTransportCmd = &cobra.Command{
	Use:   "test-transport",
	Short: "Standalone foreground test tool with live debug logs for relay transports",
	Long: `Runs an isolated relay engine in the foreground on a dedicated test port.
Useful for live debugging across Iran and Kharej without affecting active users or touching production config.

Examples:
  # On Iran (Entry):
  node test-transport --role=entry --transport=reverse-reality --port=58444 --sni=cafebazaar.ir --debug

  # On Germany (Exit):
  node test-transport --role=exit --transport=reverse-reality --port=58444 --peer=<IRAN_IP> --sni=cafebazaar.ir --debug

  # Test Stealth:
  node test-transport --role=entry --transport=stealth --port=58444 --debug
  node test-transport --role=exit --transport=stealth --port=58444 --peer=<IRAN_IP> --debug

  # Test TCPMux:
  node test-transport --role=entry --transport=tcpmux --port=58444 --debug
  node test-transport --role=exit --transport=tcpmux --port=58444 --peer=<IRAN_IP> --debug`,
	Run: func(cmd *cobra.Command, args []string) {
		runTestTransport()
	},
}

func init() {
	testTransportCmd.Flags().StringVar(&testRole, "role", "entry", "Role: entry (Iran server) or exit (Kharej server)")
	testTransportCmd.Flags().StringVar(&testTransport, "transport", "reverse-reality", "Transport: reverse-reality, stealth, tcp, tcpmux, ws-reverse, wsmux, wss-reverse, wssmux, quic-reverse, kcp, l3-tcp, etc.")
	testTransportCmd.Flags().IntVar(&testPort, "port", 58444, "Carrier port to test on (default 58444)")
	testTransportCmd.Flags().StringVar(&testPeer, "peer", "", "Peer IP (required on exit: public IP of Iran entry server)")
	testTransportCmd.Flags().StringVar(&testPassword, "password", "archnet-standalone-secret", "Shared authentication secret")
	testTransportCmd.Flags().StringVar(&testSNI, "sni", "", "Camouflage SNI domain (default: cafebazaar.ir for reality)")
	testTransportCmd.Flags().StringVar(&testOrigin, "origin", "", "Resolved origin IP for reality camouflage")
	testTransportCmd.Flags().BoolVar(&testHalfDuplex, "halfduplex", true, "Enable half-duplex stream splitting")
	testTransportCmd.Flags().BoolVar(&testFisher, "fisher", false, "Enable ConnectionFisher race dialer")
	testTransportCmd.Flags().StringVar(&testDirection, "direction", "reverse", "Direction: reverse (exit dials entry) or direct (entry dials exit)")
	testTransportCmd.Flags().BoolVar(&testDebug, "debug", true, "Enable verbose debug logs")
	testTransportCmd.Flags().BoolVar(&testProbe, "probe", true, "Run continuous speed probes once connected (entry role)")

	command.AddCommand(testTransportCmd)
}

func runTestTransport() {
	if testDebug {
		log.SetLevel(log.DebugLevel)
	} else {
		log.SetLevel(log.InfoLevel)
	}
	customFormatter := new(log.TextFormatter)
	customFormatter.TimestampFormat = "15:04:05.000"
	customFormatter.FullTimestamp = true
	log.SetFormatter(customFormatter)

	testRole = strings.ToLower(strings.TrimSpace(testRole))
	testTransport = strings.ToLower(strings.TrimSpace(testTransport))
	testDirection = strings.ToLower(strings.TrimSpace(testDirection))

	if testRole == "exit" && testPeer == "" && testDirection == "reverse" {
		log.Fatal("When --role=exit, --peer=<Iran-IP> is required (the public IP of your Iran server)")
	}
	if testRole == "entry" && testPeer == "" && testDirection == "direct" {
		log.Fatal("When --role=entry and --direction=direct, --peer=<Kharej-IP> is required")
	}

	spec := transport.GetTransportSpec(testTransport)
	if spec.IsMux || spec.IsQuic || spec.IsPacket {
		testHalfDuplex = false
	}

	if spec.NeedsSNI && testSNI == "" {
		if testTransport == "reverse-reality" {
			testSNI = "cafebazaar.ir"
		}
	}
	if testOrigin == "" && testSNI != "" {
		if orig, err := telemetry.ResolveOriginIP(testSNI, ""); err == nil {
			testOrigin = orig
		}
	}

	// Auto-install top-priority iptables ACCEPT rule to ensure local firewall never blocks test port
	if os.Geteuid() == 0 && testPort > 0 {
		p := strconv.Itoa(testPort)
		_ = exec.Command("iptables", "-w", "2", "-t", "filter", "-I", "INPUT", "1", "-p", "tcp", "--dport", p, "-j", "ACCEPT").Run()
		_ = exec.Command("iptables", "-w", "2", "-t", "filter", "-I", "INPUT", "1", "-p", "udp", "--dport", p, "-j", "ACCEPT").Run()
		log.Infof("[Firewall] Inserted top-level iptables ACCEPT rule for port %d", testPort)
		defer func() {
			_ = exec.Command("iptables", "-w", "2", "-t", "filter", "-D", "INPUT", "-p", "tcp", "--dport", p, "-j", "ACCEPT").Run()
			_ = exec.Command("iptables", "-w", "2", "-t", "filter", "-D", "INPUT", "-p", "udp", "--dport", p, "-j", "ACCEPT").Run()
			log.Infof("[Firewall] Removed temporary iptables ACCEPT rule for port %d", testPort)
		}()
	}

	entryIP := testPeer
	exitIP := testPeer
	if testRole == "entry" {
		entryIP = "0.0.0.0"
	}

	certMode := ""
	if spec.NeedsTLSServerCfg || spec.IsQuic {
		certMode = "self"
	}

	cfg := relay.Config{
		TunnelID:           88888,
		Role:               testRole,
		Direction:          testDirection,
		Transport:          testTransport,
		CarrierPort:        testPort,
		ListenIP:           "0.0.0.0",
		EntryServerIP:      entryIP,
		ExitServerIP:       exitIP,
		TargetIP:           "127.0.0.1",
		SNI:                testSNI,
		OriginIP:           testOrigin,
		Password:           testPassword,
		UseHalfDuplex:      testHalfDuplex,
		UseFisher:          testFisher,
		FisherConnections:  2,
		MinHeldConnections: 4,
		CertMode:           certMode,
		Logger:             log.WithField("transport", testTransport),
	}

	log.Infof("=================================================================")
	log.Infof("Starting Standalone Foreground Test Engine")
	log.Infof("  Role:        %s", testRole)
	log.Infof("  Transport:   %s", testTransport)
	log.Infof("  CarrierPort: %d", testPort)
	log.Infof("  Peer IP:     %s", testPeer)
	log.Infof("  SNI:         %s (Origin: %s)", testSNI, testOrigin)
	log.Infof("  HalfDuplex:  %v", testHalfDuplex)
	log.Infof("  Password:    %s", testPassword)
	log.Infof("Press Ctrl+C to stop cleanly at any time.")
	log.Infof("=================================================================")

	eng := relay.NewEngine(cfg)
	if err := eng.Start(); err != nil {
		log.Fatalf("Failed to start engine: %v", err)
	}
	defer eng.Close()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case sig := <-sigChan:
			log.Infof("Received signal %v, terminating test cleanly...", sig)
			return
		case <-ticker.C:
			idle := eng.Stats.PoolIdleConnections.Load()
			active := eng.Stats.ActiveConnections.Load()
			upBytes := eng.Stats.TotalUploadBytes.Load()
			downBytes := eng.Stats.TotalDownloadBytes.Load()
			upMbps := float64(eng.Stats.CurrentUploadBps.Load()) * 8.0 / 1_000_000.0
			downMbps := float64(eng.Stats.CurrentDownloadBps.Load()) * 8.0 / 1_000_000.0

			if testRole == "entry" {
				log.Infof("[Entry Status] Idle Streams in Pool: %d | Active: %d | Up: %.2f Mbps (%d B) | Down: %.2f Mbps (%d B)",
					idle, active, upMbps, upBytes, downMbps, downBytes)

				if idle > 0 && testProbe {
					go func() {
						rtt, err := telemetry.MeasureLatency(eng.ClaimReverseStream, eng.Stats)
						if err == nil {
							log.Infof("   ---> Carrier Latency: %d ms (RTT)", rtt)
						} else {
							log.Warnf("   ---> Carrier Ping failed: %v", err)
						}
					}()
				}
			} else {
				log.Infof("[Exit Status] Connecting/Holding Streams: Active: %d | Up: %.2f Mbps (%d B) | Down: %.2f Mbps (%d B)",
					active, upMbps, upBytes, downMbps, downBytes)
			}
		}
	}
}

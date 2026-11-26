package core

import (
	"encoding/hex"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestWireGuardAssignIPAndPoolSubnet(t *testing.T) {
	core := &WireGuardCore{
		Address: "10.0.0.1/24",
	}

	tests := []struct {
		name string
		id   int
		want string
	}{
		{
			name: "ID 1 (First host)",
			id:   1,
			want: "10.0.0.2",
		},
		{
			name: "ID 2",
			id:   2,
			want: "10.0.0.4",
		},
		{
			name: "ID 127 (Last host in C=0)",
			id:   127,
			want: "10.0.0.254",
		},
		{
			name: "ID 128 (Next subnet C=1)",
			id:   128,
			want: "10.0.1.2",
		},
		{
			name: "ID 129 (Next subnet C=1, dIndex=1)",
			id:   129,
			want: "10.0.1.4",
		},
		{
			name: "ID 255 (Next subnet C=2)",
			id:   255,
			want: "10.0.2.2",
		},
		{
			name: "ID 32513 (Overflow C to B=1)",
			id:   32513,
			want: "10.1.0.2",
		},
		{
			name: "ID 0 (Invalid)",
			id:   0,
			want: "",
		},
		{
			name: "Negative ID (Invalid)",
			id:   -1,
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := core.assignIP(tt.id)
			if got != tt.want {
				t.Errorf("assignIP(%d) = %q, want %q", tt.id, got, tt.want)
			}
		})
	}

	subnetTests := []struct {
		address string
		want    string
	}{
		{"10.0.0.1/24", "10.0.0.0/13"},
		{"10.1.0.1/16", "10.1.0.0/16"},
		{"10.8.0.1/16", "10.8.0.0/16"},
		{"10.10.0.1/24", "10.10.0.0/16"},
		{"10.0.0.1/16", "10.0.0.0/13"},
		{"10.0.0.1/8", "10.0.0.0/8"},
		{"192.168.1.1/24", "192.168.0.0/16"},
		{"172.20.0.1/24", "172.20.0.0/16"},
	}

	for _, tt := range subnetTests {
		t.Run("Subnet_"+tt.address, func(t *testing.T) {
			got := getPoolSubnet(tt.address)
			if got != tt.want {
				t.Errorf("getPoolSubnet(%q) = %q, want %q", tt.address, got, tt.want)
			}
		})
	}
}

func TestFilterOnlineWGPeers_And_ParseAWGDump(t *testing.T) {
	now := time.Unix(1795695000, 0)

	kActive, _ := wgtypes.GeneratePrivateKey()
	kStaleData, _ := wgtypes.GeneratePrivateKey()
	kNoEndpoint, _ := wgtypes.GeneratePrivateKey()

	pubActive := kActive.PublicKey()
	pubStale := kStaleData.PublicKey()
	pubNoEp := kNoEndpoint.PublicKey()

	var keyToPeer sync.Map
	keyToPeer.Store(pubActive.String(), &WireGuardPeer{UID: 101, PublicKey: pubActive, IP: "10.0.0.2"})
	keyToPeer.Store(pubStale.String(), &WireGuardPeer{UID: 102, PublicKey: pubStale, IP: "10.0.0.4"})
	keyToPeer.Store(pubNoEp.String(), &WireGuardPeer{UID: 103, PublicKey: pubNoEp, IP: "10.0.0.6"})

	lastStats := map[string]*peerStats{
		pubActive.String(): {
			ReceiveBytes:  50000,
			TransmitBytes: 100000,
			LastHandshake: now.Add(-15 * time.Second),
			LastDataTime:  now.Add(-20 * time.Second),
		},
		pubStale.String(): {
			ReceiveBytes:  500000,
			TransmitBytes: 900000,
			LastHandshake: now.Add(-10 * time.Second), // keepalive/probe refreshed handshake
			LastDataTime:  now.Add(-5 * time.Minute),  // real data stopped 5m ago
		},
		pubNoEp.String(): {
			ReceiveBytes:  5000,
			TransmitBytes: 5000,
			LastHandshake: now.Add(-10 * time.Second),
			LastDataTime:  now.Add(-10 * time.Second),
		},
	}

	peers := []wgtypes.Peer{
		{
			PublicKey:         pubActive,
			Endpoint:          &net.UDPAddr{IP: net.ParseIP("::ffff:5.52.57.98"), Port: 51820},
			LastHandshakeTime: now.Add(-15 * time.Second),
			ReceiveBytes:      50000,
			TransmitBytes:     100000,
		},
		{
			PublicKey:         pubStale,
			Endpoint:          &net.UDPAddr{IP: net.ParseIP("5.52.57.99"), Port: 51820},
			LastHandshakeTime: now.Add(-10 * time.Second),
			ReceiveBytes:      500300,
			TransmitBytes:     900100,
		},
		{
			PublicKey:         pubNoEp,
			Endpoint:          nil,
			LastHandshakeTime: now.Add(-10 * time.Second),
			ReceiveBytes:      5000,
			TransmitBytes:     5000,
		},
	}

	online := filterOnlineWGPeers(peers, lastStats, &keyToPeer, now)
	if len(online) != 1 {
		t.Fatalf("expected exactly 1 online peer, got %d: %+v", len(online), online)
	}
	if online[0].UID != 101 || online[0].IP != "5.52.57.98" {
		t.Fatalf("unexpected online peer: %+v", online[0])
	}

	// Verify AmneziaWG dump parser enforces the same rules
	dump := pubActive.String() + "\t(none)\t5.52.57.98:4000\t10.0.0.2/32\t1795694985\t50000\t100000\t25\n" +
		pubStale.String() + "\t(none)\t5.52.57.99:4001\t10.0.0.4/32\t1795694990\t500300\t900100\t25\n" +
		pubNoEp.String() + "\t(none)\t(none)\t10.0.0.6/32\t1795694990\t5000\t5000\t25\n"

	awgOnline := parseAWGDumpOnlinePeers(dump, lastStats, &keyToPeer, now)
	if len(awgOnline) != 1 {
		t.Fatalf("expected exactly 1 online AWG peer, got %d: %+v", len(awgOnline), awgOnline)
	}
	if awgOnline[0].UID != 101 || awgOnline[0].IP != "5.52.57.98" {
		t.Fatalf("unexpected AWG online peer: %+v", awgOnline[0])
	}
}

func TestAmneziaWGUAPIConfigAndDump(t *testing.T) {
	priv, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	hpk, err := wgtypes.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	awgCore, err := NewAmneziaWGCore("awg-test", 51820, "10.0.0.1/24", "awg0", 1280, "1.1.1.1", priv.String(), AmneziaConfig{
		Jc:                     4,
		Jmin:                   10,
		Jmax:                   50,
		S1:                     15,
		S2:                     25,
		S3:                     12,
		S4:                     16,
		H1:                     "100-200",
		H2:                     "300-400",
		H3:                     "500-600",
		H4:                     "700-800",
		I1:                     "<b 0x1122>",
		HeaderProtectionKey:    hpk.String(),
		ContentPaddingAddition: "10-20",
		RekeyAfterTime:         "120",
		RandomTrailers:         true,
		DisableCookies:         true,
	})
	if err != nil {
		t.Fatal(err)
	}

	cfg, err := awgCore.buildUAPIDeviceConfig()
	if err != nil {
		t.Fatalf("buildUAPIDeviceConfig failed: %v", err)
	}

	expectedFragments := []string{
		"private_key=" + hex.EncodeToString(priv[:]),
		"listen_port=51820",
		"jc=4",
		"jmin=10",
		"jmax=50",
		"s1=15",
		"s2=25",
		"s3=12",
		"s4=16",
		"h1=100-200",
		"h2=300-400",
		"h3=500-600",
		"h4=700-800",
		"i1=<b 0x1122>",
		"header_protection_key=" + hex.EncodeToString(hpk[:]),
		"content_padding_addition=10-20",
		"rekey_after_time=120",
		"random_trailers=true",
		"disable_cookies=true",
	}
	for _, frag := range expectedFragments {
		if !strings.Contains(cfg, frag) {
			t.Errorf("expected UAPI config to contain %q, got:\n%s", frag, cfg)
		}
	}

	if _, err := uapiKeyToHex("not-a-valid-key"); err == nil {
		t.Fatal("expected error for invalid header protection key")
	}

	// Verify uapiGetToDump converts hex public keys & counters to `awg show dump` format
	peerPriv, _ := wgtypes.GeneratePrivateKey()
	peerPub := peerPriv.PublicKey()
	now := time.Unix(1795695000, 0)
	uapiOut := strings.Join([]string{
		"private_key=" + hex.EncodeToString(priv[:]),
		"listen_port=51820",
		"public_key=" + hex.EncodeToString(peerPub[:]),
		"preshared_key=0000000000000000000000000000000000000000000000000000000000000000",
		"protocol_version=1",
		"endpoint=5.52.57.98:51820",
		"last_handshake_time_sec=1795694985",
		"last_handshake_time_nsec=0",
		"tx_bytes=100000",
		"rx_bytes=50000",
		"persistent_keepalive_interval=25",
		"allowed_ip=10.0.0.2/32",
		"errno=0",
	}, "\n")

	dump := uapiGetToDump(uapiOut)
	var keyToPeer sync.Map
	keyToPeer.Store(peerPub.String(), &WireGuardPeer{PublicKey: peerPub, UID: 202, IP: "10.0.0.2"})
	lastStats := map[string]*peerStats{
		peerPub.String(): {
			ReceiveBytes:  50000,
			TransmitBytes: 100000,
			LastHandshake: now.Add(-15 * time.Second),
			LastDataTime:  now.Add(-10 * time.Second),
		},
	}

	online := parseAWGDumpOnlinePeers(dump, lastStats, &keyToPeer, now)
	if len(online) != 1 || online[0].UID != 202 || online[0].IP != "5.52.57.98" {
		t.Fatalf("expected online peer UID=202 IP=5.52.57.98, got %+v (dump:\n%s)", online, dump)
	}
}

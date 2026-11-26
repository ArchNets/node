package core

import (
	"net"
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

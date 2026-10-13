package core

import (
	"testing"
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
		{"10.0.0.1/24", "10.0.0.0/16"},
		{"10.10.0.1/24", "10.10.0.0/16"},
		{"10.0.0.1/16", "10.0.0.0/16"},
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

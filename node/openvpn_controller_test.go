package node

import (
	"testing"
)

func TestDeriveSubnets(t *testing.T) {
	tests := []struct {
		name       string
		base       string
		wantUDP    string
		wantTCP    string
	}{
		{
			name:    "empty base defaults to 10.9.0.0/24 and 10.9.1.0/24",
			base:    "",
			wantUDP: "10.9.0.0/24",
			wantTCP: "10.9.1.0/24",
		},
		{
			name:    "standard 10.9.1.0/24 derives 10.9.2.0/24 for TCP",
			base:    "10.9.1.0/24",
			wantUDP: "10.9.1.0/24",
			wantTCP: "10.9.2.0/24",
		},
		{
			name:    "edge third octet 254 shifts down to 253",
			base:    "10.9.254.0/24",
			wantUDP: "10.9.254.0/24",
			wantTCP: "10.9.253.0/24",
		},
		{
			name:    "invalid CIDR falls back safely",
			base:    "invalid-cidr",
			wantUDP: "10.9.1.0/24",
			wantTCP: "10.9.2.0/24",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotUDP, gotTCP := deriveSubnets(tt.base)
			if gotUDP != tt.wantUDP {
				t.Errorf("deriveSubnets(%q) gotUDP = %v, want %v", tt.base, gotUDP, tt.wantUDP)
			}
			if gotTCP != tt.wantTCP {
				t.Errorf("deriveSubnets(%q) gotTCP = %v, want %v", tt.base, gotTCP, tt.wantTCP)
			}
		})
	}
}

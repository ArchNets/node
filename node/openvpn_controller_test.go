package node

import (
	"testing"

	"github.com/archnets/node/api/panel"
	"github.com/archnets/node/common/format"
	"github.com/archnets/node/limiter"
)

func TestDeriveSubnets(t *testing.T) {
	tests := []struct {
		name    string
		base    string
		wantUDP string
		wantTCP string
	}{
		{
			name:    "empty base defaults to 10.9.0.0/17 and 10.9.128.0/17",
			base:    "",
			wantUDP: "10.9.0.0/17",
			wantTCP: "10.9.128.0/17",
		},
		{
			name:    "/16 base splits into non-overlapping /17 subnets",
			base:    "10.9.0.0/16",
			wantUDP: "10.9.0.0/17",
			wantTCP: "10.9.128.0/17",
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
			wantUDP: "10.9.0.0/17",
			wantTCP: "10.9.128.0/17",
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

func TestOpenVPNLimiterTagMatch(t *testing.T) {
	tag := "openvpn-27-6444"
	users := []panel.UserInfo{
		{Id: 1, Uuid: "user-uuid-1", DeviceLimit: 0},
	}
	l := limiter.AddLimiter("openvpn", tag, users, nil)

	// Case 1: Wrong tag (openvpn-27-6444-tcp) causes instant rejection because key not found!
	wrongTagUUID := format.UserTag(tag+"-tcp", "user-uuid-1")
	_, reject := l.CheckLimit(wrongTagUUID, "127.0.0.1", true)
	if !reject {
		t.Fatalf("expected wrong tag to be rejected")
	}

	// Case 2: Correct base tag (openvpn-27-6444) passes cleanly!
	correctTagUUID := format.UserTag(tag, "user-uuid-1")
	_, reject2 := l.CheckLimit(correctTagUUID, "127.0.0.1", true)
	if reject2 {
		t.Fatalf("expected correct base tag NOT to be rejected")
	}
}

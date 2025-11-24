package limiter

import (
	"testing"
)

func TestIsConnectivityCheck(t *testing.T) {
	tests := []struct {
		name     string
		host     string
		expected bool
	}{
		{"Google connectivity check", "connectivitycheck.gstatic.com", true},
		{"Apple captive portal", "captive.apple.com", true},
		{"Apple hotspot detect", "captive.apple.com/hotspot-detect.html", true},
		{"Microsoft connectivity", "www.msftconnecttest.com", true},
		{"Android connectivity", "connectivitycheck.android.com", true},
		{"Firefox detect portal", "detectportal.firefox.com", true},
		{"Cloudflare portal", "cp.cloudflare.com", true},
		{"Regular domain", "example.com", false},
		{"Regular API", "api.myservice.com", false},
		{"Empty string", "", false},
		{"Case insensitive", "CAPTIVE.APPLE.COM", true},
		{"Subdomain match", "test.gstatic.com", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isConnectivityCheck(tt.host)
			if result != tt.expected {
				t.Errorf("isConnectivityCheck(%q) = %v, want %v", tt.host, result, tt.expected)
			}
		})
	}
}

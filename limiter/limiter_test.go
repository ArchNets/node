package limiter

import (
	"sync"
	"testing"

	"github.com/archnets/node/api/panel"
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



func TestGetOnlineDevice(t *testing.T) {
	Init()

	users := []panel.UserInfo{
		{Id: 201, Uuid: "uuid201"},
	}
	aliveList := map[int]int{
		201: 1,
	}

	l := AddLimiter("vless", "vless:14", users, aliveList)

	ipMap := new(sync.Map)
	ipMap.Store("3.3.3.3", 201)
	l.UserOnlineIP.Store("vless:14|uuid201", ipMap)

	onlinePtr, err := l.GetOnlineDevice()
	if err != nil {
		t.Fatalf("GetOnlineDevice failed: %v", err)
	}

	online := *onlinePtr
	if len(online) != 1 {
		t.Fatalf("Expected 1 online user, got %d", len(online))
	}

	if online[0].UID != 201 || online[0].IP != "3.3.3.3" {
		t.Errorf("Expected user 201 with IP 3.3.3.3, got %+v", online[0])
	}

	// Verify UserOnlineIP is drained
	empty := true
	l.UserOnlineIP.Range(func(key, value interface{}) bool {
		empty = false
		return false
	})
	if !empty {
		t.Errorf("Expected UserOnlineIP to be drained/empty")
	}

	// Verify OldUserOnline is populated
	if val, ok := l.OldUserOnline.Load("3.3.3.3"); !ok || val.(int) != 201 {
		t.Errorf("Expected OldUserOnline to store 3.3.3.3 -> 201")
	}
}

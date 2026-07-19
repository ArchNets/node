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

func TestGetOnlineDevicesForTags(t *testing.T) {
	Init()

	users := []panel.UserInfo{
		{Id: 101, Uuid: "uuid1"},
		{Id: 102, Uuid: "uuid2"},
	}
	aliveList := map[int]int{
		101: 1,
		102: 1,
	}

	l1 := AddLimiter("vless", "vless:13", users, aliveList)
	l2 := AddLimiter("vless", "vless-2:13", users, aliveList)

	ipMap1 := new(sync.Map)
	ipMap1.Store("1.1.1.1", 101)
	l1.UserOnlineIP.Store("vless:13|uuid1", ipMap1)

	ipMap2 := new(sync.Map)
	ipMap2.Store("2.2.2.2", 102)
	l2.UserOnlineIP.Store("vless-2:13|uuid2", ipMap2)

	online, err := GetOnlineDevicesForTags([]string{"vless:13", "vless-2:13"})
	if err != nil {
		t.Fatalf("GetOnlineDevicesForTags failed: %v", err)
	}

	if len(online) != 2 {
		t.Errorf("Expected 2 online users, got %d", len(online))
	}

	// Verify entries exist
	found101 := false
	found102 := false
	for _, ou := range online {
		if ou.UID == 101 && ou.IP == "1.1.1.1" {
			found101 = true
		}
		if ou.UID == 102 && ou.IP == "2.2.2.2" {
			found102 = true
		}
	}

	if !found101 {
		t.Errorf("Expected user 101 with IP 1.1.1.1 to be online")
	}
	if !found102 {
		t.Errorf("Expected user 102 with IP 2.2.2.2 to be online")
	}

	// Verify UserOnlineIP is drained
	l1Empty := true
	l1.UserOnlineIP.Range(func(key, value interface{}) bool {
		l1Empty = false
		return false
	})
	if !l1Empty {
		t.Errorf("Expected l1.UserOnlineIP to be drained/empty")
	}

	l2Empty := true
	l2.UserOnlineIP.Range(func(key, value interface{}) bool {
		l2Empty = false
		return false
	})
	if !l2Empty {
		t.Errorf("Expected l2.UserOnlineIP to be drained/empty")
	}

	// Verify OldUserOnline is populated
	if val, ok := l1.OldUserOnline.Load("1.1.1.1"); !ok || val.(int) != 101 {
		t.Errorf("Expected OldUserOnline to store 1.1.1.1 -> 101 in l1")
	}
	if val, ok := l2.OldUserOnline.Load("2.2.2.2"); !ok || val.(int) != 102 {
		t.Errorf("Expected OldUserOnline to store 2.2.2.2 -> 102 in l2")
	}
}

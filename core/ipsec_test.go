package core

import (
	"testing"
	"time"
)

func TestIPsecProcessSasStats_ActiveThreshold(t *testing.T) {
	c := NewIPsecCore(IPsecConfig{Tag: "ipsec-test"})
	c.users[1] = &IPsecUser{UID: 1, Username: "user1"}
	c.users[2] = &IPsecUser{UID: 2, Username: "user2"}

	// Small probe (2 KB <= 8 KB) should not mark user1 active
	c.processSasStats([]parsedSA{
		{Username: "user1", RemoteIP: "1.2.3.4", InBytes: 1000, OutBytes: 1000},
		{Username: "user2", RemoteIP: "5.6.7.8", InBytes: 5000, OutBytes: 10000},
	})

	if st := c.lastSasStats["user1"]; st == nil || !st.LastDataTime.IsZero() {
		t.Fatalf("expected user1 with 2KB not to trigger LastDataTime, got %+v", st)
	}
	if st := c.lastSasStats["user2"]; st == nil || st.LastDataTime.IsZero() || time.Since(st.LastDataTime) > time.Second {
		t.Fatalf("expected user2 with 15KB to trigger LastDataTime, got %+v", st)
	}

	// Disconnecting user1 cleans up its lastSasStats entry
	c.processSasStats([]parsedSA{
		{Username: "user2", RemoteIP: "5.6.7.8", InBytes: 5000, OutBytes: 10000},
	})
	if _, exists := c.lastSasStats["user1"]; exists {
		t.Fatalf("expected disconnected user1 to be pruned from lastSasStats")
	}
}

package dispatcher

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/xtls/xray-core/common/net"
)

func TestUserResolver(t *testing.T) {
	// Set mock resolver
	SetUserResolver(func(email string, clientIP string) (UserDetails, bool) {
		if email == "vless_tcp|test-uuid-1" {
			return UserDetails{
				UID:  42,
				UUID: "test-uuid-1",
				Tag:  "vless_tcp",
			}, true
		}
		if clientIP == "10.0.0.4" {
			return UserDetails{
				UID:  99,
				UUID: "tunnel-uuid-99",
				Tag:  "wg-40-443",
			}, true
		}
		return UserDetails{}, false
	})

	// Test resolving by email
	details, found := resolveUser("vless_tcp|test-uuid-1", "1.2.3.4")
	assert.True(t, found)
	assert.Equal(t, 42, details.UID)
	assert.Equal(t, "test-uuid-1", details.UUID)
	assert.Equal(t, "vless_tcp", details.Tag)

	// Test resolving by tunnel client IP
	details, found = resolveUser("", "10.0.0.4")
	assert.True(t, found)
	assert.Equal(t, 99, details.UID)
	assert.Equal(t, "tunnel-uuid-99", details.UUID)
	assert.Equal(t, "wg-40-443", details.Tag)

	// Test unknown
	_, found = resolveUser("unknown", "1.1.1.1")
	assert.False(t, found)
}

func TestEnrichedAccessMessageFormatting(t *testing.T) {
	// Test destination formatting when domain was sniffed
	destination := net.TCPDestination(net.ParseAddress("10.17ce.martianinc.co"), 9166)
	originalTarget := net.TCPDestination(net.ParseAddress("178.162.202.97"), 9166)
	protocol := "tls"

	destStr := destination.String()
	origAddr := ""
	if originalTarget.IsValid() && originalTarget.Address != destination.Address {
		origAddr = originalTarget.Address.String()
	}
	var formattedTo strings.Builder
	formattedTo.WriteString(destStr)
	if origAddr != "" {
		formattedTo.WriteString(" (")
		formattedTo.WriteString(origAddr)
		formattedTo.WriteString(")")
	}
	if protocol != "" {
		formattedTo.WriteString(" [")
		formattedTo.WriteString(protocol)
		formattedTo.WriteString("]")
	}

	assert.Equal(t, "tcp:10.17ce.martianinc.co:9166 (178.162.202.97) [tls]", formattedTo.String())

	// Test destination formatting when no domain was sniffed (direct IP connection)
	ipDest := net.TCPDestination(net.ParseAddress("178.162.202.97"), 9166)
	var formattedToIP strings.Builder
	formattedToIP.WriteString(ipDest.String())
	assert.Equal(t, "tcp:178.162.202.97:9166", formattedToIP.String())
}

func TestTelemetryRecorderCallback(t *testing.T) {
	var received TelemetryRecord
	var called bool

	SetTelemetryRecorder(func(record TelemetryRecord) {
		called = true
		received = record
	})

	testRecord := TelemetryRecord{
		UID:             20306,
		ClientIP:        "5.126.109.232",
		DestinationHost: "i.instagram.com",
		DestinationIP:   "157.240.22.174",
		Port:            443,
		Protocol:        "tls",
		Blocked:         false,
		Timestamp:       1725297600,
	}

	recordTelemetry(testRecord)

	assert.True(t, called)
	assert.Equal(t, int64(20306), received.UID)
	assert.Equal(t, "5.126.109.232", received.ClientIP)
	assert.Equal(t, "i.instagram.com", received.DestinationHost)
	assert.Equal(t, "157.240.22.174", received.DestinationIP)
	assert.Equal(t, 443, received.Port)
	assert.Equal(t, "tls", received.Protocol)
	assert.False(t, received.Blocked)
}


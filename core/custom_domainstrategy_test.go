package core

import (
	"testing"

	"github.com/archnets/node/api/panel"
	"github.com/stretchr/testify/assert"
)

// A valid standard-base64, 32-byte WireGuard pre-shared key.
const testPresharedKey = "cISl4uid6UiSYnWsGwCjLV8jJ9Vr6ummjL7bx0Yxq+M="

const (
	testDualStackAddress = "172.16.0.2/32,2606:4700:110:8f86::1/128"
	testV4OnlyAddress    = "172.16.0.2/32"
	testEndpoint         = "162.159.192.1:2408"
)

func newWgOutbound(address, strategy string) panel.Outbound {
	return panel.Outbound{
		Name:                   "wg_test",
		Protocol:               "wireguard",
		WireguardPrivateKey:    "private_key",
		WireguardAddress:       address,
		WireguardMTU:           1420,
		WireguardPeerPublicKey: "peer_pub_key",
		WireguardPeerEndpoint:  testEndpoint,
		DomainStrategy:         strategy,
	}
}

// The panel-selected strategy must be passed through verbatim, and nothing may be
// inferred from the address list except when the panel sent no strategy at all.
func TestWireguardDomainStrategy_PassThrough(t *testing.T) {
	cases := []struct {
		name     string
		address  string
		strategy string
		want     string
	}{
		{"ForceIPv6v4 dual stack", testDualStackAddress, "ForceIPv6v4", "ForceIPv6v4"},
		{"ForceIPv6v4 v4-only address is still honoured", testV4OnlyAddress, "ForceIPv6v4", "ForceIPv6v4"},
		{"ForceIPv6", testDualStackAddress, "ForceIPv6", "ForceIPv6"},
		{"ForceIPv4", testDualStackAddress, "ForceIPv4", "ForceIPv4"},
		{"ForceIPv4v6", testV4OnlyAddress, "ForceIPv4v6", "ForceIPv4v6"},
		{"ForceIP", testDualStackAddress, "ForceIP", "ForceIP"},
		{"case insensitive", testDualStackAddress, "forceipv6v4", "ForceIPv6v4"},
		{"surrounding whitespace tolerated", testDualStackAddress, "  ForceIPv6v4  ", "ForceIPv6v4"},
		{"empty keeps legacy dual-stack default", testDualStackAddress, "", "ForceIPv4v6"},
		{"empty keeps legacy v4-only default", testV4OnlyAddress, "", "ForceIPv4"},
		{"Use* rejected for wireguard", testDualStackAddress, "UseIPv6v4", "ForceIPv4v6"},
		{"garbage rejected", testV4OnlyAddress, "nonsense", "ForceIPv4"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			settings, err := BuildWireguardOutboundJSON(newWgOutbound(tc.address, tc.strategy), testEndpoint)
			assert.NoError(t, err)
			assert.Equal(t, tc.want, settings["domainStrategy"])
		})
	}
}

func TestWireguardPresharedKey(t *testing.T) {
	peerOf := func(out panel.Outbound) map[string]interface{} {
		settings, err := BuildWireguardOutboundJSON(out, testEndpoint)
		assert.NoError(t, err)
		peers := settings["peers"].([]interface{})
		assert.Len(t, peers, 1)
		return peers[0].(map[string]interface{})
	}

	out := newWgOutbound(testV4OnlyAddress, "ForceIPv6v4")

	// A valid key is emitted as peers[].preSharedKey.
	out.WireguardPeerPresharedKey = testPresharedKey
	assert.Equal(t, testPresharedKey, peerOf(out)["preSharedKey"])

	// An empty key must be omitted entirely, never sent as "".
	out.WireguardPeerPresharedKey = ""
	_, ok := peerOf(out)["preSharedKey"]
	assert.False(t, ok)

	// A malformed key is dropped with a warning instead of breaking the outbound.
	out.WireguardPeerPresharedKey = "not-base64!!"
	_, ok = peerOf(out)["preSharedKey"]
	assert.False(t, ok)

	// Correct base64 but the wrong length is also rejected.
	out.WireguardPeerPresharedKey = "c2hvcnQ="
	_, ok = peerOf(out)["preSharedKey"]
	assert.False(t, ok)
}

// An IPv6 tunnel address on a wireguard outbound counts as IPv6 egress even when the
// host itself has no public IPv6, because that tunnel lives in a userspace TUN.
func TestHasIPv6Egress_FromTunnelAddress(t *testing.T) {
	dual := &panel.ServerConfigResponse{
		Data: &panel.Data{
			Outbound: &[]panel.Outbound{newWgOutbound(testDualStackAddress, "")},
		},
	}
	assert.True(t, hasIPv6Egress(dual))

	v4Only := &panel.ServerConfigResponse{
		Data: &panel.Data{
			Outbound: &[]panel.Outbound{newWgOutbound(testV4OnlyAddress, "")},
		},
	}
	assert.Equal(t, hasPublicIPv6(), hasIPv6Egress(v4Only))

	assert.Equal(t, hasPublicIPv6(), hasIPv6Egress(&panel.ServerConfigResponse{Data: &panel.Data{}}))
	assert.Equal(t, hasPublicIPv6(), hasIPv6Egress(nil))
}

func TestDomainStrategyNormalizers(t *testing.T) {
	// sockopt accepts the full AsIs / Use* / Force* set.
	for _, in := range []string{"AsIs", "UseIP", "UseIPv4", "UseIPv6", "UseIPv4v6", "UseIPv6v4",
		"ForceIP", "ForceIPv4", "ForceIPv6", "ForceIPv4v6", "ForceIPv6v4", "  forceipv6v4 "} {
		_, ok := normalizeSockoptDomainStrategy(in)
		assert.True(t, ok, in)
	}
	for _, in := range []string{"", "   ", "bogus", "prefer_ipv6"} {
		_, ok := normalizeSockoptDomainStrategy(in)
		assert.False(t, ok, in)
	}

	// The wireguard outbound accepts Force* only.
	for _, in := range []string{"AsIs", "UseIP", "UseIPv6v4", "", "bogus"} {
		_, ok := normalizeForceDomainStrategy(in)
		assert.False(t, ok, in)
	}
	v, ok := normalizeForceDomainStrategy("forceipv6v4")
	assert.True(t, ok)
	assert.Equal(t, "ForceIPv6v4", v)
}

func TestWireguardAddresses(t *testing.T) {
	addrs, hasIPv6 := wireguardAddresses("100.111.133.170/32, fd54:4::7981:ba43:f88a:8ab/128")
	assert.Equal(t, []string{"100.111.133.170/32", "fd54:4::7981:ba43:f88a:8ab/128"}, addrs)
	assert.True(t, hasIPv6)

	addrs, hasIPv6 = wireguardAddresses("172.16.0.2/32")
	assert.Equal(t, []string{"172.16.0.2/32"}, addrs)
	assert.False(t, hasIPv6)

	addrs, hasIPv6 = wireguardAddresses("")
	assert.Empty(t, addrs)
	assert.False(t, hasIPv6)

	addrs, hasIPv6 = wireguardAddresses(" , ,")
	assert.Empty(t, addrs)
	assert.False(t, hasIPv6)
}

func TestIsHostnameEndpoint(t *testing.T) {
	assert.True(t, isHostnameEndpoint("engage.cloudflareclient.com:2408"))
	assert.True(t, isHostnameEndpoint("jfk-106-wg.whiskergalaxy.com:443"))
	assert.False(t, isHostnameEndpoint("162.159.192.1:2408"))
	assert.False(t, isHostnameEndpoint("[2606:4700:d0::a29f:c001]:2408"))
	assert.False(t, isHostnameEndpoint("no-port-here"))
}

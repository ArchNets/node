package core

import (
	"testing"

	"github.com/archnets/node/api/panel"
	"github.com/stretchr/testify/assert"
)

func TestGetCustomConfig_Wireguard(t *testing.T) {
	// Test case 1: WireGuard with IPv4 only
	outboundIPv4 := panel.Outbound{
		Name:                   "warp_v4",
		Protocol:               "wireguard",
		WireguardPrivateKey:    "private_key_v4",
		WireguardAddress:       "172.16.0.2/32",
		WireguardMTU:           1420,
		WireguardPeerPublicKey: "peer_pub_key",
		WireguardPeerEndpoint:  "162.159.192.1:2408",
		WireguardReserved:      "1,2,3",
	}

	serverConfigIPv4 := &panel.ServerConfigResponse{
		Data: &panel.Data{
			Outbound: &[]panel.Outbound{outboundIPv4},
		},
	}

	dnsCfg, outboundCfg, routerCfg, wgOutbounds, err := GetCustomConfig(serverConfigIPv4)
	assert.NoError(t, err)
	assert.NotNil(t, dnsCfg)
	assert.NotNil(t, outboundCfg)
	assert.NotNil(t, routerCfg)
	assert.NotNil(t, wgOutbounds)

	// Verify the outbound was compiled
	wgOut, ok := wgOutbounds["warp_v4"]
	assert.True(t, ok)
	assert.Equal(t, "warp_v4", wgOut.Config.Tag)

	// Unmarshal and assert properties using BuildWireguardOutboundJSON
	settings, err := BuildWireguardOutboundJSON(outboundIPv4, "162.159.192.1:2408")
	assert.NoError(t, err)
	assert.Equal(t, "private_key_v4", settings["secretKey"])
	assert.Equal(t, "ForceIPv4", settings["domainStrategy"])
	assert.Equal(t, 1420, settings["mtu"])
	assert.Equal(t, []string{"172.16.0.2/32"}, settings["address"])
	assert.Equal(t, []int{1, 2, 3}, settings["reserved"])
	assert.True(t, settings["noKernelTun"].(bool))

	peers := settings["peers"].([]interface{})
	assert.Len(t, peers, 1)
	peer := peers[0].(map[string]interface{})
	assert.Equal(t, "peer_pub_key", peer["publicKey"])
	assert.Equal(t, "162.159.192.1:2408", peer["endpoint"])
	assert.Equal(t, 25, peer["keepAlive"])
}

func TestGetCustomConfig_Wireguard_IPv6(t *testing.T) {
	// Test case 2: WireGuard with dual stack (IPv4 and IPv6) - replace with static IP so no live DNS lookups are done
	outboundDual := panel.Outbound{
		Name:                   "warp_dual",
		Protocol:               "wireguard",
		WireguardPrivateKey:    "private_key_dual",
		WireguardAddress:       "172.16.0.2/32,2606:4700:110:8f86:3ab3:7f16:c22c:c339/128",
		WireguardMTU:           1420,
		WireguardPeerPublicKey: "peer_pub_key",
		WireguardPeerEndpoint:  "162.159.192.1:2408",
	}

	serverConfigDual := &panel.ServerConfigResponse{
		Data: &panel.Data{
			Outbound: &[]panel.Outbound{outboundDual},
		},
	}

	_, _, _, wgOutbounds, err := GetCustomConfig(serverConfigDual)
	assert.NoError(t, err)
	assert.NotNil(t, wgOutbounds)

	wgOut, ok := wgOutbounds["warp_dual"]
	assert.True(t, ok)
	assert.Equal(t, "warp_dual", wgOut.Config.Tag)

	// Assert dual-stack settings
	settings, err := BuildWireguardOutboundJSON(outboundDual, "162.159.192.1:2408")
	assert.NoError(t, err)
	assert.Equal(t, "ForceIPv4v6", settings["domainStrategy"])
	assert.Equal(t, []string{"172.16.0.2/32", "2606:4700:110:8f86:3ab3:7f16:c22c:c339/128"}, settings["address"])
}

func TestGetNextEndpoint_Rotation(t *testing.T) {
	c := New(nil, nil)
	original := "127.0.0.1:2408"
	tag := "warp_test"

	// Call 1: Should return original
	ep1 := c.getNextEndpoint(tag, original)
	assert.Equal(t, original, ep1)

	// Call 2..9: Should return fallback pool entries in order
	for i, expected := range fallbackEndpoints {
		ep := c.getNextEndpoint(tag, original)
		assert.Equal(t, expected, ep, "at index %d", i)
	}

	// Call 10: Should wrap back around to original
	ep10 := c.getNextEndpoint(tag, original)
	assert.Equal(t, original, ep10)
}

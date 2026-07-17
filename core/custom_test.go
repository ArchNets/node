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
	assert.Equal(t, "warp_v4", wgOut.Tag)
}

func TestGetCustomConfig_Wireguard_IPv6(t *testing.T) {
	// Test case 2: WireGuard with dual stack (IPv4 and IPv6)
	outboundDual := panel.Outbound{
		Name:                   "warp_dual",
		Protocol:               "wireguard",
		WireguardPrivateKey:    "private_key_dual",
		WireguardAddress:       "172.16.0.2/32,2606:4700:110:8f86:3ab3:7f16:c22c:c339/128",
		WireguardMTU:           1420,
		WireguardPeerPublicKey: "peer_pub_key",
		WireguardPeerEndpoint:  "engage.cloudflareclient.com:2408",
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
	assert.Equal(t, "warp_dual", wgOut.Tag)
}

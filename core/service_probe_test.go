package core

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetConfiguredOutboundTags_IncludesMasqueAndWireguard(t *testing.T) {
	xc := &XrayCore{
		outboundNames: []string{"direct", "block", "masque-eu", "warp-wg", "masque-eu"},
		wgOutbounds: map[string]*WireguardOutbound{
			"warp-wg":  {},
			"wg-extra": {},
		},
	}

	tags := xc.GetConfiguredOutboundTags()
	assert.Contains(t, tags, "direct")
	assert.Contains(t, tags, "masque-eu")
	assert.Contains(t, tags, "warp-wg")
	assert.Contains(t, tags, "wg-extra")
	assert.NotContains(t, tags, "block")

	// Ensure no duplicates
	seen := make(map[string]int)
	for _, tag := range tags {
		seen[tag]++
		assert.Equal(t, 1, seen[tag], "duplicate tag %s", tag)
	}
}

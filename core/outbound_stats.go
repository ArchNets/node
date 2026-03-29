package core

import (
	"github.com/archnets/node/api/panel"
)

// GetOutboundTraffic queries Xray's internal stats counters for per-outbound traffic.
// Xray stores outbound stats as:
//
//	"outbound>>>{tag}>>>traffic>>>uplink"
//	"outbound>>>{tag}>>>traffic>>>downlink"
//
// Returns a slice of OutboundTraffic with upload/download values, and resets counters.
func (vc *XrayCore) GetOutboundTraffic() []panel.OutboundTraffic {
	if vc.statsManager == nil {
		return nil
	}

	// Collect outbound tags: configured outbounds + defaults (direct, block)
	tags := make([]string, 0)
	for _, name := range vc.outboundNames {
		tags = append(tags, name)
	}
	for _, defaultTag := range []string{"direct", "block"} {
		found := false
		for _, t := range tags {
			if t == defaultTag {
				found = true
				break
			}
		}
		if !found {
			tags = append(tags, defaultTag)
		}
	}

	var result []panel.OutboundTraffic
	for _, tag := range tags {
		upName := "outbound>>>" + tag + ">>>traffic>>>uplink"
		downName := "outbound>>>" + tag + ">>>traffic>>>downlink"

		var upload, download int64

		if c := vc.statsManager.GetCounter(upName); c != nil {
			upload = c.Value()
			if upload > 0 {
				c.Set(0)
			}
		}
		if c := vc.statsManager.GetCounter(downName); c != nil {
			download = c.Value()
			if download > 0 {
				c.Set(0)
			}
		}

		if upload > 0 || download > 0 {
			result = append(result, panel.OutboundTraffic{
				Tag:      tag,
				Upload:   upload,
				Download: download,
			})
		}
	}

	return result
}

package core

import (
	"strings"

	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf"
)

// build default freedom outbund
// domainStrategy is the node-wide strategy resolved from the panel's ip_strategy.
// An empty value keeps the historical "UseIPv4v6" behaviour.
func buildDefaultOutbound(domainStrategy string) (*core.OutboundHandlerConfig, error) {
	outboundDetourConfig := &conf.OutboundDetourConfig{}
	outboundDetourConfig.Protocol = "freedom"
	outboundDetourConfig.Tag = "direct"
	//sendthrough := "origin"
	//outboundDetourConfig.SendThrough = &sendthrough

	if strings.TrimSpace(domainStrategy) == "" {
		domainStrategy = "UseIPv4v6"
	}
	outboundDetourConfig.StreamSetting = &conf.StreamConfig{
		SocketSettings: &conf.SocketConfig{
			DomainStrategy: domainStrategy,
		},
	}
	return outboundDetourConfig.Build()
}

// build block outbund
func buildBlockOutbound() (*core.OutboundHandlerConfig, error) {
	outboundDetourConfig := &conf.OutboundDetourConfig{}
	outboundDetourConfig.Protocol = "blackhole"
	outboundDetourConfig.Tag = "block"
	return outboundDetourConfig.Build()
}

// build dns outbound
func buildDnsOutbound() (*core.OutboundHandlerConfig, error) {
	outboundDetourConfig := &conf.OutboundDetourConfig{}
	outboundDetourConfig.Protocol = "dns"
	outboundDetourConfig.Tag = "dns_out"
	return outboundDetourConfig.Build()
}

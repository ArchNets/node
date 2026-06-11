package core

import (
	"encoding/json"
	"net"
	"strconv"
	"strings"

	"github.com/archnets/node/api/panel"
	"github.com/xtls/xray-core/app/dns"
	"github.com/xtls/xray-core/app/router"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	coreConf "github.com/xtls/xray-core/infra/conf"
)

// hasPublicIPv6 checks if the machine has a public IPv6 address
func hasPublicIPv6() bool {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		ip := ipNet.IP
		// Check if it's IPv6, not loopback, not link-local, not private/ULA
		if ip.To4() == nil && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() && !ip.IsPrivate() {
			return true
		}
	}
	return false
}

func hasOutboundWithTag(list []*core.OutboundHandlerConfig, tag string) bool {
	for _, o := range list {
		if o != nil && o.Tag == tag {
			return true
		}
	}
	return false
}

func GetCustomConfig(serverconfig *panel.ServerConfigResponse) (*dns.Config, []*core.OutboundHandlerConfig, *router.Config, error) {
	var ip_strategy string
	if serverconfig.Data.IPStrategy != "" {
		switch serverconfig.Data.IPStrategy {
		case "prefer_ipv4":
			ip_strategy = "UseIPv4v6"
		case "prefer_ipv6":
			ip_strategy = "UseIPv6v4"
		default:
			ip_strategy = "UseIPv4v6"
		}
	} else {
		if hasPublicIPv6() {
			ip_strategy = "UseIPv4v6"
		} else {
			ip_strategy = "UseIPv4"
		}
	}
	dnsConfig := serverconfig.Data.DNS
	blockList := serverconfig.Data.Block
	outboundList := serverconfig.Data.Outbound

	//default dns
	queryStrategy := "UseIPv4v6"
	if !hasPublicIPv6() {
		queryStrategy = "UseIPv4"
	}
	coreDnsConfig := &coreConf.DNSConfig{
		Servers: []*coreConf.NameServerConfig{
			{
				Address: &coreConf.Address{
					Address: xnet.ParseAddress("localhost"),
				},
			},
		},
		QueryStrategy: queryStrategy,
	}

	//custom dns
	if dnsConfig != nil {
		for _, item := range *dnsConfig {
			var domains []string
			for _, domainitem := range item.Domains {
				data := strings.Split(domainitem, ":")
				if len(data) == 2 {
					switch data[0] {
					case "keyword":
						domains = append(domains, data[1])
					case "suffix":
						domains = append(domains, "domain:"+data[1])
					case "regex":
						domains = append(domains, "regexp:"+data[1])
					default:
						domains = append(domains, data[1])
					}
				} else {
					domains = append(domains, "full:"+domainitem)
				}
			}
			/*switch item.Proto {
			case "udp":
				item.Address = item.Address
			case "tcp":
				item.Address = "tcp://" + item.Address
			case "tls":
				item.Address = "tls://" + item.Address
			case "https":
				item.Address = "https://" + item.Address
			case "quic":
				item.Address = "quic://" + item.Address
			}*/
			server := &coreConf.NameServerConfig{
				Address: &coreConf.Address{
					Address: xnet.ParseAddress(item.Address),
				},
				QueryStrategy: ip_strategy,
				Domains:       domains,
			}
			coreDnsConfig.Servers = append(coreDnsConfig.Servers, server)
		}
	}

	//default outbound
	defaultoutbound, _ := buildDefaultOutbound()
	coreOutboundConfig := append([]*core.OutboundHandlerConfig{}, defaultoutbound)
	block, _ := buildBlockOutbound()
	coreOutboundConfig = append(coreOutboundConfig, block)
	dns, _ := buildDnsOutbound()
	coreOutboundConfig = append(coreOutboundConfig, dns)

	//default route
	domainStrategy := "AsIs"
	dnsRule, _ := json.Marshal(map[string]interface{}{
		"port":        "53",
		"network":     "udp",
		"outboundTag": "dns_out",
	})
	coreRouterConfig := &coreConf.RouterConfig{
		RuleList:       []json.RawMessage{},
		DomainStrategy: &domainStrategy,
	}

	//custom block
	if blockList != nil {
		var domains []string
		for _, bitem := range *blockList {
			data := strings.Split(bitem, ":")
			if len(data) == 2 {
				switch data[0] {
				case "keyword":
					domains = append(domains, data[1])
				case "suffix":
					domains = append(domains, "domain:"+data[1])
				case "regex":
					domains = append(domains, "regexp:"+data[1])
				default:
					domains = append(domains, data[1])
				}
			} else {
				domains = append(domains, "full:"+bitem)
			}
		}
		rule := map[string]interface{}{
			"domain":      domains,
			"outboundTag": "block",
		}
		rawRule, err := json.Marshal(rule)
		if err == nil {
			coreRouterConfig.RuleList = append(coreRouterConfig.RuleList, rawRule)
		}
	}

	//custom outbound
	if outboundList != nil {
		for _, outbounditem := range *outboundList {
			jsonsettings := map[string]interface{}{
				"address": outbounditem.Address,
				"port":    outbounditem.Port,
			}
			switch outbounditem.Protocol {
			case "http":
				if outbounditem.User != "" {
					jsonsettings["user"] = outbounditem.User
				}
				if outbounditem.Password != "" {
					jsonsettings["pass"] = outbounditem.Password
				}
			case "socks":
				if outbounditem.User != "" {
					jsonsettings["user"] = outbounditem.User
				}
				if outbounditem.Password != "" {
					jsonsettings["pass"] = outbounditem.Password
				}
			case "shadowsocks":
				if outbounditem.Cipher != "" {
					jsonsettings["method"] = outbounditem.Cipher
				} else {
					jsonsettings["method"] = "chacha20-ietf-poly1305"
				}
				jsonsettings["password"] = outbounditem.Password
				jsonsettings["uot"] = true
				jsonsettings["UoTVersion"] = 2
			case "trojan":
				jsonsettings["password"] = outbounditem.Password
			case "vmess":
				jsonsettings["id"] = outbounditem.Password
			case "vless":
				jsonsettings["id"] = outbounditem.Password
				enc := outbounditem.Encryption
				if enc == "" {
					enc = "none"
				}
				jsonsettings["encryption"] = enc
				if outbounditem.Flow != "" {
					jsonsettings["flow"] = outbounditem.Flow
				}
			case "wireguard":
				delete(jsonsettings, "address")
				delete(jsonsettings, "port")
				jsonsettings["secretKey"] = outbounditem.WireguardPrivateKey
				if len(outbounditem.WireguardAddress) > 0 {
					jsonsettings["address"] = []string{outbounditem.WireguardAddress}
				}
				if outbounditem.WireguardMTU > 0 {
					jsonsettings["mtu"] = outbounditem.WireguardMTU
				}
				peer := map[string]interface{}{
					"publicKey": outbounditem.WireguardPeerPublicKey,
					"endpoint":  outbounditem.WireguardPeerEndpoint,
				}
				jsonsettings["peers"] = []interface{}{peer}

				if len(outbounditem.WireguardReserved) > 0 {
					parts := strings.Split(outbounditem.WireguardReserved, ",")
					if len(parts) == 3 {
						var res []int
						for _, p := range parts {
							v, err := strconv.Atoi(strings.TrimSpace(p))
							if err == nil {
								res = append(res, v)
							}
						}
						if len(res) == 3 {
							jsonsettings["reserved"] = res
						}
					}
				}
			default:
				continue
			}

			settings, _ := json.Marshal(jsonsettings)
			rawSettings := json.RawMessage(settings)

			var outbound *coreConf.OutboundDetourConfig

			if outbounditem.Protocol == "wireguard" {
				// WireGuard outbounds are self-contained tunnels;
				// they don't use transport or TLS stream settings.
				outbound = &coreConf.OutboundDetourConfig{
					Tag:      outbounditem.Name,
					Protocol: outbounditem.Protocol,
					Settings: &rawSettings,
				}
			} else {
				// Setup transport network
				transport := outbounditem.Transport
				if transport == "" {
					transport = "tcp"
				}
				protoT := coreConf.TransportProtocol(transport)
				streamSettings := &coreConf.StreamConfig{Network: &protoT}

				switch transport {
				case "tcp":
					streamSettings.TCPSettings = &coreConf.TCPConfig{}
					if outbounditem.TCPHeaderType == "http" {
						httpHeader := map[string]interface{}{
							"type":    "http",
							"request": map[string]interface{}{},
						}
						request := httpHeader["request"].(map[string]interface{})
						path := outbounditem.TCPHeaderPath
						if path == "" {
							path = "/"
						}
						request["path"] = []string{path}
						if len(outbounditem.TCPHeaderHost) > 0 {
							request["headers"] = map[string]interface{}{
								"Host": outbounditem.TCPHeaderHost,
							}
						}
						headerJSON, err := json.Marshal(httpHeader)
						if err == nil {
							streamSettings.TCPSettings.HeaderConfig = json.RawMessage(headerJSON)
						}
					}
				case "ws", "websocket":
					streamSettings.WSSettings = &coreConf.WebSocketConfig{
						Host: outbounditem.Host,
						Path: outbounditem.Path,
					}
				case "grpc":
					streamSettings.GRPCSettings = &coreConf.GRPCConfig{
						ServiceName: outbounditem.ServiceName,
					}
				case "httpupgrade":
					streamSettings.HTTPUPGRADESettings = &coreConf.HttpUpgradeConfig{
						Host: outbounditem.Host,
						Path: outbounditem.Path,
					}
				case "splithttp", "xhttp":
					streamSettings.SplitHTTPSettings = &coreConf.SplitHTTPConfig{
						Host: outbounditem.Host,
						Path: outbounditem.Path,
					}
				}

				// Setup security (TLS/Reality)
				security := outbounditem.Security
				if security == "tls" {
					streamSettings.Security = "tls"
					streamSettings.TLSSettings = &coreConf.TLSConfig{
						ServerName:    outbounditem.SNI,
						AllowInsecure: outbounditem.AllowInsecure,
						Fingerprint:   outbounditem.Fingerprint,
					}
				} else if security == "reality" {
					streamSettings.Security = "reality"
					streamSettings.REALITYSettings = &coreConf.REALITYConfig{
						ServerName:  outbounditem.SNI,
						Fingerprint: outbounditem.Fingerprint,
						PublicKey:   outbounditem.RealityPublicKey,
						ShortId:     outbounditem.RealityShortId,
						SpiderX:     outbounditem.RealitySpiderX,
					}
				}

				if outbounditem.DialerProxy != "" {
					if streamSettings.SocketSettings == nil {
						streamSettings.SocketSettings = &coreConf.SocketConfig{}
					}
					streamSettings.SocketSettings.DialerProxy = outbounditem.DialerProxy
				}

				outbound = &coreConf.OutboundDetourConfig{
					Tag:           outbounditem.Name,
					Protocol:      outbounditem.Protocol,
					Settings:      &rawSettings,
					StreamSetting: streamSettings,
				}
			}

			custom_outbound, err := outbound.Build()
			if err != nil {
				continue
			}

			if hasOutboundWithTag(coreOutboundConfig, custom_outbound.Tag) {
				continue
			}
			coreOutboundConfig = append(coreOutboundConfig, custom_outbound)
		}
	}

	// custom routing rules — placed BEFORE dns_out so inbound-tag rules
	// (e.g. ikev2:28 → Main Panel) take priority for IPsec/WG traffic.
	// Pre-compute valid balancer tags to validate references in routing rules
	validBalancerTags := make(map[string]bool)
	if balancerList := serverconfig.Data.Balancers; balancerList != nil {
		for _, b := range *balancerList {
			if b.Tag != "" {
				validBalancerTags[b.Tag] = true
			}
		}
	}
	if routingList := serverconfig.Data.Routing; routingList != nil {
		for _, rule := range *routingList {
			splitFunc := func(items []string) []string {
				var res []string
				for _, item := range items {
					for _, part := range strings.Split(item, ",") {
						if trimmed := strings.TrimSpace(part); trimmed != "" {
							res = append(res, trimmed)
						}
					}
				}
				return res
			}

			xrayRule := map[string]interface{}{"type": "field"}
			if len(rule.InboundTags) > 0 {
				xrayRule["inboundTag"] = splitFunc(rule.InboundTags)
			}
			if rule.BalancerTag != "" && validBalancerTags[rule.BalancerTag] {
				xrayRule["balancerTag"] = rule.BalancerTag
			} else if rule.OutboundTag != "" {
				xrayRule["outboundTag"] = rule.OutboundTag
			} else {
				// Neither valid balancer nor outbound — skip this rule
				continue
			}
			if rule.Network != "" {
				xrayRule["network"] = rule.Network
			}
			if len(rule.Domain) > 0 {
				xrayRule["domain"] = splitFunc(rule.Domain)
			}
			if len(rule.IP) > 0 {
				xrayRule["ip"] = splitFunc(rule.IP)
			}
			if rule.Port != "" {
				xrayRule["port"] = rule.Port
			}
			if len(rule.SourceIP) > 0 {
				xrayRule["source"] = splitFunc(rule.SourceIP)
			}
			if rule.SourcePort != "" {
				xrayRule["sourcePort"] = rule.SourcePort
			}
			if len(rule.Protocol) > 0 {
				xrayRule["protocol"] = splitFunc(rule.Protocol)
			}
			if len(rule.User) > 0 {
				xrayRule["user"] = splitFunc(rule.User)
			}
			if rule.Attrs != "" {
				xrayRule["attrs"] = rule.Attrs
			}
			rawRule, err := json.Marshal(xrayRule)
			if err == nil {
				coreRouterConfig.RuleList = append(coreRouterConfig.RuleList, rawRule)
			}
		}
	}

	// custom balancers — referenced by routing rules via balancerTag
	if balancerList := serverconfig.Data.Balancers; balancerList != nil {
		for _, b := range *balancerList {
			if b.Tag == "" || len(b.Selector) == 0 {
				continue
			}
			strategy := b.Strategy
			if strategy == "" {
				strategy = "random"
			}
			balancer := &coreConf.BalancingRule{
				Tag:         b.Tag,
				Selectors:   b.Selector,
				FallbackTag: b.FallbackTag,
				Strategy: coreConf.StrategyConfig{
					Type: strategy,
				},
			}
			coreRouterConfig.Balancers = append(coreRouterConfig.Balancers, balancer)
		}
	}

	// dns_out rule AFTER custom rules — catches remaining UDP DNS from standard inbounds
	coreRouterConfig.RuleList = append(coreRouterConfig.RuleList, dnsRule)
	//build config
	DnsConfig, err := coreDnsConfig.Build()
	if err != nil {
		return nil, nil, nil, err
	}
	RouterConfig, err := coreRouterConfig.Build()
	if err != nil {
		return nil, nil, nil, err
	}
	return DnsConfig, coreOutboundConfig, RouterConfig, nil
}

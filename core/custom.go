package core

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/archnets/node/api/panel"
	log "github.com/sirupsen/logrus"
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

// forceDomainStrategies is the exact enum accepted by the Xray wireguard OUTBOUND
// (settings.domainStrategy). The Use* family is deliberately absent: wireguard must
// obtain a usable IP and cannot fall back to a domain name after resolution fails.
// See https://xtls.github.io/en/config/outbounds/wireguard.html
var forceDomainStrategies = map[string]string{
	"forceip":     "ForceIP",
	"forceipv4":   "ForceIPv4",
	"forceipv6":   "ForceIPv6",
	"forceipv4v6": "ForceIPv4v6",
	"forceipv6v4": "ForceIPv6v4",
}

// sockoptDomainStrategies is the enum accepted by streamSettings.sockopt.domainStrategy,
// which is how every NON-wireguard outbound receives a per-outbound strategy.
var sockoptDomainStrategies = map[string]string{
	"asis":        "AsIs",
	"useip":       "UseIP",
	"useipv4":     "UseIPv4",
	"useipv6":     "UseIPv6",
	"useipv4v6":   "UseIPv4v6",
	"useipv6v4":   "UseIPv6v4",
	"forceip":     "ForceIP",
	"forceipv4":   "ForceIPv4",
	"forceipv6":   "ForceIPv6",
	"forceipv4v6": "ForceIPv4v6",
	"forceipv6v4": "ForceIPv6v4",
}

// normalizeForceDomainStrategy validates a panel-supplied strategy for a wireguard
// outbound and returns its canonical spelling. ok is false for empty or unknown input.
func normalizeForceDomainStrategy(s string) (string, bool) {
	v, ok := forceDomainStrategies[strings.ToLower(strings.TrimSpace(s))]
	return v, ok
}

// normalizeSockoptDomainStrategy validates a panel-supplied strategy for any
// non-wireguard outbound and returns its canonical spelling.
func normalizeSockoptDomainStrategy(s string) (string, bool) {
	v, ok := sockoptDomainStrategies[strings.ToLower(strings.TrimSpace(s))]
	return v, ok
}

// wireguardAddresses splits a comma-separated wireguard_address value into trimmed
// entries and reports whether any of them is IPv6.
func wireguardAddresses(raw string) ([]string, bool) {
	var addresses []string
	hasIPv6 := false
	for _, p := range strings.Split(raw, ",") {
		trimmed := strings.TrimSpace(p)
		if trimmed == "" {
			continue
		}
		addresses = append(addresses, trimmed)
		ipStr := trimmed
		if idx := strings.Index(ipStr, "/"); idx != -1 {
			ipStr = ipStr[:idx]
		}
		if ip := net.ParseIP(ipStr); ip != nil && ip.To4() == nil {
			hasIPv6 = true
		}
	}
	return addresses, hasIPv6
}

// hasIPv6Egress reports whether this node can actually egress over IPv6: either the
// host holds a public IPv6 address, or a wireguard outbound carries an IPv6 tunnel
// address. The second case is invisible to net.InterfaceAddrs() because those
// outbounds run a gVisor userspace TUN (noKernelTun: true), so relying on
// hasPublicIPv6() alone makes the resolver strip AAAA records and leaves every
// Force*IPv6* outbound strategy with nothing to work with.
func hasIPv6Egress(serverconfig *panel.ServerConfigResponse) bool {
	if hasPublicIPv6() {
		return true
	}
	if serverconfig == nil || serverconfig.Data == nil || serverconfig.Data.Outbound == nil {
		return false
	}
	for _, o := range *serverconfig.Data.Outbound {
		if o.Protocol != "wireguard" {
			continue
		}
		if _, hasIPv6 := wireguardAddresses(o.WireguardAddress); hasIPv6 {
			return true
		}
	}
	return false
}

// validPresharedKey reports whether psk is a standard-base64 encoded 32-byte key.
func validPresharedKey(psk string) bool {
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(psk))
	return err == nil && len(b) == 32
}

// isHostnameEndpoint reports whether the host part of endpoint is a domain rather
// than an IP literal.
func isHostnameEndpoint(endpoint string) bool {
	host, _, err := net.SplitHostPort(strings.TrimSpace(endpoint))
	if err != nil {
		return false
	}
	return net.ParseIP(host) == nil
}

func hasOutboundWithTag(list []*core.OutboundHandlerConfig, tag string) bool {
	for _, o := range list {
		if o != nil && o.Tag == tag {
			return true
		}
	}
	return false
}

type WireguardOutbound struct {
	Config   *core.OutboundHandlerConfig
	Outbound panel.Outbound
}

func BuildWireguardOutboundJSON(outbounditem panel.Outbound, endpoint string) (map[string]interface{}, error) {
	jsonsettings := map[string]interface{}{
		"secretKey": outbounditem.WireguardPrivateKey,
	}

	addresses, hasIPv6 := wireguardAddresses(outbounditem.WireguardAddress)
	if len(addresses) > 0 {
		jsonsettings["address"] = addresses
	}

	// Per-outbound resolution strategy, chosen by the admin in the panel and passed
	// through verbatim. Nothing is inferred here: Xray already constrains the strategy
	// by the address list, so ForceIPv6v4 on a v4-only tunnel degrades to IPv4 for
	// proxied traffic instead of breaking.
	if ds, ok := normalizeForceDomainStrategy(outbounditem.DomainStrategy); ok {
		jsonsettings["domainStrategy"] = ds
	} else {
		if strings.TrimSpace(outbounditem.DomainStrategy) != "" {
			log.WithFields(log.Fields{
				"name":           outbounditem.Name,
				"domainStrategy": outbounditem.DomainStrategy,
			}).Warn("Unrecognised domain_strategy for wireguard outbound; using the legacy default. Allowed: ForceIP, ForceIPv4, ForceIPv6, ForceIPv4v6, ForceIPv6v4")
		}
		// Legacy fallback, kept only so nodes talking to an un-upgraded panel behave
		// exactly as they did before this change. Xray's own default is ForceIP.
		if hasIPv6 {
			jsonsettings["domainStrategy"] = "ForceIPv4v6"
		} else {
			jsonsettings["domainStrategy"] = "ForceIPv4"
		}
	}

	if outbounditem.WireguardMTU > 0 {
		jsonsettings["mtu"] = outbounditem.WireguardMTU
	}

	peer := map[string]interface{}{
		"publicKey": outbounditem.WireguardPeerPublicKey,
		"endpoint":  endpoint,
		"keepAlive": 25,
	}
	// peers[].preSharedKey is peer-level and optional. Never emit an empty string:
	// Xray's default is the all-zero key.
	if psk := strings.TrimSpace(outbounditem.WireguardPeerPresharedKey); psk != "" {
		if validPresharedKey(psk) {
			peer["preSharedKey"] = psk
		} else {
			log.WithField("name", outbounditem.Name).Warn("Ignoring invalid wireguard_peer_preshared_key: must be standard base64 decoding to 32 bytes")
		}
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

	// Force gVisor userspace TUN to avoid kernel TUN failures on VPSes
	// without /dev/net/tun, and to prevent sysctl side effects
	// (rp_filter=0 globally) that kernel TUN would cause.
	jsonsettings["noKernelTun"] = true

	return jsonsettings, nil
}

func BuildWireguardOutbound(outbounditem panel.Outbound, endpoint string) (*core.OutboundHandlerConfig, error) {
	jsonsettings, err := BuildWireguardOutboundJSON(outbounditem, endpoint)
	if err != nil {
		return nil, err
	}

	settings, err := json.Marshal(jsonsettings)
	if err != nil {
		return nil, err
	}
	rawSettings := json.RawMessage(settings)

	outbound := &coreConf.OutboundDetourConfig{
		Tag:      outbounditem.Name,
		Protocol: outbounditem.Protocol,
		Settings: &rawSettings,
	}
	
	// Log the WireGuard outbound config for debugging
	log.WithFields(log.Fields{
		"tag":            outbounditem.Name,
		"address":        outbounditem.WireguardAddress,
		"endpoint":       endpoint,
		"mtu":            outbounditem.WireguardMTU,
		"domainStrategy": jsonsettings["domainStrategy"],
		"psk":            strings.TrimSpace(outbounditem.WireguardPeerPresharedKey) != "",
	}).Info("Built WireGuard outbound config")

	// Endpoint resolution is NOT constrained by the address list the way proxied
	// traffic is, so a Force*IPv6* strategy can make Xray resolve a hostname endpoint
	// to an AAAA record this host cannot reach. Warn once per outbound.
	if ds, _ := jsonsettings["domainStrategy"].(string); strings.HasPrefix(ds, "ForceIPv6") && isHostnameEndpoint(endpoint) && !hasPublicIPv6() {
		log.WithFields(log.Fields{
			"tag":            outbounditem.Name,
			"endpoint":       endpoint,
			"domainStrategy": ds,
		}).Warn("IPv6 domain strategy with a hostname peer endpoint on a host without native IPv6; use an IP:Port literal (e.g. 162.159.192.1:2408) if the handshake fails")
	}

	return outbound.Build()
}

func GetCustomConfig(serverconfig *panel.ServerConfigResponse) (*dns.Config, []*core.OutboundHandlerConfig, *router.Config, map[string]*WireguardOutbound, error) {
	wgOutbounds := make(map[string]*WireguardOutbound)
	// ipv6Egress is derived from configuration, not from host interfaces, because a
	// wireguard outbound's IPv6 tunnel address never shows up in net.InterfaceAddrs().
	ipv6Egress := hasIPv6Egress(serverconfig)

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
		if ipv6Egress {
			ip_strategy = "UseIPv4v6"
		} else {
			ip_strategy = "UseIPv4"
		}
	}
	dnsConfig := serverconfig.Data.DNS
	blockList := serverconfig.Data.Block
	outboundList := serverconfig.Data.Outbound

	// default dns - the panel-wide ip_strategy now also applies to the default
	// localhost server, not only to the custom DNS entries below. Without this the
	// resolver strips AAAA records and every Force*IPv6* outbound strategy no-ops.
	queryStrategy := ip_strategy
	log.WithFields(log.Fields{
		"queryStrategy": queryStrategy,
		"ipv6Egress":    ipv6Egress,
		"ipStrategy":    serverconfig.Data.IPStrategy,
	}).Info("Resolved DNS query strategy")
	// Note: Xray DNS configured here is GLOBAL to the node's Xray instance (not per-inbound).
	// TPROXY-captured tunnel traffic (WireGuard/OpenVPN/IPsec) only reaches this DNS for plain
	// UDP :53 queries via the existing port-53 -> dns_out routing rule; DoH/DoT queries from
	// clients bypass this DNS and are routed directly.
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

	// What changed: Implemented Proto handling (udp, tcp, tls, https, quic, local) and empty address validation for custom DNS items.
	// Why: Allows panel-configured DoT, DoH, and DoQ DNS servers to format their address correctly for Xray, skipping invalid empty entries.
	if dnsConfig != nil {
		for _, item := range *dnsConfig {
			addr := strings.TrimSpace(item.Address)
			// Validate: skip entry if address is empty
			if addr == "" {
				log.WithField("proto", item.Proto).Warn("Skipping DNS item with empty address")
				continue
			}

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

			proto := strings.ToLower(strings.TrimSpace(item.Proto))
			var formattedAddr string
			switch proto {
			case "udp", "":
				formattedAddr = addr
			case "tcp":
				formattedAddr = "tcp://" + addr
			case "tls":
				formattedAddr = "tls://" + addr
			case "https":
				formattedAddr = "https://" + addr
			case "quic":
				formattedAddr = "quic://" + addr
			case "local", "localhost":
				formattedAddr = "localhost"
			default:
				formattedAddr = addr
				log.WithFields(log.Fields{
					"proto":   item.Proto,
					"address": addr,
				}).Warn("Unknown DNS protocol, treating address as-is")
			}

			server := &coreConf.NameServerConfig{
				Address: &coreConf.Address{
					Address: xnet.ParseAddress(formattedAddr),
				},
				QueryStrategy: ip_strategy,
				Domains:       domains,
			}
			coreDnsConfig.Servers = append(coreDnsConfig.Servers, server)
		}
	}

	//default outbound
	defaultoutbound, _ := buildDefaultOutbound(ip_strategy)
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

	// Captive-portal / connectivity-check bypass. Appended after the block rules so
	// blocking still wins, and before the panel routing rules below so a probe is not
	// swallowed by a broad geosite rule. Returns nothing unless the feature is on.
	coreRouterConfig.RuleList = append(coreRouterConfig.RuleList,
		connectivityCheckRules(serverconfig.Data)...)

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
				endpoint := outbounditem.WireguardPeerEndpoint
				if endpoint != "" {
					host, port, err := net.SplitHostPort(endpoint)
					if err == nil {
						if ip := net.ParseIP(host); ip == nil {
							ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
							ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
							if err == nil && len(ips) > 0 {
								var targetIP net.IP
								for _, ip := range ips {
									if ip.To4() != nil {
										targetIP = ip
										break
									}
								}
								if targetIP == nil {
									targetIP = ips[0]
								}
								endpoint = net.JoinHostPort(targetIP.String(), port)
							}
							cancel()
						}
					}
				}

				custom_outbound, err := BuildWireguardOutbound(outbounditem, endpoint)
				if err != nil {
					log.WithFields(log.Fields{
						"name": outbounditem.Name,
						"err":  err,
					}).Warn("Failed to build WireGuard outbound, skipping")
					continue
				}

				if hasOutboundWithTag(coreOutboundConfig, custom_outbound.Tag) {
					continue
				}
				wgOutbounds[outbounditem.Name] = &WireguardOutbound{
					Config:   custom_outbound,
					Outbound: outbounditem,
				}
				coreOutboundConfig = append(coreOutboundConfig, custom_outbound)
				continue
			default:
				continue
			}

			settings, _ := json.Marshal(jsonsettings)
			rawSettings := json.RawMessage(settings)

			var outbound *coreConf.OutboundDetourConfig

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

				// Per-outbound domain resolution strategy for non-wireguard outbounds.
				// Xray exposes no settings.domainStrategy for these protocols, so the
				// strategy goes on streamSettings.sockopt.domainStrategy, which accepts
				// the AsIs / Use* / Force* families. streamSettings is a pointer already
				// stored on the detour config, so mutating it here is safe.
				if ds, ok := normalizeSockoptDomainStrategy(outbounditem.DomainStrategy); ok {
					if streamSettings.SocketSettings == nil {
						streamSettings.SocketSettings = &coreConf.SocketConfig{}
					}
					streamSettings.SocketSettings.DomainStrategy = ds
					log.WithFields(log.Fields{
						"name":           outbounditem.Name,
						"protocol":       outbounditem.Protocol,
						"domainStrategy": ds,
					}).Info("Applied per-outbound sockopt domainStrategy")
				} else if strings.TrimSpace(outbounditem.DomainStrategy) != "" {
					log.WithFields(log.Fields{
						"name":           outbounditem.Name,
						"protocol":       outbounditem.Protocol,
						"domainStrategy": outbounditem.DomainStrategy,
					}).Warn("Ignoring unrecognised domain_strategy for outbound")
				}

			custom_outbound, err := outbound.Build()
			if err != nil {
				log.WithFields(log.Fields{
					"name":     outbounditem.Name,
					"protocol": outbounditem.Protocol,
					"err":      err,
				}).Warn("Failed to build custom outbound, skipping")
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
				outTag := rule.OutboundTag
				if outTag == "Default" {
					outTag = "direct"
				}
				xrayRule["outboundTag"] = outTag
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
		return nil, nil, nil, nil, err
	}
	RouterConfig, err := coreRouterConfig.Build()
	if err != nil {
		return nil, nil, nil, nil, err
	}
	return DnsConfig, coreOutboundConfig, RouterConfig, wgOutbounds, nil
}

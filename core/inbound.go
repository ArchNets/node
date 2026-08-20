package core

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/archnets/node/api/panel"
	certutil "github.com/archnets/node/common/cert"
	log "github.com/sirupsen/logrus"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/inbound"
	coreConf "github.com/xtls/xray-core/infra/conf"
)

func (v *XrayCore) RemoveInbound(tag string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return v.ihm.RemoveHandler(ctx, tag)
}

func (v *XrayCore) AddInbound(config *core.InboundHandlerConfig) error {
	rawHandler, err := core.CreateObject(v.Server, config)
	if err != nil {
		return err
	}
	handler, ok := rawHandler.(inbound.Handler)
	if !ok {
		return fmt.Errorf("not an InboundHandler: %s", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := v.ihm.AddHandler(ctx, handler); err != nil {
		return err
	}
	return nil
}

// BuildInbound build Inbound config for different protocol
func buildInbound(nodeInfo *panel.NodeInfo, tag string) (*core.InboundHandlerConfig, error) {
	in := &coreConf.InboundDetourConfig{}
	var err error
	switch nodeInfo.Type {
	case "vless":
		err = buildVLess(nodeInfo, in)
	case "vmess":
		err = buildVMess(nodeInfo, in)
	case "trojan":
		err = buildTrojan(nodeInfo, in)
	case "shadowsocks":
		err = buildShadowsocks(nodeInfo, in)
	case "hysteria2", "hysteria":
		err = buildHysteria2(nodeInfo, in)
	case "tuic":
		err = buildTuic(nodeInfo, in)
	case "anytls":
		err = buildAnyTLS(nodeInfo, in)
	case "socks":
		err = buildSocks(nodeInfo, in)
	case "http":
		err = buildHTTP(nodeInfo, in)
	default:
		return nil, fmt.Errorf("unsupported node type: %s", nodeInfo.Type)
	}
	if err != nil {
		return nil, err
	}
	// Set network protocol
	// Set server port
	in.PortList = &coreConf.PortList{
		Range: []coreConf.PortRange{
			{
				From: uint32(nodeInfo.Protocol.Port),
				To:   uint32(nodeInfo.Protocol.Port),
			}},
	}
	// Set Listen IP address (default to 0.0.0.0 if not specified)
	listenIP := nodeInfo.Protocol.ListenIP
	if listenIP == "" {
		listenIP = "0.0.0.0"
	}
	ipAddress := net.ParseAddress(listenIP)
	log.WithFields(log.Fields{
		"type": nodeInfo.Type,
		"ip":   listenIP,
		"port": nodeInfo.Protocol.Port,
		"tag":  tag,
	}).Debug("building inbound handler")
	in.ListenOn = &coreConf.Address{Address: ipAddress}
	// Set SniffingConfig
	sniffingConfig := &coreConf.SniffingConfig{
		Enabled:      true,
		DestOverride: coreConf.StringList{"http", "tls"},
	}
	in.SniffingConfig = sniffingConfig

	// Set TLS or Reality settings
	switch nodeInfo.Protocol.Security {
	case "tls":
		switch nodeInfo.Protocol.CertMode {
		case "none", "":
			break
		default:
			if in.StreamSetting == nil {
				in.StreamSetting = &coreConf.StreamConfig{}
			}
			in.StreamSetting.Security = "tls"
			var alpn *coreConf.StringList
			if len(nodeInfo.Protocol.Alpn) > 0 {
				a := coreConf.StringList(nodeInfo.Protocol.Alpn)
				alpn = &a
			}
			// Determine cert/key paths based on cert_mode
			var certFile, keyFile string
			if nodeInfo.Protocol.CertMode == "path" {
				// Use user-provided filesystem paths directly
				certFile = nodeInfo.Protocol.CertFile
				keyFile = nodeInfo.Protocol.KeyFile
			} else {
				// Use auto-generated paths (for file, dns, http, self modes)
				certFile, keyFile = certutil.GetCertPaths(nodeInfo.Protocol.SNI, nodeInfo.Type, nodeInfo.Id)
			}
			in.StreamSetting.TLSSettings = &coreConf.TLSConfig{
				ALPN: alpn,
				Certs: []*coreConf.TLSCertConfig{
					{
						CertFile: certFile,
						KeyFile:  keyFile,
					},
				},
			}
		}
	case "reality":
		if in.StreamSetting == nil {
			in.StreamSetting = &coreConf.StreamConfig{}
		}
		in.StreamSetting.Security = "reality"
		v := nodeInfo.Protocol
		add := v.RealityServerAddr
		if add == "" {
			add = v.SNI
		}
		d, err := json.Marshal(fmt.Sprintf(
			"%s:%d",
			add,
			v.RealityServerPort))
		if err != nil {
			return nil, fmt.Errorf("marshal reality dest error: %s", err)
		}
		shortIds := v.RealityShortIds
		if len(shortIds) == 0 && v.RealityShortID != "" {
			shortIds = []string{v.RealityShortID}
		}
		in.StreamSetting.REALITYSettings = &coreConf.REALITYConfig{
			Dest:         d,
			Xver:         uint64(0),
			Show:         false,
			ServerNames:  []string{v.SNI},
			PrivateKey:   v.RealityPrivateKey,
			MinClientVer: "0.0.1",
			ShortIds:     shortIds,
			SpiderX:      v.RealitySpiderX,
		}
	default:
		break
	}
	in.Tag = tag

	// Set PROXY protocol (centralized handling via SocketSettings only)
	if nodeInfo.Protocol.AcceptProxyProtocol {
		if in.StreamSetting == nil {
			// Default to "tcp" when transport is empty (e.g., Shadowsocks without obfs)
			transport := nodeInfo.Protocol.Transport
			if transport == "" {
				transport = "tcp"
			}
			t := coreConf.TransportProtocol(transport)
			in.StreamSetting = &coreConf.StreamConfig{
				Network: &t,
				SocketSettings: &coreConf.SocketConfig{
					AcceptProxyProtocol: true,
				},
			}
		} else {
			if in.StreamSetting.SocketSettings == nil {
				in.StreamSetting.SocketSettings = &coreConf.SocketConfig{}
			}
			in.StreamSetting.SocketSettings.AcceptProxyProtocol = true
		}
	}

	// Apply low-level sockopts
	sockoptConfig := mapSockopt(&nodeInfo.Protocol.Sockopt)
	if sockoptConfig != nil {
		if in.StreamSetting == nil {
			// Default to "tcp" when transport is empty (e.g., Shadowsocks without obfs)
			transport := nodeInfo.Protocol.Transport
			if transport == "" {
				transport = "tcp"
			}
			t := coreConf.TransportProtocol(transport)
			in.StreamSetting = &coreConf.StreamConfig{
				Network: &t,
			}
		}
		if in.StreamSetting.SocketSettings == nil {
			in.StreamSetting.SocketSettings = sockoptConfig
		} else {
			// Merge with existing AcceptProxyProtocol logic
			acceptProxy := in.StreamSetting.SocketSettings.AcceptProxyProtocol
			in.StreamSetting.SocketSettings = sockoptConfig
			in.StreamSetting.SocketSettings.AcceptProxyProtocol = acceptProxy
		}
	}

	return in.Build()
}

func buildVLess(nodeInfo *panel.NodeInfo, inbound *coreConf.InboundDetourConfig) error {
	inbound.Protocol = "vless"
	var err error
	decryption := "none"
	if nodeInfo.Protocol.Encryption != "" && nodeInfo.Protocol.Encryption != "none" {
		switch nodeInfo.Protocol.Encryption {
		case "mlkem768x25519plus":
			parts := []string{
				"mlkem768x25519plus",
				nodeInfo.Protocol.EncryptionMode,
				nodeInfo.Protocol.EncryptionTicket + "s",
			}
			if nodeInfo.Protocol.EncryptionServerPadding != "" {
				parts = append(parts, nodeInfo.Protocol.EncryptionServerPadding)
			}
			parts = append(parts, nodeInfo.Protocol.EncryptionPrivateKey)
			decryption = strings.Join(parts, ".")
		default:
			return fmt.Errorf("vless decryption method %s is not support", nodeInfo.Protocol.Encryption)
		}
	}
	s, err := json.Marshal(&coreConf.VLessInboundConfig{
		Decryption: decryption,
	})
	if err != nil {
		return fmt.Errorf("marshal vless config error: %s", err)
	}
	inbound.Settings = (*json.RawMessage)(&s)
	t := coreConf.TransportProtocol(nodeInfo.Protocol.Transport)
	inbound.StreamSetting = &coreConf.StreamConfig{Network: &t}
	switch nodeInfo.Protocol.Transport {
	case "tcp":
		inbound.StreamSetting.TCPSettings = &coreConf.TCPConfig{}
		// Add HTTP header obfuscation if configured
		if nodeInfo.Protocol.TCPHeaderType == "http" {
			path := nodeInfo.Protocol.TCPHeaderPath
			if path == "" {
				path = "/"
			}
			method := nodeInfo.Protocol.TCPHeaderMethod
			if method == "" {
				method = "GET"
			}
			headers := make(map[string]interface{})
			// Set host headers if configured
			if len(nodeInfo.Protocol.TCPHeaderHost) > 0 {
				headers["Host"] = nodeInfo.Protocol.TCPHeaderHost
			}
			// Set custom headers
			for k, v := range nodeInfo.Protocol.TCPHeaderHeaders {
				headers[k] = []string{v}
			}
			httpHeader := map[string]interface{}{
				"type": "http",
				"request": map[string]interface{}{
					"method":  method,
					"path":    []string{path},
					"headers": headers,
				},
			}
			headerJSON, err := json.Marshal(httpHeader)
			if err == nil {
				inbound.StreamSetting.TCPSettings.HeaderConfig = json.RawMessage(headerJSON)
			}
		}
	case "ws", "websocket":
		inbound.StreamSetting.WSSettings = &coreConf.WebSocketConfig{
			Host: nodeInfo.Protocol.Host,
			Path: nodeInfo.Protocol.Path,
		}
	case "grpc":
		inbound.StreamSetting.GRPCSettings = &coreConf.GRPCConfig{
			ServiceName: nodeInfo.Protocol.ServiceName,
		}
	/*case "mkcp":
	inbound.StreamSetting.KCPSettings = &coreConf.KCPConfig{
	}*/
	case "httpupgrade":
		inbound.StreamSetting.HTTPUPGRADESettings = &coreConf.HttpUpgradeConfig{
			Host: nodeInfo.Protocol.Host,
			Path: nodeInfo.Protocol.Path,
		}
	case "splithttp", "xhttp":
		inbound.StreamSetting.SplitHTTPSettings = &coreConf.SplitHTTPConfig{
			Host: nodeInfo.Protocol.Host,
			Path: nodeInfo.Protocol.Path,
			Mode: nodeInfo.Protocol.XHTTPMode,
			//Extra: json.RawMessage(nodeInfo.Protocol.XHTTPExtra),
		}
	default:
		return errors.New("the network type is not vail")
	}
	return nil
}

func buildVMess(nodeInfo *panel.NodeInfo, inbound *coreConf.InboundDetourConfig) error {
	inbound.Protocol = "vmess"
	var err error
	s, err := json.Marshal(&coreConf.VMessInboundConfig{})
	if err != nil {
		return fmt.Errorf("marshal vmess settings error: %s", err)
	}
	inbound.Settings = (*json.RawMessage)(&s)
	t := coreConf.TransportProtocol(nodeInfo.Protocol.Transport)
	inbound.StreamSetting = &coreConf.StreamConfig{Network: &t}
	switch nodeInfo.Protocol.Transport {
	case "tcp":
		inbound.StreamSetting.TCPSettings = &coreConf.TCPConfig{}
		// Add HTTP header obfuscation if configured
		if nodeInfo.Protocol.TCPHeaderType == "http" {
			path := nodeInfo.Protocol.TCPHeaderPath
			if path == "" {
				path = "/"
			}
			method := nodeInfo.Protocol.TCPHeaderMethod
			if method == "" {
				method = "GET"
			}
			headers := make(map[string]interface{})
			// Set host headers if configured
			if len(nodeInfo.Protocol.TCPHeaderHost) > 0 {
				headers["Host"] = nodeInfo.Protocol.TCPHeaderHost
			}
			// Set custom headers
			for k, v := range nodeInfo.Protocol.TCPHeaderHeaders {
				headers[k] = []string{v}
			}
			httpHeader := map[string]interface{}{
				"type": "http",
				"request": map[string]interface{}{
					"method":  method,
					"path":    []string{path},
					"headers": headers,
				},
			}
			headerJSON, err := json.Marshal(httpHeader)
			if err == nil {
				inbound.StreamSetting.TCPSettings.HeaderConfig = json.RawMessage(headerJSON)
			}
		}
	case "ws", "websocket":
		inbound.StreamSetting.WSSettings = &coreConf.WebSocketConfig{
			Host: nodeInfo.Protocol.Host,
			Path: nodeInfo.Protocol.Path,
		}
	case "grpc":
		inbound.StreamSetting.GRPCSettings = &coreConf.GRPCConfig{
			ServiceName: nodeInfo.Protocol.ServiceName,
		}
	/*case "mkcp":
	inbound.StreamSetting.KCPSettings = &coreConf.KCPConfig{
	}*/
	case "httpupgrade":
		inbound.StreamSetting.HTTPUPGRADESettings = &coreConf.HttpUpgradeConfig{
			Host: nodeInfo.Protocol.Host,
			Path: nodeInfo.Protocol.Path,
		}
	case "splithttp", "xhttp":
		inbound.StreamSetting.SplitHTTPSettings = &coreConf.SplitHTTPConfig{
			Host: nodeInfo.Protocol.Host,
			Path: nodeInfo.Protocol.Path,
			Mode: nodeInfo.Protocol.XHTTPMode,
		}
	default:
		return errors.New("the network type is not vail")
	}
	return nil
}

func buildTrojan(nodeInfo *panel.NodeInfo, inbound *coreConf.InboundDetourConfig) error {
	inbound.Protocol = "trojan"
	s, err := json.Marshal(&coreConf.TrojanServerConfig{})
	if err != nil {
		return fmt.Errorf("marshal trojan settings error: %s", err)
	}
	inbound.Settings = (*json.RawMessage)(&s)
	network := nodeInfo.Protocol.Transport
	t := coreConf.TransportProtocol(network)
	inbound.StreamSetting = &coreConf.StreamConfig{Network: &t}
	switch network {
	case "tcp":
		inbound.StreamSetting.TCPSettings = &coreConf.TCPConfig{}
	case "ws", "websocket":
		inbound.StreamSetting.WSSettings = &coreConf.WebSocketConfig{
			Host: nodeInfo.Protocol.Host,
			Path: nodeInfo.Protocol.Path,
		}
	case "grpc":
		inbound.StreamSetting.GRPCSettings = &coreConf.GRPCConfig{
			ServiceName: nodeInfo.Protocol.ServiceName,
		}
	default:
		return errors.New("the network type is not vail")
	}
	return nil
}

func buildShadowsocks(nodeInfo *panel.NodeInfo, inbound *coreConf.InboundDetourConfig) error {
	inbound.Protocol = "shadowsocks"
	cipher := nodeInfo.Protocol.Cipher
	settings := &coreConf.ShadowsocksServerConfig{
		Cipher: cipher,
	}
	p := make([]byte, 32)
	_, err := rand.Read(p)
	if err != nil {
		return fmt.Errorf("generate random password error: %s", err)
	}
	randomPasswd := hex.EncodeToString(p)

	if nodeInfo.Protocol.ServerKey != "" && strings.Contains(cipher, "2022") {
		nodeInfo.Protocol.ServerKey = base64.StdEncoding.EncodeToString([]byte(nodeInfo.Protocol.ServerKey))
		settings.Password = nodeInfo.Protocol.ServerKey
		randomPasswd = base64.StdEncoding.EncodeToString([]byte(randomPasswd))
		cipher = ""
	}
	defaultSSuser := &coreConf.ShadowsocksUserConfig{
		Cipher:   cipher,
		Password: randomPasswd,
	}
	settings.Users = append(settings.Users, defaultSSuser)
	settings.NetworkList = &coreConf.NetworkList{"tcp", "udp"}

	if nodeInfo.Protocol.Obfs != "" && nodeInfo.Protocol.Obfs == "http" {
		if nodeInfo.Protocol.ObfsPath != "" || nodeInfo.Protocol.ObfsHost != "" {
			settings.NetworkList = &coreConf.NetworkList{"tcp"}
		}
		t := coreConf.TransportProtocol("tcp")
		inbound.StreamSetting = &coreConf.StreamConfig{Network: &t}
		inbound.StreamSetting.TCPSettings = &coreConf.TCPConfig{}
		httpHeader := map[string]interface{}{
			"type":    "http",
			"request": map[string]interface{}{},
		}
		request := httpHeader["request"].(map[string]interface{})

		path := nodeInfo.Protocol.ObfsPath
		if path == "" {
			path = "/"
		}
		request["path"] = []string{path}

		if nodeInfo.Protocol.ObfsHost != "" {
			request["headers"] = map[string]interface{}{
				"Host": []string{nodeInfo.Protocol.ObfsHost},
			}
		}
		headerJSON, err := json.Marshal(httpHeader)
		if err == nil {
			inbound.StreamSetting.TCPSettings.HeaderConfig = json.RawMessage(headerJSON)
		}
	}

	sets, err := json.Marshal(settings)
	inbound.Settings = (*json.RawMessage)(&sets)
	if err != nil {
		return fmt.Errorf("marshal shadowsocks settings error: %s", err)
	}
	return nil
}

func buildHysteria2(nodeInfo *panel.NodeInfo, inbound *coreConf.InboundDetourConfig) error {
	inbound.Protocol = "hysteria"
	settings := &coreConf.HysteriaServerConfig{}

	t := coreConf.TransportProtocol("hysteria")
	inbound.StreamSetting = &coreConf.StreamConfig{Network: &t}

	sets, err := json.Marshal(settings)
	inbound.Settings = (*json.RawMessage)(&sets)
	if err != nil {
		return fmt.Errorf("marshal hysteria settings error: %s", err)
	}
	return nil
}

func buildTuic(nodeInfo *panel.NodeInfo, inbound *coreConf.InboundDetourConfig) error {
	inbound.Protocol = "tuic"
	settings := &coreConf.TuicServerConfig{
		CongestionControl: nodeInfo.Protocol.CongestionController,
		ZeroRttHandshake:  nodeInfo.Protocol.ReduceRTT,
	}
	t := coreConf.TransportProtocol("tuic")
	inbound.StreamSetting = &coreConf.StreamConfig{Network: &t}
	sets, err := json.Marshal(settings)
	inbound.Settings = (*json.RawMessage)(&sets)
	if err != nil {
		return fmt.Errorf("marshal tuic settings error: %s", err)
	}
	return nil
}

func buildAnyTLS(nodeInfo *panel.NodeInfo, inbound *coreConf.InboundDetourConfig) error {
	inbound.Protocol = "anytls"
	var padding []string
	//nodeInfo.Protocol.PaddingScheme "stop=8\n0=30-30\n1=100-400\n2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000\n3=9-9,500-1000\n4=500-1000\n5=500-1000\n6=500-1000\n7=500-1000"
	if nodeInfo.Protocol.PaddingScheme != "" {
		padding = strings.Split(nodeInfo.Protocol.PaddingScheme, "\n")
	}
	settings := &coreConf.AnyTLSServerConfig{
		PaddingScheme: padding,
	}
	// anytls does not support udp or i just can't implement it
	// TODO: Study AnyTLS* Prio #10
	t := coreConf.TransportProtocol("tcp")
	inbound.StreamSetting = &coreConf.StreamConfig{Network: &t}
	inbound.StreamSetting.TCPSettings = &coreConf.TCPConfig{}
	sets, err := json.Marshal(settings)
	inbound.Settings = (*json.RawMessage)(&sets)
	if err != nil {
		return fmt.Errorf("marshal anytls settings error: %s", err)
	}
	return nil
}

func mapSockopt(s *panel.Sockopt) *coreConf.SocketConfig {
	cfg := &coreConf.SocketConfig{
		Mark:                 int32(s.Mark),
		TProxy:               s.TProxy,
		DomainStrategy:       s.DomainStrategy,
		DialerProxy:          s.DialerProxy,
		TCPKeepAliveInterval: int32(s.TCPKeepAliveInterval),
		TCPKeepAliveIdle:     int32(s.TCPKeepAliveIdle),
		TCPCongestion:        s.TCPCongestion,
		TCPWindowClamp:       int32(s.TCPWindowClamp),
		TCPMaxSeg:            int32(s.TCPMaxSeg),
		Penetrate:            s.Penetrate,
		TCPUserTimeout:       int32(s.TCPUserTimeout),
		V6only:               s.V6Only,
		Interface:            s.InterfaceName,
		TcpMptcp:             s.Mptcp,
		AddressPortStrategy:  s.AddressPortStrategy,
	}
	if s.TCPFastOpen {
		cfg.TFO = true
	}
	if s.HappyEyeballs {
		cfg.HappyEyeballsSettings = &coreConf.HappyEyeballsConfig{
			PrioritizeIPv6: true,
		}
	}
	if len(s.TrustedXForwardedFor) > 0 {
		cfg.TrustedXForwardedFor = s.TrustedXForwardedFor
	}
	if s.CustomSockopt != "" {
		// Attempt to parse custom_sockopt if stored as JSON array:
		var customConfigs []*coreConf.CustomSockoptConfig
		if err := json.Unmarshal([]byte(s.CustomSockopt), &customConfigs); err == nil {
			cfg.CustomSockopt = customConfigs
		} else {
			// Line-by-line fallback parsing (e.g. system,network,level,opt,value,type)
			lines := strings.Split(s.CustomSockopt, "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if line == "" {
					continue
				}
				parts := strings.Split(line, ",")
				if len(parts) >= 4 {
					cfg.CustomSockopt = append(cfg.CustomSockopt, &coreConf.CustomSockoptConfig{
						Syetem:  "all",
						Network: "all",
						Level:   strings.TrimSpace(parts[0]),
						Type:    strings.TrimSpace(parts[1]),
						Opt:     strings.TrimSpace(parts[2]),
						Value:   strings.TrimSpace(parts[3]),
					})
				}
			}
		}
	}
	return cfg
}

// What changed: Added buildAccounts helper to extract static credentials for SOCKS/HTTP inbounds.
// Why: SOCKS and HTTP do not support dynamic user management. Credentials come from Protocol.User/Password if defined, otherwise from nodeInfo.Users (using Uuid as username and password).
func buildAccounts(nodeInfo *panel.NodeInfo) []map[string]string {
	var accounts []map[string]string
	if nodeInfo.Protocol != nil && nodeInfo.Protocol.User != "" && nodeInfo.Protocol.Password != "" {
		accounts = append(accounts, map[string]string{
			"user": nodeInfo.Protocol.User,
			"pass": nodeInfo.Protocol.Password,
		})
	}
	for _, u := range nodeInfo.Users {
		if u.Uuid != "" {
			accounts = append(accounts, map[string]string{
				"user": u.Uuid,
				"pass": u.Uuid,
			})
		}
	}
	return accounts
}

// What changed: Added buildSocks function to configure Xray SOCKS inbounds with password auth or unauthenticated mode.
// Why: Implements SOCKS inbound node support, generating static accounts or logging a warning if no auth credentials exist.
func buildSocks(nodeInfo *panel.NodeInfo, inbound *coreConf.InboundDetourConfig) error {
	inbound.Protocol = "socks"
	accounts := buildAccounts(nodeInfo)
	var settings map[string]interface{}
	listenIP := nodeInfo.Protocol.ListenIP
	if listenIP == "" {
		listenIP = "0.0.0.0"
	}

	if len(accounts) > 0 {
		settings = map[string]interface{}{
			"auth":     "password",
			"accounts": accounts,
			"udp":      true,
			"ip":       "127.0.0.1",
		}
	} else {
		settings = map[string]interface{}{
			"auth": "noauth",
			"udp":  true,
			"ip":   "127.0.0.1",
		}
		log.WithFields(log.Fields{
			"ip":   listenIP,
			"port": nodeInfo.Protocol.Port,
		}).Warnf("Unauthenticated SOCKS proxy exposed on %s:%d - open relay risk", listenIP, nodeInfo.Protocol.Port)
	}

	s, err := json.Marshal(settings)
	if err != nil {
		return fmt.Errorf("marshal socks config error: %s", err)
	}
	inbound.Settings = (*json.RawMessage)(&s)
	return nil
}

// What changed: Added buildHTTP function to configure Xray HTTP inbounds with static user auth or open proxy mode.
// Why: Implements HTTP inbound node support, generating static accounts or logging a warning if no auth credentials exist.
func buildHTTP(nodeInfo *panel.NodeInfo, inbound *coreConf.InboundDetourConfig) error {
	inbound.Protocol = "http"
	accounts := buildAccounts(nodeInfo)
	var settings map[string]interface{}
	listenIP := nodeInfo.Protocol.ListenIP
	if listenIP == "" {
		listenIP = "0.0.0.0"
	}

	if len(accounts) > 0 {
		settings = map[string]interface{}{
			"accounts":         accounts,
			"allowTransparent": false,
		}
	} else {
		settings = map[string]interface{}{
			"allowTransparent": false,
		}
		log.WithFields(log.Fields{
			"ip":   listenIP,
			"port": nodeInfo.Protocol.Port,
		}).Warnf("Unauthenticated HTTP proxy exposed on %s:%d - open relay risk", listenIP, nodeInfo.Protocol.Port)
	}

	s, err := json.Marshal(settings)
	if err != nil {
		return fmt.Errorf("marshal http config error: %s", err)
	}
	inbound.Settings = (*json.RawMessage)(&s)
	return nil
}

// What changed: Added BuildShadowTLSInnerSSInbound function to build loopback Shadowsocks inbound configs for ShadowTLS.
// Why: Enables node auto-provisioning of the inner Shadowsocks transport for ShadowTLS without applying outer TLS/Reality or sniffing settings.
func BuildShadowTLSInnerSSInbound(nodeInfo *panel.NodeInfo, innerTag string) (*core.InboundHandlerConfig, error) {
	proto := nodeInfo.Protocol
	if proto == nil {
		return nil, fmt.Errorf("protocol config is nil")
	}

	listenIP := proto.ShadowsocksListen
	if listenIP == "" {
		listenIP = "127.0.0.1"
	}

	network := proto.ShadowsocksNetwork
	if network == "" {
		network = "tcp"
	}

	// What changed: Resolved cipher from proto.ShadowsocksMethod, falling back to proto.Cipher for backward compatibility.
	// Why: Backend panels send the cipher as "shadowsocks_method" in JSON; fallback ensures existing configs remain compatible.
	cipher := proto.ShadowsocksMethod
	if cipher == "" {
		cipher = proto.Cipher
	}
	serverKey := proto.ShadowsocksServerKey
	if serverKey == "" {
		serverKey = proto.ServerKey
	}

	// Validate 2022 PSK length if using a 2022 cipher
	if strings.Contains(cipher, "2022") {
		if serverKey == "" {
			return nil, fmt.Errorf("ShadowTLS inner Shadowsocks: 2022 cipher %s requires shadowsocks_server_key", cipher)
		}
		rawKey, err := base64.StdEncoding.DecodeString(serverKey)
		if err != nil {
			return nil, fmt.Errorf("ShadowTLS inner Shadowsocks: shadowsocks_server_key is invalid base64: %w", err)
		}
		if cipher == "2022-blake3-aes-128-gcm" {
			if len(rawKey) != 16 {
				return nil, fmt.Errorf("ShadowTLS inner Shadowsocks: 2022-blake3-aes-128-gcm server key must decode to exactly 16 bytes, got %d", len(rawKey))
			}
		} else {
			if len(rawKey) != 32 {
				return nil, fmt.Errorf("ShadowTLS inner Shadowsocks: %s server key must decode to exactly 32 bytes, got %d", cipher, len(rawKey))
			}
		}
	}

	in := &coreConf.InboundDetourConfig{
		Protocol: "shadowsocks",
		Tag:      innerTag,
		PortList: &coreConf.PortList{
			Range: []coreConf.PortRange{
				{
					From: uint32(proto.ShadowsocksPort),
					To:   uint32(proto.ShadowsocksPort),
				},
			},
		},
		ListenOn: &coreConf.Address{
			Address: net.ParseAddress(listenIP),
		},
	}

	settings := &coreConf.ShadowsocksServerConfig{
		Cipher:      cipher,
		NetworkList: &coreConf.NetworkList{coreConf.Network(network)},
	}

	p := make([]byte, 32)
	if _, err := rand.Read(p); err != nil {
		return nil, fmt.Errorf("generate random password error: %w", err)
	}
	randomPasswd := hex.EncodeToString(p)

	userCipher := cipher
	if strings.Contains(cipher, "2022") {
		settings.Password = serverKey
		randomPasswd = serverKey
		userCipher = ""
	}
	defaultSSuser := &coreConf.ShadowsocksUserConfig{
		Cipher:   userCipher,
		Password: randomPasswd,
	}
	settings.Users = append(settings.Users, defaultSSuser)

	sets, err := json.Marshal(settings)
	if err != nil {
		return nil, fmt.Errorf("marshal inner shadowsocks settings error: %w", err)
	}
	in.Settings = (*json.RawMessage)(&sets)

	return in.Build()
}

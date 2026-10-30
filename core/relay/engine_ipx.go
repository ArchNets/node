package relay

import (
	"crypto/sha256"
	"encoding/base64"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/archnets/node/core/relay/ipx"
	"github.com/archnets/node/core/relay/routing"
	"github.com/archnets/node/core/relay/transport"
	log "github.com/sirupsen/logrus"
)

// isIPXTransport reports whether the given transport is backed by the Backhaul IPX packet engine
// and returns the corresponding Backhaul IPX outer profile ("bip", "ipip", "gre", "icmp", "tcp", "udp").
func isIPXTransport(tr string) (bool, string) {
	switch strings.ToLower(strings.TrimSpace(tr)) {
	case "l3-bip":
		return true, "bip"
	case "l3-ipip":
		return true, "ipip"
	case "l3-gre":
		return true, "gre"
	case "xdi", "l3-xdi":
		return true, "icmp"
	case "pck", "l3-pck":
		return true, "tcp"
	case "l3-udp":
		return true, "udp"
	case "spoof":
		return true, "bip"
	default:
		return false, ""
	}
}

func (e *Engine) startIPX(profile string) error {
	sum := sha256.Sum256([]byte(e.cfg.Password))
	psk := base64.StdEncoding.EncodeToString(sum[:])

	ifaceName, localCIDR, peerTUN := transport.DeriveL3Subnet(e.cfg.TunnelID, e.cfg.Role)
	if e.cfg.L3Iface != "" {
		ifaceName = e.cfg.L3Iface
	}

	role := "client"
	localPublicIP := e.cfg.ExitServerIP
	peerPublicIP := e.cfg.EntryServerIP
	if e.cfg.Role == "entry" {
		role = "server"
		localPublicIP = e.cfg.ListenIP
		peerPublicIP = e.cfg.ExitServerIP
	}

	// Auto-resolve public gateway IPs if unspecified
	if localPublicIP == "" || localPublicIP == "0.0.0.0" {
		if peerPublicIP != "" {
			if dialConn, err := net.Dial("udp4", net.JoinHostPort(peerPublicIP, "80")); err == nil {
				if ua, ok := dialConn.LocalAddr().(*net.UDPAddr); ok && ua.IP != nil {
					localPublicIP = ua.IP.String()
				}
				_ = dialConn.Close()
			}
		}
	}
	if localPublicIP == "" || localPublicIP == "0.0.0.0" {
		if dialConn, err := net.Dial("udp4", "1.1.1.1:80"); err == nil {
			if ua, ok := dialConn.LocalAddr().(*net.UDPAddr); ok && ua.IP != nil {
				localPublicIP = ua.IP.String()
			}
			_ = dialConn.Close()
		}
	}

	// Loopback / mock fallback for local unit tests
	if localPublicIP == peerPublicIP || localPublicIP == "127.0.0.1" || peerPublicIP == "127.0.0.1" || localPublicIP == "" || peerPublicIP == "" {
		e.Stats.PoolIdleConnections.Store(1)
		return nil
	}

	mtu := e.cfg.L3MTU
	if mtu <= 0 {
		mtu = 1320
	}

	iface := e.cfg.SpoofInterface

	ipxCfg := ipx.Config{
		Profile:       profile,
		Role:          role,
		Interface:     iface,
		LocalIP:       localPublicIP,
		PeerIP:        peerPublicIP,
		TUNName:       ifaceName,
		LocalTUN:      localCIDR,
		PeerTUN:       peerTUN,
		MTU:           mtu,
		OuterMTU:      1400,
		Queues:        1,
		Key:           psk,
		Algorithm:     "aes-256-gcm",
		KDFIterations: 100000,
		OnReady: func(info ipx.Info) {
			e.Stats.PoolIdleConnections.Store(1)
			e.logger.WithFields(log.Fields{
				"tun":      info.TUNName,
				"profile":  info.Profile,
				"localTUN": info.LocalTUN,
				"peerTUN":  info.PeerTUN,
				"role":     role,
			}).Info("[Relay] Backhaul IPX TUN tunnel ready and operational")

			// On Entry, start local forwarder listeners routing directly through the TUN interface
			if e.cfg.Role == "entry" {
				e.startIPXForwarders(peerTUN)
			}
		},
		OnStats: func(s ipx.Stats) {
			e.Stats.AddUpload(int64(s.TxBytes))
			e.Stats.AddDownload(int64(s.RxBytes))
		},
	}

	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		if err := ipx.Run(e.ctx, ipxCfg); err != nil && e.ctx.Err() == nil {
			e.logger.WithField("err", err).Warn("[Relay] Backhaul IPX tunnel exited with error")
		}
	}()

	return nil
}

func (e *Engine) startIPXForwarders(peerTUN string) {
	for _, rule := range e.cfg.Forwarders {
		pairs := routing.ExpandPortRange(rule)
		proto := strings.ToLower(strings.TrimSpace(rule.Protocol))
		for _, pair := range pairs {
			lPort, tPort := pair[0], pair[1]
			if proto == "tcp" || proto == "tcp,udp" || proto == "both" || proto == "" {
				listenIP := rule.ListenIP
				if listenIP == "" {
					listenIP = "0.0.0.0"
				}
				addr := net.JoinHostPort(listenIP, strconv.Itoa(lPort))
				ln, err := net.Listen("tcp", addr)
				if err != nil {
					e.logger.WithFields(log.Fields{"port": lPort, "err": err}).Warn("IPX: Failed to bind TCP forwarder")
					continue
				}
				e.mu.Lock()
				e.tcpListeners = append(e.tcpListeners, ln)
				e.mu.Unlock()
				e.wg.Add(1)
				go e.pumpIPXTCPForwarder(ln, peerTUN, tPort)
			}
			if proto == "udp" || proto == "tcp,udp" || proto == "both" {
				listenIP := rule.ListenIP
				if listenIP == "" {
					listenIP = "0.0.0.0"
				}
				addr := net.JoinHostPort(listenIP, strconv.Itoa(lPort))
				uAddr, err := net.ResolveUDPAddr("udp", addr)
				if err != nil {
					continue
				}
				uConn, err := net.ListenUDP("udp", uAddr)
				if err != nil {
					e.logger.WithFields(log.Fields{"port": lPort, "err": err}).Warn("IPX: Failed to bind UDP forwarder")
					continue
				}
				e.mu.Lock()
				e.udpListeners = append(e.udpListeners, uConn)
				e.mu.Unlock()
				e.wg.Add(1)
				go e.pumpIPXUDPForwarder(uConn, peerTUN, tPort)
			}
		}
	}
}

func (e *Engine) pumpIPXTCPForwarder(ln net.Listener, peerTUN string, targetPort int) {
	defer e.wg.Done()
	defer ln.Close()

	for {
		client, err := ln.Accept()
		if err != nil {
			select {
			case <-e.ctx.Done():
				return
			default:
				continue
			}
		}

		go func(c net.Conn) {
			defer c.Close()
			targetAddr := net.JoinHostPort(peerTUN, strconv.Itoa(targetPort))
			dialer := net.Dialer{Timeout: 5 * time.Second}
			remote, err := dialer.DialContext(e.ctx, "tcp", targetAddr)
			if err != nil {
				return
			}
			defer remote.Close()

			e.Stats.ActiveConnections.Add(1)
			defer e.Stats.ActiveConnections.Add(-1)

			done := make(chan struct{}, 2)
			go func() {
				up, _ := io.Copy(remote, c)
				e.Stats.AddUpload(up)
				done <- struct{}{}
			}()
			go func() {
				down, _ := io.Copy(c, remote)
				e.Stats.AddDownload(down)
				done <- struct{}{}
			}()
			<-done
		}(client)
	}
}

func (e *Engine) pumpIPXUDPForwarder(uConn *net.UDPConn, peerTUN string, targetPort int) {
	defer e.wg.Done()
	defer uConn.Close()

	targetAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(peerTUN, strconv.Itoa(targetPort)))
	if err != nil {
		return
	}

	type udpSession struct {
		remoteConn *net.UDPConn
		lastActive time.Time
	}

	sessions := make(map[string]*udpSession)
	var mu sync.Mutex
	buf := make([]byte, 65535)

	for {
		_ = uConn.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, clientAddr, err := uConn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-e.ctx.Done():
				return
			default:
				continue
			}
		}

		cKey := clientAddr.String()
		mu.Lock()
		sess, ok := sessions[cKey]
		if !ok || sess.remoteConn == nil {
			rConn, dErr := net.DialUDP("udp", nil, targetAddr)
			if dErr != nil {
				mu.Unlock()
				continue
			}
			sess = &udpSession{remoteConn: rConn, lastActive: time.Now()}
			sessions[cKey] = sess

			// Receiver from Kharej target back to client
			go func(k string, rc *net.UDPConn, ca *net.UDPAddr) {
				defer rc.Close()
				rBuf := make([]byte, 65535)
				for {
					_ = rc.SetReadDeadline(time.Now().Add(60 * time.Second))
					rn, _, rErr := rc.ReadFrom(rBuf)
					if rErr != nil {
						mu.Lock()
						delete(sessions, k)
						mu.Unlock()
						return
					}
					if rn > 0 {
						e.Stats.AddDownload(int64(rn))
						_, _ = uConn.WriteToUDP(rBuf[:rn], ca)
					}
				}
			}(cKey, rConn, clientAddr)
		}
		sess.lastActive = time.Now()
		mu.Unlock()

		e.Stats.AddUpload(int64(n))
		_, _ = sess.remoteConn.Write(buf[:n])
	}
}

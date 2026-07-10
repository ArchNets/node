package node

import (
	"fmt"
	"sync"

	"github.com/archnets/node/api/panel"
	"github.com/archnets/node/conf"
	vCore "github.com/archnets/node/core"
	log "github.com/sirupsen/logrus"
)

// NodeController interface for both Xray and SSH controllers
type NodeController interface {
	Start() error
	Close() error
}

type Node struct {
	xrayControllers      []*Controller
	sshControllers       []*SSHController
	shadowtlsControllers []*ShadowTLSController
	wireguardControllers []*WireGuardController
	amneziawgControllers []*AmneziaWGController
	ipsecControllers     []*IPsecController
	openvpnControllers   []*OpenVPNController
	tunnelController     *TunnelController
}

func New(core *vCore.XrayCore, config *conf.Conf, serverconfig *panel.ServerConfigResponse) (*Node, error) {
	node := &Node{
		xrayControllers:      make([]*Controller, 0),
		sshControllers:       make([]*SSHController, 0),
		shadowtlsControllers: make([]*ShadowTLSController, 0),
		wireguardControllers: make([]*WireGuardController, 0),
		amneziawgControllers: make([]*AmneziaWGController, 0),
		ipsecControllers:     make([]*IPsecController, 0),
		openvpnControllers:   make([]*OpenVPNController, 0),
	}
	pushinterval := serverconfig.Data.PushInterval
	if pushinterval <= 0 {
		pushinterval = 60
	}
	pullinterval := serverconfig.Data.PullInterval
	if pullinterval <= 0 {
		pullinterval = 60
	}
	// Track protocol type counts for generating unique tags
	protocolCounts := make(map[string]int)
	// Track created clients for reuse
	clientMap := make(map[string]*panel.ClientV1)

	for _, cfg := range *serverconfig.Data.Protocols {
		nodeconfig := cfg
		if !nodeconfig.Enable {
			continue
		}
		// Increment protocol count for this type
		protocolCounts[nodeconfig.Type]++
		protocolIndex := protocolCounts[nodeconfig.Type]

		n := &panel.NodeInfo{
			Id:                     config.ApiConfig.ServerId,
			Type:                   nodeconfig.Type,
			TrafficReportThreshold: serverconfig.Data.TrafficReportThreshold,
			PushInterval:           pushinterval,
			PullInterval:           pullinterval,
			Protocol:               &nodeconfig,
		}

		var p *panel.ClientV1
		var err error
		isPrimaryReporter := false

		// Check if we already have a client for this protocol type
		if existingClient, ok := clientMap[nodeconfig.Type]; ok {
			p = existingClient
			// Use existing client, so this is NOT the primary reporter
			isPrimaryReporter = false
			log.WithFields(log.Fields{
				"type": nodeconfig.Type,
				"port": nodeconfig.Port,
			}).Info("Reusing existing client for protocol")
		} else {
			// Create new client
			p, err = panel.NewClientV1(&conf.NodeApiConfig{
				APIHost:   config.ApiConfig.ApiHost,
				NodeType:  nodeconfig.Type,
				NodeID:    config.ApiConfig.ServerId,
				SecretKey: config.ApiConfig.SecretKey,
			})
			if err != nil {
				return nil, err
			}
			// This is the first client for this type, so it IS the primary reporter
			clientMap[nodeconfig.Type] = p
			isPrimaryReporter = true
		}

		// Handle SSH protocol separately
		if nodeconfig.Type == "ssh" {
			node.sshControllers = append(node.sshControllers, NewSSHController(p, n, isPrimaryReporter))
			log.WithFields(log.Fields{
				"type": "ssh",
				"port": nodeconfig.Port,
			}).Info("SSH protocol detected, using SSH controller")
		} else if nodeconfig.Type == "wireguard" {
			node.wireguardControllers = append(node.wireguardControllers, NewWireGuardController(core, p, n, isPrimaryReporter))
			log.WithFields(log.Fields{
				"type": "wireguard",
				"port": nodeconfig.Port,
			}).Info("WireGuard protocol detected, using WireGuard controller")
		} else if nodeconfig.Type == "amneziawg" {
			node.amneziawgControllers = append(node.amneziawgControllers, NewAmneziaWGController(core, p, n, isPrimaryReporter))
			log.WithFields(log.Fields{
				"type": "amneziawg",
				"port": nodeconfig.Port,
			}).Info("AmneziaWG protocol detected, using AmneziaWG controller")
		} else if nodeconfig.Type == "shadowtls" {
			// FIX: Create a local copy to ensure pointer safety (though Go 1.22+ handles loop vars)
			cfg := nodeconfig

			// Log debug info if needed (reverted to Info or removed for production)
			// log.WithFields(log.Fields{...}).Debug("ShadowTLS config")

			// Update n.Protocol to point to our local safe copy to avoid loop variable issues
			n.Protocol = &cfg
			node.shadowtlsControllers = append(node.shadowtlsControllers, NewShadowTLSController(p, n, isPrimaryReporter))
			log.WithFields(log.Fields{
				"type": "shadowtls",
				"port": nodeconfig.Port,
			}).Info("ShadowTLS protocol detected, using ShadowTLS controller")
		} else if nodeconfig.Type == "ikev2" || nodeconfig.Type == "l2tp" || nodeconfig.Type == "ipsec" {
			node.ipsecControllers = append(node.ipsecControllers, NewIPsecController(core, p, n, isPrimaryReporter))
			log.WithFields(log.Fields{
				"type": nodeconfig.Type,
				"port": nodeconfig.Port,
			}).Info("IPsec/IKEv2 protocol detected, using IPsec controller")
		} else if nodeconfig.Type == "openvpn" {
			node.openvpnControllers = append(node.openvpnControllers, NewOpenVPNController(core, p, n, isPrimaryReporter))
			log.WithFields(log.Fields{
				"type": "openvpn",
				"port": nodeconfig.Port,
			}).Info("OpenVPN protocol detected, using OpenVPN controller")
		} else {
			node.xrayControllers = append(node.xrayControllers, NewControllerWithIndex(core, p, n, protocolIndex, isPrimaryReporter))
		}
	}

	return node, nil
}

// startParallel runs start(item) for every item concurrently and returns
// any errors collected, in no particular order. Used to start independent
// controller instances (different ports/tags, no ordering dependency)
// concurrently instead of blocking one after another.
func startParallel[T any](items []T, start func(T) error) []error {
	var wg sync.WaitGroup
	errCh := make(chan error, len(items))

	for _, item := range items {
		wg.Add(1)
		go func(it T) {
			defer wg.Done()
			if err := start(it); err != nil {
				errCh <- err
			}
		}(item)
	}

	wg.Wait()
	close(errCh)

	var errs []error
	for err := range errCh {
		errs = append(errs, err)
	}
	return errs
}

func (n *Node) Start() error {
	// Start Xray controllers
	if errs := startParallel(n.xrayControllers, func(c *Controller) error {
		if err := c.Start(); err != nil {
			return fmt.Errorf("xray node [%s-%s-%d]: %w",
				c.apiClient.APIHost, c.info.Type, c.info.Id, err)
		}
		return nil
	}); len(errs) > 0 {
		return fmt.Errorf("failed to start xray node: %s", errs[0])
	}

	// Start SSH controllers
	if errs := startParallel(n.sshControllers, func(c *SSHController) error {
		if err := c.Start(); err != nil {
			return fmt.Errorf("ssh node [%s]: %w", c.tag, err)
		}
		return nil
	}); len(errs) > 0 {
		return errs[0]
	}

	// Start ShadowTLS controllers
	if errs := startParallel(n.shadowtlsControllers, func(c *ShadowTLSController) error {
		if err := c.Start(); err != nil {
			return fmt.Errorf("shadowtls node [%s]: %w", c.tag, err)
		}
		return nil
	}); len(errs) > 0 {
		return errs[0]
	}

	// Start WireGuard controllers
	if errs := startParallel(n.wireguardControllers, func(c *WireGuardController) error {
		if err := c.Start(); err != nil {
			return fmt.Errorf("wireguard node [%s]: %w", c.tag, err)
		}
		return nil
	}); len(errs) > 0 {
		return errs[0]
	}

	// Start AmneziaWG controllers
	if errs := startParallel(n.amneziawgControllers, func(c *AmneziaWGController) error {
		if err := c.Start(); err != nil {
			return fmt.Errorf("amneziawg node [%s]: %w", c.tag, err)
		}
		return nil
	}); len(errs) > 0 {
		return errs[0]
	}

	// Start IPsec controllers (log-and-continue on failure, matching prior behavior)
	startParallel(n.ipsecControllers, func(c *IPsecController) error {
		if err := c.Start(); err != nil {
			log.WithFields(log.Fields{
				"tag": c.tag,
				"err": err,
			}).Error("Failed to start IPsec node (strongSwan may not be installed)")
		}
		return nil
	})

	// Start OpenVPN controllers (log-and-continue on failure, matching prior behavior)
	startParallel(n.openvpnControllers, func(c *OpenVPNController) error {
		if err := c.Start(); err != nil {
			log.WithFields(log.Fields{
				"tag": c.tag,
				"err": err,
			}).Error("Failed to start OpenVPN node (openvpn binary may not be installed)")
		}
		return nil
	})

	// Start Tunnel controller -- kept sequential and last, since it may
	// depend on the other controllers already being up (allocated ports,
	// exit node config, etc.)
	if n.tunnelController != nil {
		err := n.tunnelController.Start()
		if err != nil {
			return fmt.Errorf("failed to start tunnel controller [%s]: %s",
				n.tunnelController.tag,
				err)
		}
	}

	return nil
}

// closeParallel runs close(item) for every item concurrently, logging
// individual errors with the given label instead of blocking one after
// another. Mirrors startParallel's concurrency model for shutdown.
func closeParallel[T any](items []T, label string, close func(T) error) {
	var wg sync.WaitGroup
	for _, item := range items {
		wg.Add(1)
		go func(it T) {
			defer wg.Done()
			if err := close(it); err != nil {
				log.WithError(err).Errorf("Error closing %s controller", label)
			}
		}(item)
	}
	wg.Wait()
}

func (n *Node) Close() {
	// Close Xray controllers
	closeParallel(n.xrayControllers, "Xray", func(c *Controller) error { return c.Close() })
	n.xrayControllers = nil

	// Close SSH controllers
	closeParallel(n.sshControllers, "SSH", func(c *SSHController) error { return c.Close() })
	n.sshControllers = nil

	// Close ShadowTLS controllers
	closeParallel(n.shadowtlsControllers, "ShadowTLS", func(c *ShadowTLSController) error { return c.Close() })
	n.shadowtlsControllers = nil

	// Close WireGuard controllers
	closeParallel(n.wireguardControllers, "WireGuard", func(c *WireGuardController) error { return c.Close() })
	n.wireguardControllers = nil

	// Close AmneziaWG controllers
	closeParallel(n.amneziawgControllers, "AmneziaWG", func(c *AmneziaWGController) error { return c.Close() })
	n.amneziawgControllers = nil

	// Close IPsec controllers
	closeParallel(n.ipsecControllers, "IPsec", func(c *IPsecController) error { return c.Close() })
	n.ipsecControllers = nil

	// Close OpenVPN controllers
	closeParallel(n.openvpnControllers, "OpenVPN", func(c *OpenVPNController) error { return c.Close() })
	n.openvpnControllers = nil

	// Close Tunnel controller
	if n.tunnelController != nil {
		err := n.tunnelController.Close()
		if err != nil {
			log.WithError(err).Error("Error closing Tunnel controller")
		}
		n.tunnelController = nil
	}
}

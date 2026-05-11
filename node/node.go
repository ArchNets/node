package node

import (
	"fmt"

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
		} else {
			node.xrayControllers = append(node.xrayControllers, NewControllerWithIndex(core, p, n, protocolIndex, isPrimaryReporter))
		}
	}

	return node, nil
}

func (n *Node) Start() error {
	// Start Xray controllers
	for i := range n.xrayControllers {
		err := n.xrayControllers[i].Start()
		if err != nil {
			return fmt.Errorf("failed to start xray node [%s-%s-%d]: %s",
				n.xrayControllers[i].apiClient.APIHost,
				n.xrayControllers[i].info.Type,
				n.xrayControllers[i].info.Id,
				err)
		}
	}

	// Start SSH controllers
	for i := range n.sshControllers {
		err := n.sshControllers[i].Start()
		if err != nil {
			return fmt.Errorf("failed to start ssh node [%s]: %s",
				n.sshControllers[i].tag,
				err)
		}
	}

	// Start ShadowTLS controllers
	for i := range n.shadowtlsControllers {
		err := n.shadowtlsControllers[i].Start()
		if err != nil {
			return fmt.Errorf("failed to start shadowtls node [%s]: %s",
				n.shadowtlsControllers[i].tag,
				err)
		}
	}

	// Start WireGuard controllers
	for i := range n.wireguardControllers {
		err := n.wireguardControllers[i].Start()
		if err != nil {
			return fmt.Errorf("failed to start wireguard node [%s]: %s",
				n.wireguardControllers[i].tag,
				err)
		}
	}

	// Start AmneziaWG controllers
	for i := range n.amneziawgControllers {
		err := n.amneziawgControllers[i].Start()
		if err != nil {
			return fmt.Errorf("failed to start amneziawg node [%s]: %s",
				n.amneziawgControllers[i].tag,
				err)
		}
	}

	// Start IPsec controllers
	for i := range n.ipsecControllers {
		err := n.ipsecControllers[i].Start()
		if err != nil {
			log.WithFields(log.Fields{
				"tag": n.ipsecControllers[i].tag,
				"err": err,
			}).Error("Failed to start IPsec node (strongSwan may not be installed)")
		}
	}

	// Start Tunnel controller
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

func (n *Node) Close() {
	// Close Xray controllers
	for _, c := range n.xrayControllers {
		err := c.Close()
		if err != nil {
			log.WithError(err).Error("Error closing Xray controller")
		}
	}
	n.xrayControllers = nil

	// Close SSH controllers
	for _, c := range n.sshControllers {
		err := c.Close()
		if err != nil {
			log.WithError(err).Error("Error closing SSH controller")
		}
	}
	n.sshControllers = nil

	// Close ShadowTLS controllers
	for _, c := range n.shadowtlsControllers {
		err := c.Close()
		if err != nil {
			log.WithError(err).Error("Error closing ShadowTLS controller")
		}
	}
	n.shadowtlsControllers = nil

	// Close WireGuard controllers
	for _, c := range n.wireguardControllers {
		err := c.Close()
		if err != nil {
			log.WithError(err).Error("Error closing WireGuard controller")
		}
	}
	n.wireguardControllers = nil

	// Close AmneziaWG controllers
	for _, c := range n.amneziawgControllers {
		err := c.Close()
		if err != nil {
			log.WithError(err).Error("Error closing AmneziaWG controller")
		}
	}
	n.amneziawgControllers = nil

	// Close IPsec controllers
	for _, c := range n.ipsecControllers {
		err := c.Close()
		if err != nil {
			log.WithError(err).Error("Error closing IPsec controller")
		}
	}
	n.ipsecControllers = nil

	// Close Tunnel controller
	if n.tunnelController != nil {
		err := n.tunnelController.Close()
		if err != nil {
			log.WithError(err).Error("Error closing Tunnel controller")
		}
		n.tunnelController = nil
	}
}

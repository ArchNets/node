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
}

func New(core *vCore.XrayCore, config *conf.Conf, serverconfig *panel.ServerConfigResponse) (*Node, error) {
	node := &Node{
		xrayControllers:      make([]*Controller, 0),
		sshControllers:       make([]*SSHController, 0),
		shadowtlsControllers: make([]*ShadowTLSController, 0),
		wireguardControllers: make([]*WireGuardController, 0),
	}
	pushinterval := serverconfig.Data.PushInterval
	if pushinterval <= 0 {
		pushinterval = 60
	}
	pullinterval := serverconfig.Data.PullInterval
	if pullinterval <= 0 {
		pullinterval = 60
	}
	for _, nodeconfig := range *serverconfig.Data.Protocols {
		if !nodeconfig.Enable {
			continue
		}
		n := &panel.NodeInfo{
			Id:                     config.ApiConfig.ServerId,
			Type:                   nodeconfig.Type,
			TrafficReportThreshold: serverconfig.Data.TrafficReportThreshold,
			PushInterval:           pushinterval,
			PullInterval:           pullinterval,
			Protocol:               &nodeconfig,
		}
		p, err := panel.NewClientV1(&conf.NodeApiConfig{
			APIHost:   config.ApiConfig.ApiHost,
			NodeType:  nodeconfig.Type,
			NodeID:    config.ApiConfig.ServerId,
			SecretKey: config.ApiConfig.SecretKey,
		})
		if err != nil {
			return nil, err
		}

		// Handle SSH protocol separately
		if nodeconfig.Type == "ssh" {
			node.sshControllers = append(node.sshControllers, NewSSHController(p, n))
			log.WithFields(log.Fields{
				"type": "ssh",
				"port": nodeconfig.Port,
			}).Info("SSH protocol detected, using SSH controller")
		} else if nodeconfig.Type == "wireguard" {
			node.wireguardControllers = append(node.wireguardControllers, NewWireGuardController(p, n))
			log.WithFields(log.Fields{
				"type": "wireguard",
				"port": nodeconfig.Port,
			}).Info("WireGuard protocol detected, using WireGuard controller")
		} else if nodeconfig.Type == "shadowtls" {
			// FIX: Create a local copy to ensure pointer safety (though Go 1.22+ handles loop vars)
			cfg := nodeconfig

			// Log debug info if needed (reverted to Info or removed for production)
			// log.WithFields(log.Fields{...}).Debug("ShadowTLS config")

			// Update n.Protocol to point to our local safe copy to avoid loop variable issues
			n.Protocol = &cfg
			node.shadowtlsControllers = append(node.shadowtlsControllers, NewShadowTLSController(p, n))
			log.WithFields(log.Fields{
				"type": "shadowtls",
				"port": nodeconfig.Port,
			}).Info("ShadowTLS protocol detected, using ShadowTLS controller")
		} else {
			node.xrayControllers = append(node.xrayControllers, NewController(core, p, n))
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
}

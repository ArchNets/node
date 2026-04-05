package node

import (
	"fmt"

	"github.com/archnets/node/api/panel"
	"github.com/archnets/node/common/task"
	vCore "github.com/archnets/node/core"
	"github.com/archnets/node/limiter"
	log "github.com/sirupsen/logrus"
)

type Controller struct {
	server                  *vCore.XrayCore
	apiClient               *panel.ClientV1
	tag                     string
	protocolIndex           int // Index for duplicate protocol types (1, 2, 3...)
	limiter                 *limiter.Limiter
	userList                []panel.UserInfo
	aliveMap                map[int]int
	info                    *panel.NodeInfo
	userListMonitorPeriodic *task.Task
	userReportPeriodic      *task.Task
	renewCertPeriodic       *task.Task
	onlineIpReportPeriodic  *task.Task
	isPrimaryReporter       bool // true if this controller is responsible for reporting status/online users
}

// NewController return a Node controller with default parameters.
func NewController(core *vCore.XrayCore, api *panel.ClientV1, info *panel.NodeInfo) *Controller {
	return NewControllerWithIndex(core, api, info, 1, true)
}

// NewControllerWithIndex creates a controller with a specific protocol index for unique tag generation
func NewControllerWithIndex(core *vCore.XrayCore, api *panel.ClientV1, info *panel.NodeInfo, protocolIndex int, isPrimaryReporter bool) *Controller {
	controller := &Controller{
		server:            core,
		apiClient:         api,
		info:              info,
		protocolIndex:     protocolIndex,
		isPrimaryReporter: isPrimaryReporter,
	}
	return controller
}

// Start implement the Start() function of the service interface
func (c *Controller) Start() error {
	var err error
	// Update user
	c.userList, err = c.apiClient.GetUserList()
	if err != nil {
		log.WithError(err).Warn("Failed to fetch initial user list, starting with empty list")
		c.userList = []panel.UserInfo{}
	}
	if len(c.userList) == 0 {
		log.Warn("User list is empty, node started with no users")
	}
	c.aliveMap, err = c.apiClient.GetUserAlive()
	if err != nil {
		return fmt.Errorf("failed to get user alive list: %s", err)
	}
	c.tag = c.buildNodeTag(c.info)

	// add limiter
	l := limiter.AddLimiter(c.info.Type, c.tag, c.userList, c.aliveMap)
	c.limiter = l

	if c.info.Protocol.Security == "tls" {
		err = c.requestCert()
		if err != nil {
			return fmt.Errorf("request cert error: %s", err)
		}
	}
	// Add new tag
	err = c.server.AddNode(c.tag, c.info)
	if err != nil {
		return fmt.Errorf("add new node error: %s", err)
	}
	added, err := c.server.AddUsers(&vCore.AddUsersParams{
		Tag:      c.tag,
		Users:    c.userList,
		NodeInfo: c.info,
	})
	if err != nil {
		return fmt.Errorf("add users error: %s", err)
	}
	log.WithField("node", c.tag).Infof("Added %d new users", added)
	c.startTasks(c.info)
	return nil
}

// Close implement the Close() function of the service interface
func (c *Controller) Close() error {
	limiter.DeleteLimiter(c.tag)
	if c.userListMonitorPeriodic != nil {
		c.userListMonitorPeriodic.Close()
	}
	if c.userReportPeriodic != nil {
		c.userReportPeriodic.Close()
	}
	if c.renewCertPeriodic != nil {
		c.renewCertPeriodic.Close()
	}
	if c.onlineIpReportPeriodic != nil {
		c.onlineIpReportPeriodic.Close()
	}
	err := c.server.DelNode(c.tag)
	if err != nil {
		return fmt.Errorf("del node error: %s", err)
	}
	return nil
}

func (c *Controller) buildNodeTag(node *panel.NodeInfo) string {
	if c.protocolIndex > 1 {
		// Multiple protocols of same type: add index suffix
		return fmt.Sprintf("%s-%d:%d", node.Type, c.protocolIndex, node.Id)
	}
	// Single protocol of this type: use original format
	return fmt.Sprintf("%s:%d", node.Type, node.Id)
}

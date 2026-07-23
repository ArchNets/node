package core

import (
	"sync"

	log "github.com/sirupsen/logrus"
)

var tproxyIpRuleOnce sync.Once

// ensureTProxyIpRule installs the global fwmark rule + local route
// that deliver TPROXY-marked packets to Xray. Shared by all tunnel
// protocols; safe to call concurrently from multiple instances.
func ensureTProxyIpRule() {
	tproxyIpRuleOnce.Do(func() {
		// `ip rule show` exits 0 even with no match — must check output
		if err := execCommand("ip rule show fwmark 1 lookup 100 | grep -q ."); err != nil {
			if err := execCommand("ip rule add fwmark 1 lookup 100"); err != nil {
				log.WithError(err).Error("Failed to add fwmark ip rule — TPROXY routing will not work")
			}
		}
		_ = execCommand("ip route replace local 0.0.0.0/0 dev lo table 100")
	})
}

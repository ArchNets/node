package core

import (
	"encoding/json"
	"os"
	"strings"

	"github.com/archnets/node/api/panel"
	log "github.com/sirupsen/logrus"
)

// connectivityBypassEnv is a node-local override for the panel flag. It exists so
// the bypass can be turned on before the panel exposes the field, and so a single
// node can be opted out without a panel change.
const connectivityBypassEnv = "NODE_BYPASS_CONNECTIVITY_CHECKS"

// connectivityBypassTag is the tag of the node's direct (freedom) outbound.
const connectivityBypassTag = "direct"

// defaultConnectivityCheckDomains lists the hostnames used by operating system and
// browser captive-portal probes. They are matched with "full:" so only the exact
// host is bypassed, never a parent domain.
var defaultConnectivityCheckDomains = []string{
	"full:connectivitycheck.gstatic.com",
	"full:connectivitycheck.android.com",
	"full:clients3.google.com",
	"full:clients4.google.com",
	"full:www.gstatic.com",
	"full:cp.cloudflare.com",
	"full:captive.apple.com",
	"full:detectportal.firefox.com",
	"full:www.msftconnecttest.com",
	"full:ipv6.msftconnecttest.com",
	"full:www.msftncsi.com",
	"full:dns.msftncsi.com",
	"full:connectivity-check.ubuntu.com",
	"full:nmcheck.gnome.org",
	"full:network-test.debian.org",
}

// connectivityCheckPathRegexp matches the well-known cleartext probe paths. Xray
// treats attrs values as regular expressions, so one rule covers all of them. It is
// deliberately not anchored at the end because some clients append a query string.
const connectivityCheckPathRegexp = `^/(generate_204|gen_204|ncsi\.txt|connecttest\.txt|hotspot-detect\.html|success\.txt|nm_check\.txt)`

// domainRulePrefixes are the Xray routing domain prefixes left untouched when
// normalising a panel-supplied host list.
var domainRulePrefixes = []string{"full:", "domain:", "keyword:", "regexp:", "geosite:", "ext:"}

// connectivityBypassEnabled reports whether the bypass is on. The environment
// variable wins over the panel flag in both directions; with neither set, it is off.
func connectivityBypassEnabled(data *panel.Data) bool {
	if v := strings.TrimSpace(os.Getenv(connectivityBypassEnv)); v != "" {
		switch strings.ToLower(v) {
		case "1", "true", "yes", "on":
			return true
		case "0", "false", "no", "off":
			return false
		}
	}
	return data != nil && data.BypassConnectivityChecks
}

// normalizeCheckDomains trims, de-duplicates and prefixes a panel-supplied host
// list. A bare hostname becomes an exact (full:) match; existing prefixes are kept.
func normalizeCheckDomains(in []string) []string {
	out := make([]string, 0, len(in))
	seen := make(map[string]bool, len(in))
	for _, d := range in {
		d = strings.TrimSpace(d)
		if d == "" {
			continue
		}
		lower := strings.ToLower(d)
		prefixed := false
		for _, p := range domainRulePrefixes {
			if strings.HasPrefix(lower, p) {
				prefixed = true
				break
			}
		}
		if !prefixed {
			d = "full:" + d
		}
		if seen[d] {
			continue
		}
		seen[d] = true
		out = append(out, d)
	}
	return out
}

// connectivityCheckRules returns routing rules that send captive-portal probes
// straight out of the node instead of through a proxy outbound. It returns nil when
// the feature is off, so the generated config is unchanged by default.
//
// Callers must append these rules AFTER the block rules (so blocking still wins) and
// BEFORE the panel's own routing rules, because Xray evaluates rules top-down and
// the first match wins.
//
// The path rule can only match cleartext HTTP/1.x: the path of an HTTPS request is
// inside the TLS record and is invisible to routing. HTTPS probes are covered at host
// granularity by the domain rule instead.
func connectivityCheckRules(data *panel.Data) []json.RawMessage {
	if !connectivityBypassEnabled(data) {
		return nil
	}

	domains := defaultConnectivityCheckDomains
	custom := false
	if data != nil && data.ConnectivityCheckDomains != nil {
		if normalized := normalizeCheckDomains(*data.ConnectivityCheckDomains); len(normalized) > 0 {
			domains = normalized
			custom = true
		}
	}

	var rules []json.RawMessage
	if len(domains) > 0 {
		rawRule, err := json.Marshal(map[string]interface{}{
			"ruleTag":     "bypass-connectivity-check-hosts",
			"domain":      domains,
			"outboundTag": connectivityBypassTag,
		})
		if err == nil {
			rules = append(rules, rawRule)
		} else {
			log.WithField("error", err.Error()).Warn("Failed to build connectivity-check host rule")
		}
	}

	rawPathRule, err := json.Marshal(map[string]interface{}{
		"ruleTag":     "bypass-connectivity-check-paths",
		"network":     "tcp",
		"port":        "80",
		"attrs":       map[string]string{":path": connectivityCheckPathRegexp},
		"outboundTag": connectivityBypassTag,
	})
	if err == nil {
		rules = append(rules, rawPathRule)
	} else {
		log.WithField("error", err.Error()).Warn("Failed to build connectivity-check path rule")
	}

	log.WithFields(log.Fields{
		"hosts":       len(domains),
		"customHosts": custom,
		"rules":       len(rules),
		"outboundTag": connectivityBypassTag,
	}).Info("Connectivity-check bypass enabled")

	return rules
}

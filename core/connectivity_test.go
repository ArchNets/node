package core

import (
	"encoding/json"
	"regexp"
	"testing"

	"github.com/archnets/node/api/panel"
)

func decodeRule(t *testing.T, raw json.RawMessage) map[string]interface{} {
	t.Helper()
	var rule map[string]interface{}
	if err := json.Unmarshal(raw, &rule); err != nil {
		t.Fatalf("rule is not valid JSON: %v", err)
	}
	return rule
}

func TestConnectivityBypassOffByDefault(t *testing.T) {
	if rules := connectivityCheckRules(nil); rules != nil {
		t.Fatalf("expected no rules for nil data, got %d", len(rules))
	}
	if rules := connectivityCheckRules(&panel.Data{}); rules != nil {
		t.Fatalf("expected no rules while the flag is unset, got %d", len(rules))
	}
}

func TestConnectivityBypassDefaultHosts(t *testing.T) {
	rules := connectivityCheckRules(&panel.Data{BypassConnectivityChecks: true})
	if len(rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(rules))
	}

	host := decodeRule(t, rules[0])
	if host["outboundTag"] != connectivityBypassTag {
		t.Fatalf("unexpected outboundTag %v", host["outboundTag"])
	}
	domains, ok := host["domain"].([]interface{})
	if !ok || len(domains) != len(defaultConnectivityCheckDomains) {
		t.Fatalf("unexpected domain list %v", host["domain"])
	}
	if domains[0] != "full:connectivitycheck.gstatic.com" {
		t.Fatalf("unexpected first domain %v", domains[0])
	}

	path := decodeRule(t, rules[1])
	attrs, ok := path["attrs"].(map[string]interface{})
	if !ok {
		t.Fatalf("attrs must serialise as a JSON object, got %T", path["attrs"])
	}
	if attrs[":path"] != connectivityCheckPathRegexp {
		t.Fatalf("unexpected :path %v", attrs[":path"])
	}
	if path["port"] != "80" || path["network"] != "tcp" {
		t.Fatalf("unexpected port/network %v %v", path["port"], path["network"])
	}
}

func TestConnectivityCheckCustomHosts(t *testing.T) {
	custom := []string{" my.probe.example ", "domain:check.example", "my.probe.example", "", "full:my.probe.example"}
	rules := connectivityCheckRules(&panel.Data{BypassConnectivityChecks: true, ConnectivityCheckDomains: &custom})
	host := decodeRule(t, rules[0])
	domains, _ := host["domain"].([]interface{})
	want := []string{"full:my.probe.example", "domain:check.example"}
	if len(domains) != len(want) {
		t.Fatalf("expected %d domains, got %v", len(want), domains)
	}
	for i, w := range want {
		if domains[i] != w {
			t.Fatalf("domain %d: want %q got %v", i, w, domains[i])
		}
	}
}

func TestConnectivityBypassEnvOverride(t *testing.T) {
	t.Setenv(connectivityBypassEnv, "true")
	if !connectivityBypassEnabled(&panel.Data{}) {
		t.Fatal("env should enable the bypass while the panel flag is off")
	}
	t.Setenv(connectivityBypassEnv, "off")
	if connectivityBypassEnabled(&panel.Data{BypassConnectivityChecks: true}) {
		t.Fatal("env should disable the bypass while the panel flag is on")
	}
	t.Setenv(connectivityBypassEnv, "")
	if !connectivityBypassEnabled(&panel.Data{BypassConnectivityChecks: true}) {
		t.Fatal("an empty env value should fall back to the panel flag")
	}
}

func TestConnectivityCheckPathRegexp(t *testing.T) {
	re, err := regexp.Compile(connectivityCheckPathRegexp)
	if err != nil {
		t.Fatalf("path regexp does not compile: %v", err)
	}
	for _, p := range []string{"/generate_204", "/generate_204?foo=1", "/gen_204", "/connecttest.txt", "/ncsi.txt", "/hotspot-detect.html"} {
		if !re.MatchString(p) {
			t.Fatalf("expected %q to match", p)
		}
	}
	for _, p := range []string{"/index.html", "/api/generate_204"} {
		if re.MatchString(p) {
			t.Fatalf("expected %q not to match", p)
		}
	}
}

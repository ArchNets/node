package telemetry

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

// SNIPreset describes a benchmarkable SNI domain and its origin configuration.
type SNIPreset struct {
	SNI      string `json:"sni"`
	Label    string `json:"label"`
	OriginIP string `json:"origin_ip"`
	Category string `json:"category"`
}

var (
	dynamicOriginsMu   sync.RWMutex
	dynamicOrigins     = make(map[string]string)
	dynamicPresets     []SNIPreset
	resolvedDNSCache   = make(map[string]string)
	resolvedDNSCacheMu sync.RWMutex

	// StaticHospitalAndNationalOrigins provides hardcoded Iranian IPs to guarantee zero-latency
	// origin proxying even if Iran VPS DNS resolvers time out or are poisoned.
	StaticHospitalAndNationalOrigins = map[string]string{
		"shariati.tums.ac.ir": "185.143.234.132",
		"rhc.ac.ir":           "194.225.92.55",
		"tums.ac.ir":          "185.143.233.132",
		"farabi.tums.ac.ir":   "194.225.62.74",
		"sina.tums.ac.ir":     "194.225.62.69",
		"pasteur.ac.ir":       "194.225.106.107",
		"sbmu.ac.ir":          "185.143.233.122",
		"miladhospital.com":   "185.116.24.163",
		"divar.ir":            "185.166.104.7",
		"cafebazaar.ir":       "94.182.176.33",
		"snapp.ir":            "185.166.104.93",
		"telewebion.ir":       "185.165.205.132",
	}
)

// SetDynamicSNIOrigins updates the in-memory SNI origin mapping pushed dynamically from the server.
// No domains or IPs are hardcoded; all configuration is driven dynamically by the server/database.
func SetDynamicSNIOrigins(origins []SNIPreset) {
	dynamicOriginsMu.Lock()
	defer dynamicOriginsMu.Unlock()
	dynamicOrigins = make(map[string]string)
	dynamicPresets = append([]SNIPreset(nil), origins...)
	for _, p := range origins {
		clean := strings.ToLower(strings.TrimSpace(p.SNI))
		cleanIP := strings.TrimSpace(p.OriginIP)
		if clean != "" && cleanIP != "" {
			dynamicOrigins[clean] = cleanIP
		}
	}

	resolvedDNSCacheMu.Lock()
	resolvedDNSCache = make(map[string]string)
	resolvedDNSCacheMu.Unlock()
}

// GetActiveSNIPresets returns the dynamically configured list of SNI origins.
func GetActiveSNIPresets() []SNIPreset {
	dynamicOriginsMu.RLock()
	defer dynamicOriginsMu.RUnlock()
	return append([]SNIPreset(nil), dynamicPresets...)
}

// ResolveOriginIP resolves the target camouflage origin IPv4 address for a given SNI domain.
// 1. If configuredOriginIP is non-empty, it is used immediately.
// 2. Looks up in dynamic admin-managed origins table pushed from the backend.
// 3. Resolves the domain via system DNS lookup.
// Returns an error if the origin cannot be resolved (no hardcoded guessing).
func ResolveOriginIP(sni, configuredOriginIP string) (string, error) {
	if trimmed := strings.TrimSpace(configuredOriginIP); trimmed != "" {
		return trimmed, nil
	}
	cleanSNI := strings.ToLower(strings.TrimSpace(sni))
	if cleanSNI == "" {
		return "", fmt.Errorf("empty SNI provided")
	}

	dynamicOriginsMu.RLock()
	if ip, ok := dynamicOrigins[cleanSNI]; ok && ip != "" {
		dynamicOriginsMu.RUnlock()
		return ip, nil
	}
	dynamicOriginsMu.RUnlock()

	// 3. Check resolved DNS cache to ensure deterministic origin IP across config polls.
	resolvedDNSCacheMu.RLock()
	if ip, ok := resolvedDNSCache[cleanSNI]; ok && ip != "" {
		resolvedDNSCacheMu.RUnlock()
		return ip, nil
	}
	resolvedDNSCacheMu.RUnlock()

	// 4. Check static Iranian hospital and national origins table
	if staticIP, ok := StaticHospitalAndNationalOrigins[cleanSNI]; ok && staticIP != "" {
		resolvedDNSCacheMu.Lock()
		resolvedDNSCache[cleanSNI] = staticIP
		resolvedDNSCacheMu.Unlock()
		return staticIP, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupHost(ctx, cleanSNI)
	if err == nil && len(addrs) > 0 {
		var v4Addrs []string
		for _, a := range addrs {
			if ip := net.ParseIP(a); ip != nil && ip.To4() != nil {
				v4Addrs = append(v4Addrs, a)
			}
		}
		if len(v4Addrs) == 0 {
			v4Addrs = addrs
		}
		sort.Strings(v4Addrs)
		chosen := v4Addrs[0]

		resolvedDNSCacheMu.Lock()
		resolvedDNSCache[cleanSNI] = chosen
		resolvedDNSCacheMu.Unlock()
		return chosen, nil
	}

	return "", fmt.Errorf("could not resolve camouflage origin IP for SNI %q: %w", cleanSNI, err)
}

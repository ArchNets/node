package cert

import (
	"path/filepath"
	"strconv"
	"strings"
)

const CertDir = "/etc/archnets/"

// SanitizeDomain converts a domain name to a safe filename component
// by replacing dots with dashes (e.g., "test.archnets.org" -> "test-archnets-org")
func SanitizeDomain(domain string) string {
	if domain == "" {
		return "unknown"
	}
	// Replace dots with dashes for safe filename
	sanitized := strings.ReplaceAll(domain, ".", "-")
	// Also replace any other potentially problematic characters
	sanitized = strings.ReplaceAll(sanitized, "/", "-")
	sanitized = strings.ReplaceAll(sanitized, ":", "-")
	sanitized = strings.ReplaceAll(sanitized, " ", "-")
	return sanitized
}

// GetCertPaths returns the certificate and key file paths for a given protocol.
// Format: /etc/archnets/{sanitized_sni}-{type}{id}.crt and .key
// Example: /etc/archnets/test-archnets-org-anytls1.crt
func GetCertPaths(sni, protocolType string, protocolId int) (certFile, keyFile string) {
	sanitizedSNI := SanitizeDomain(sni)
	baseName := sanitizedSNI + "-" + protocolType + strconv.Itoa(protocolId)
	certFile = filepath.Join(CertDir, baseName+".crt")
	keyFile = filepath.Join(CertDir, baseName+".key")
	return
}

// GetLegacyCertPaths returns the old-style certificate paths for backward compatibility.
// Format: /etc/archnets/{type}{id}.cer
// This can be removed once all deployments are updated.
func GetLegacyCertPaths(protocolType string, protocolId int) (certFile, keyFile string) {
	baseName := protocolType + strconv.Itoa(protocolId)
	certFile = filepath.Join(CertDir, baseName+".cer")
	keyFile = filepath.Join(CertDir, baseName+".key")
	return
}

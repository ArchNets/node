package core

import (
	"os"
	"testing"

	"github.com/archnets/node/api/panel"
)

func TestBuildInboundHysteria2(t *testing.T) {
	// Create temporary dummy cert and key files so TLS config validation passes
	certFile, err := os.CreateTemp("", "cert*.pem")
	if err != nil {
		t.Fatalf("failed to create temp cert file: %v", err)
	}
	defer os.Remove(certFile.Name())
	certFile.WriteString("-----BEGIN CERTIFICATE-----\ndummy\n-----END CERTIFICATE-----\n")
	certFile.Close()

	keyFile, err := os.CreateTemp("", "key*.pem")
	if err != nil {
		t.Fatalf("failed to create temp key file: %v", err)
	}
	defer os.Remove(keyFile.Name())
	keyFile.WriteString("-----BEGIN PRIVATE KEY-----\ndummy\n-----END PRIVATE KEY-----\n")
	keyFile.Close()

	nodeInfo := &panel.NodeInfo{
		Type: "hysteria",
		Protocol: &panel.Protocol{
			Port:         2053,
			ListenIP:     "0.0.0.0",
			Security:     "tls",
			SNI:          "sweden.archlix.com",
			CertMode:     "path",
			CertFile:     certFile.Name(),
			KeyFile:      keyFile.Name(),
			Obfs:         "salamander",
			ObfsPassword: "isdrpuxgkspxr3im",
		},
	}

	inboundHandlerConfig, err := buildInbound(nodeInfo, "hysteria:10")
	if err != nil {
		t.Fatalf("buildInbound failed for hysteria: %v", err)
	}

	if inboundHandlerConfig == nil {
		t.Fatal("expected inboundHandlerConfig to not be nil")
	}

	if inboundHandlerConfig.Tag != "hysteria:10" {
		t.Errorf("expected tag hysteria:10, got %s", inboundHandlerConfig.Tag)
	}
}

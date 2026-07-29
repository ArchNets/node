package core

import (
	"encoding/base64"
	"testing"

	"github.com/archnets/node/api/panel"
)

func TestBuildShadowTLSInnerSSInbound(t *testing.T) {
	// 1. Legacy cipher (e.g. aes-128-gcm)
	infoLegacy := &panel.NodeInfo{
		Id:   1,
		Type: "shadowtls",
		Protocol: &panel.Protocol{
			Port:            8443,
			ShadowsocksPort: 10001,
			Cipher:          "aes-128-gcm",
		},
	}

	config, err := BuildShadowTLSInnerSSInbound(infoLegacy, "test_tag_inner_ss")
	if err != nil {
		t.Fatalf("unexpected error for legacy cipher inner SS inbound: %v", err)
	}
	if config.Tag != "test_tag_inner_ss" {
		t.Fatalf("expected tag test_tag_inner_ss, got %s", config.Tag)
	}

	// 2. 2022 cipher with 16-byte key (2022-blake3-aes-128-gcm)
	valid16Key := base64.StdEncoding.EncodeToString([]byte("1234567890123456"))
	info2022_16 := &panel.NodeInfo{
		Id:   2,
		Type: "shadowtls",
		Protocol: &panel.Protocol{
			Port:                 8443,
			ShadowsocksPort:      10002,
			Cipher:               "2022-blake3-aes-128-gcm",
			ShadowsocksServerKey: valid16Key,
		},
	}
	_, err = BuildShadowTLSInnerSSInbound(info2022_16, "test_tag_inner_ss_2022")
	if err != nil {
		t.Fatalf("unexpected error for valid 16-byte 2022 inner SS key: %v", err)
	}

	// 3. 2022 cipher with wrong key length (32 bytes required for 2022-blake3-aes-256-gcm, but 16 provided)
	info2022_invalidLen := &panel.NodeInfo{
		Id:   3,
		Type: "shadowtls",
		Protocol: &panel.Protocol{
			Port:                 8443,
			ShadowsocksPort:      10003,
			Cipher:               "2022-blake3-aes-256-gcm",
			ShadowsocksServerKey: valid16Key,
		},
	}
	_, err = BuildShadowTLSInnerSSInbound(info2022_invalidLen, "test_tag_invalid")
	if err == nil {
		t.Fatal("expected error for 2022-blake3-aes-256-gcm with 16-byte key, got nil")
	}

	// 4. Invalid base64 key
	infoInvalidBase64 := &panel.NodeInfo{
		Id:   4,
		Type: "shadowtls",
		Protocol: &panel.Protocol{
			Port:                 8443,
			ShadowsocksPort:      10004,
			Cipher:               "2022-blake3-aes-128-gcm",
			ShadowsocksServerKey: "invalid_base64!!!",
		},
	}
	_, err = BuildShadowTLSInnerSSInbound(infoInvalidBase64, "test_tag_invalid_b64")
	if err == nil {
		t.Fatal("expected error for invalid base64 key, got nil")
	}

	// 5. ShadowsocksMethod field with Cipher fallback
	infoMethod := &panel.NodeInfo{
		Id:   5,
		Type: "shadowtls",
		Protocol: &panel.Protocol{
			Port:                 8443,
			ShadowsocksPort:      10005,
			ShadowsocksMethod:    "2022-blake3-aes-128-gcm",
			ShadowsocksServerKey: valid16Key,
		},
	}
	_, err = BuildShadowTLSInnerSSInbound(infoMethod, "test_tag_method")
	if err != nil {
		t.Fatalf("unexpected error for ShadowsocksMethod inner SS inbound: %v", err)
	}
}

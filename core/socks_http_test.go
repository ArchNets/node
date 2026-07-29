package core

import (
	"encoding/json"
	"testing"

	"github.com/archnets/node/api/panel"
	coreConf "github.com/xtls/xray-core/infra/conf"
)

func TestBuildSocksInboundWithUsers(t *testing.T) {
	info := &panel.NodeInfo{
		Id:   1,
		Type: "socks",
		Protocol: &panel.Protocol{
			Port:     1080,
			ListenIP: "127.0.0.1",
		},
		Users: []panel.UserInfo{
			{Id: 100, Uuid: "user1-uuid"},
			{Id: 101, Uuid: "user2-uuid"},
		},
	}

	in := &coreConf.InboundDetourConfig{}
	err := buildSocks(info, in)
	if err != nil {
		t.Fatalf("buildSocks failed: %v", err)
	}

	var settings map[string]interface{}
	if err := json.Unmarshal(*in.Settings, &settings); err != nil {
		t.Fatalf("failed to unmarshal socks settings: %v", err)
	}

	if settings["auth"] != "password" {
		t.Errorf("expected auth='password', got %v", settings["auth"])
	}

	accounts, ok := settings["accounts"].([]interface{})
	if !ok || len(accounts) != 2 {
		t.Fatalf("expected 2 accounts, got %v", settings["accounts"])
	}
}

func TestBuildSocksInboundSharedCreds(t *testing.T) {
	info := &panel.NodeInfo{
		Id:   1,
		Type: "socks",
		Protocol: &panel.Protocol{
			Port:     1080,
			ListenIP: "127.0.0.1",
			User:     "shareduser",
			Password: "sharedpassword",
		},
	}

	in := &coreConf.InboundDetourConfig{}
	err := buildSocks(info, in)
	if err != nil {
		t.Fatalf("buildSocks shared failed: %v", err)
	}

	var settings map[string]interface{}
	if err := json.Unmarshal(*in.Settings, &settings); err != nil {
		t.Fatalf("failed to unmarshal socks settings: %v", err)
	}

	if settings["auth"] != "password" {
		t.Errorf("expected auth='password', got %v", settings["auth"])
	}

	accounts, ok := settings["accounts"].([]interface{})
	if !ok || len(accounts) != 1 {
		t.Fatalf("expected 1 account, got %v", settings["accounts"])
	}

	acc := accounts[0].(map[string]interface{})
	if acc["user"] != "shareduser" || acc["pass"] != "sharedpassword" {
		t.Errorf("unexpected account credentials: %v", acc)
	}
}

func TestBuildSocksInboundNoAuth(t *testing.T) {
	info := &panel.NodeInfo{
		Id:   1,
		Type: "socks",
		Protocol: &panel.Protocol{
			Port:     1080,
			ListenIP: "127.0.0.1",
		},
	}

	in := &coreConf.InboundDetourConfig{}
	err := buildSocks(info, in)
	if err != nil {
		t.Fatalf("buildSocks noauth failed: %v", err)
	}

	var settings map[string]interface{}
	if err := json.Unmarshal(*in.Settings, &settings); err != nil {
		t.Fatalf("failed to unmarshal socks settings: %v", err)
	}

	if settings["auth"] != "noauth" {
		t.Errorf("expected auth='noauth', got %v", settings["auth"])
	}
}

func TestBuildHTTPInboundWithUsers(t *testing.T) {
	info := &panel.NodeInfo{
		Id:   2,
		Type: "http",
		Protocol: &panel.Protocol{
			Port:     8080,
			ListenIP: "0.0.0.0",
		},
		Users: []panel.UserInfo{
			{Id: 200, Uuid: "httpuser-uuid"},
		},
	}

	in := &coreConf.InboundDetourConfig{}
	err := buildHTTP(info, in)
	if err != nil {
		t.Fatalf("buildHTTP failed: %v", err)
	}

	var settings map[string]interface{}
	if err := json.Unmarshal(*in.Settings, &settings); err != nil {
		t.Fatalf("failed to unmarshal http settings: %v", err)
	}

	accounts, ok := settings["accounts"].([]interface{})
	if !ok || len(accounts) != 1 {
		t.Fatalf("expected 1 account, got %v", settings["accounts"])
	}
}

func TestBuildHTTPInboundNoAuth(t *testing.T) {
	info := &panel.NodeInfo{
		Id:   2,
		Type: "http",
		Protocol: &panel.Protocol{
			Port:     8080,
			ListenIP: "0.0.0.0",
		},
	}

	in := &coreConf.InboundDetourConfig{}
	err := buildHTTP(info, in)
	if err != nil {
		t.Fatalf("buildHTTP noauth failed: %v", err)
	}

	var settings map[string]interface{}
	if err := json.Unmarshal(*in.Settings, &settings); err != nil {
		t.Fatalf("failed to unmarshal http settings: %v", err)
	}

	if _, exists := settings["accounts"]; exists {
		t.Errorf("expected no accounts field for unauthenticated http, got %v", settings["accounts"])
	}
}

func TestSocksHttpUserNoOp(t *testing.T) {
	xCore := New(nil, nil)

	info := &panel.NodeInfo{
		Type: "socks",
	}

	added, err := xCore.AddUsers(&AddUsersParams{
		Tag:      "socks-tag",
		NodeInfo: info,
		Users:    []panel.UserInfo{{Id: 1, Uuid: "u1"}},
	})
	if err != nil {
		t.Fatalf("unexpected error from AddUsers: %v", err)
	}
	if added != 1 {
		t.Errorf("expected added count to be 1, got %d", added)
	}

	err = xCore.DelUsers([]panel.UserInfo{{Id: 1, Uuid: "u1"}}, "socks-tag", info)
	if err != nil {
		t.Fatalf("unexpected error from DelUsers: %v", err)
	}
}

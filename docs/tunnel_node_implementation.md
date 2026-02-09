# Node Project - Tunnel Implementation Guide

## Overview

Backend generates all WaterWall configs including `core.json`. Node just fetches and applies them.

---

## 1. API Endpoint

```
GET /v2/server/:server_id/tunnel?secret_key=...
```

**Response:**

```json
{
  "core_config": {
    "mtu": 1450,
    "log_level": "DEBUG",
    "workers": 0,
    "ram_profile": "server"
  },
  "tunnels": [
    {
      "id": 1,
      "name": "italy3",
      "role": "entry",
      "config_json": "{ ... WaterWall config ... }",
      "forwarders": [
        {
          "protocol": "tcp",
          "listen_port": 30140,
          "target_ip": "30.8.1.2",
          "target_port": 30140,
          "forwarder_type": "gost"
        }
      ]
    }
  ]
}
```

---

## 2. Directory Structure

```
/etc/archnets/
├── config.yaml         # Node config
└── tunnel/             # WaterWall directory
    ├── Waterwall       # Binary
    ├── core.json       # Generated from core_config
    ├── tunnel_1.json   # Generated from config_json
    ├── libs/
    └── log/
```

---

## 3. WaterWall Installation

```bash
mkdir -p /etc/archnets/tunnel && cd /etc/archnets/tunnel
wget https://github.com/radkesvat/WaterWall/releases/latest/download/Waterwall-linux-amd64.zip
unzip Waterwall-linux-*.zip && chmod +x Waterwall && rm *.zip
mkdir -p log libs
```

---

## 4. Gost Installation

```bash
bash <(curl -4 -fsSL https://github.com/go-gost/gost/raw/master/install.sh) --install
```

---

## 5. NodePass Installation

```bash
# X86_64
cd /tmp && wget --inet4-only https://github.com/NodePassProject/nodepass/releases/download/v1.15.0/nodepass_1.15.0_linux_amd64.tar.gz
tar -xzf nodepass_*.tar.gz && mv nodepass /usr/local/bin/ && rm -f nodepass_*.tar.gz README.md LICENSE

# ARM64
cd /tmp && wget --inet4-only https://github.com/NodePassProject/nodepass/releases/download/v1.15.0/nodepass_1.15.0_linux_arm64.tar.gz
tar -xzf nodepass_*.tar.gz && mv nodepass /usr/local/bin/ && rm -f nodepass_*.tar.gz README.md LICENSE
```

---

## 6. Node Implementation

```go
func (c *TunnelController) Start() error {
    // 1. Fetch from backend
    resp, _ := c.apiClient.Get("/v2/server/{id}/tunnel")

    // 2. Generate core.json from core_config
    coreJSON := generateCoreJSON(resp.CoreConfig, tunnelFiles)
    os.WriteFile("/etc/archnets/tunnel/core.json", coreJSON, 0644)

    // 3. Write each tunnel config
    for _, t := range resp.Tunnels {
        filename := fmt.Sprintf("tunnel_%d.json", t.Id)
        os.WriteFile(filename, []byte(t.ConfigJSON), 0644)
    }

    // 4. Start WaterWall + forwarders
    // 5. Report status
}

func generateCoreJSON(cfg CoreConfig, tunnelFiles []string) []byte {
    return fmt.Sprintf(`{
        "log": {
            "path": "log/",
            "core": {"loglevel": "%s", "file": "core.log", "console": true},
            "network": {"loglevel": "%s", "file": "network.log", "console": true},
            "dns": {"loglevel": "%s", "file": "dns.log", "console": false},
            "internal": {"loglevel": "%s", "file": "internal.log", "console": true}
        },
        "dns": {},
        "misc": {"workers": %d, "mtu": %d, "ram-profile": "%s", "libs-path": "libs/"},
        "configs": %v
    }`, cfg.LogLevel, cfg.LogLevel, cfg.LogLevel, cfg.LogLevel,
        cfg.Workers, cfg.MTU, cfg.RamProfile, tunnelFiles)
}
```

---

## 7. Status Reporting

```
POST /v2/server/:server_id/tunnel/status?secret_key=...
```

```json
{
  "tunnels": [{ "tunnel_id": 1, "online": true, "latency_ms": 45 }]
}
```

---

## 8. Admin API (Backend)

### Tunnel Settings per Server

The `tunnel_settings` table stores per-server core.json config:

| Field       | Type   | Default | Description          |
| ----------- | ------ | ------- | -------------------- |
| server_id   | int64  | -       | Server ID            |
| mtu         | int    | 1450    | MTU size             |
| log_level   | string | FATAL   | FATAL/DEBUG/INFO     |
| workers     | int    | 0       | CPU workers (0=auto) |
| ram_profile | string | server  | server/client        |

If no settings exist for a server, defaults are returned.

# Adding a New Protocol to ArchNet

This guide explains the complete process of adding a new protocol to the ArchNet system. Follow these steps in order.

## Overview

Adding a new protocol requires changes across multiple components:

| Component             | Location                      | Purpose                        |
| --------------------- | ----------------------------- | ------------------------------ |
| Node Core             | `archnet-node/core/`          | Protocol server implementation |
| Node Controller       | `archnet-node/node/`          | User sync, traffic reporting   |
| Node Panel            | `archnet-node/api/panel/`     | Protocol type validation       |
| Backend Model         | `server/internal/model/node/` | Protocol configuration fields  |
| Subscription Template | `subscription-template/`      | Client config generation       |
| Frontend              | `frontend/packages/shared/`   | Admin UI configuration         |

---

## Step 1: Node Core Implementation

Create a new core service file: `core/<protocol>.go`

### Required Components

```go
package core

// 1. Core struct with essential fields
type <Protocol>Core struct {
    Tag        string
    Port       int
    config     *<Protocol>Config
    listener   net.Listener
    users      *UserMap           // UUID -> user ID mapping
    limiterRef *limiter.Limiter   // For device/IP limiting
    sessions   sync.Map           // Active sessions tracking
    running    atomic.Bool
    traffic    map[int]*UserTraffic  // Per-user traffic accounting
}

// 2. Constructor
func New<Protocol>Core(tag string, port int, config *Config) (*<Protocol>Core, error)

// 3. Lifecycle methods
func (c *<Protocol>Core) Start() error
func (c *<Protocol>Core) Stop() error

// 4. User management
func (c *<Protocol>Core) AddUsers(users []panel.UserInfo)
func (c *<Protocol>Core) DelUsers(users []panel.UserInfo)

// 5. Traffic accounting
func (c *<Protocol>Core) GetTrafficAndReset() map[int]*UserTraffic

// 6. Online users
func (c *<Protocol>Core) GetOnlineUsers() []panel.OnlineUser

// 7. Limiter integration
func (c *<Protocol>Core) SetLimiter(l *limiter.Limiter)
```

### Example: SSH Core

See `core/ssh.go` for a complete implementation reference.

---

## Step 2: Node Controller

Create a controller file: `node/<protocol>_controller.go`

### Required Components

```go
package node

// Controller struct
type <Protocol>Controller struct {
    core       *core.<Protocol>Core
    panel      *panel.ClientV1
    limiter    *limiter.Limiter
    tasks      []periodic.Stopper
    nodeConfig panel.Protocol
    config     *conf.Conf
}

// Constructor
func New<Protocol>Controller(p panel.Protocol, c *conf.Conf) *<Protocol>Controller

// Start - initializes core and starts periodic tasks
func (c *<Protocol>Controller) Start() error

// Close - stops core and tasks
func (c *<Protocol>Controller) Close() error
```

### Required Periodic Tasks

1. **User list sync** - Fetch users from backend, add/remove from core
2. **Traffic reporting** - Report upload/download to backend
3. **Online users reporting** - Report connected users to backend

See `node/ssh_controller.go` for a complete example.

---

## Step 3: Update Node Initialization

Modify `node/node.go` to route the new protocol:

```go
// In the New() function, add protocol routing:
if nodeconfig.Type == "<protocol>" {
    node.<protocol>Controllers = append(node.<protocol>Controllers, New<Protocol>Controller(p, n))
    log.Info("<Protocol> protocol detected, using <Protocol> controller")
} else {
    // Existing Xray handling
}
```

Update the `Node` struct to include the new controller list:

```go
type Node struct {
    xrayControllers     []*Controller
    sshControllers      []*SSHController
    <protocol>Controllers []*<Protocol>Controller  // Add this
}
```

Update `Start()` and `Close()` methods to handle the new controllers.

---

## Step 4: Add Protocol Type Validation

Update `api/panel/panel.go` to allow the new protocol type:

```go
switch c.NodeType {
case
    "vmess",
    "vless",
    // ... existing protocols ...
    "<protocol>":  // Add new protocol here
default:
    return nil, fmt.Errorf("unsupported Node type: %s", c.NodeType)
}
```

---

## Step 5: Backend Protocol Model

Update `server/internal/model/node/server.go` to add protocol-specific fields:

```go
type Protocol struct {
    // ... existing fields ...

    // <Protocol>-specific fields
    <Protocol>Field1 string `json:"<protocol>_field1,omitempty"`
    <Protocol>Field2 int    `json:"<protocol>_field2,omitempty"`
}
```

---

## Step 6: Subscription Template

Update `subscription-template/application.tpl`:

### 6.1 Add to supported protocols set

```go-template
{{- $supportSet := dict "shadowsocks" true ... "<protocol>" true -}}
```

### 6.2 Add protocol handling logic

```go-template
{{- else if eq $proxy.Type "<protocol>" -}}
  {{- $settings := dict "address" $server "port" $port -}}
  {{- /* Add protocol-specific settings */ -}}
  {{- $outbound = dict "protocol" "<protocol>" "tag" "proxy" "settings" $settings -}}
{{- end -}}
```

---

## Step 7: Frontend Configuration

### 7.1 Protocol Constants

Update `frontend/packages/shared/lib/protocolConstants.ts`:

```typescript
// Add to PROTOCOL_TYPES array
{
  id: '<protocol>',
  name: '<Protocol Name>',
  description: '<Description>',
  disabled: false,
}

// Add to getProtocolDefaultConfig()
case '<protocol>':
  return {
    ...base,
    // Add protocol-specific defaults
  };
```

### 7.2 Protocol Type Interface

Update `frontend/packages/shared/types/server.ts`:

```typescript
export interface Protocol {
  // ... existing fields ...

  // <Protocol>-specific
  <protocol>_field1?: string;
  <protocol>_field2?: number;
}
```

### 7.3 Admin UI (Optional)

If the protocol has complex configuration, update `ProtocolModal.tsx` to add protocol-specific form fields.

---

## Step 8: Testing

### 8.1 Core Tests

Create `core/<protocol>_test.go` with tests for:

- [ ] Core creation
- [ ] User add/delete
- [ ] Traffic accounting
- [ ] Start/stop lifecycle
- [ ] Authentication (if applicable)
- [ ] Connection handling

### 8.2 Node Tests

Update `node/node_test.go` to test protocol routing.

### 8.3 Build Verification

```bash
# Node
cd archnet-node && go build ./... && go test ./...

# Frontend
cd frontend && npx tsc --noEmit
```

---

## Checklist

Use this checklist when adding a new protocol:

- [ ] `core/<protocol>.go` - Core implementation
- [ ] `core/<protocol>_test.go` - Core tests
- [ ] `node/<protocol>_controller.go` - Controller implementation
- [ ] `node/node.go` - Protocol routing
- [ ] `api/panel/panel.go` - Type validation
- [ ] `api/panel/server.go` - Protocol fields (if needed)
- [ ] Backend `server.go` - Protocol fields (if needed)
- [ ] `subscription-template/application.tpl` - Client config
- [ ] `frontend/.../protocolConstants.ts` - Protocol type
- [ ] `frontend/.../server.ts` - TypeScript interface
- [ ] `frontend/.../ProtocolModal.tsx` - Admin UI (if complex config)
- [ ] Build and test all components

---

## Reference Implementations

| Protocol  | Core                | Controller                     | Notes                       |
| --------- | ------------------- | ------------------------------ | --------------------------- |
| SSH       | `core/ssh.go`       | `node/ssh_controller.go`       | Simple, good starting point |
| ShadowTLS | `core/shadowtls.go` | `node/shadowtls_controller.go` | Uses sing-shadowtls library |
| Xray      | `core/xray.go`      | `node/controller.go`           | Complex, multi-protocol     |

For questions, refer to the existing SSH implementation as a template.

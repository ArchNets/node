# TODO: Multi-Protocol Support Improvements

This document outlines planned improvements for better handling of multiple protocols of the same type (e.g., 2x VLESS on ports 49999 and 50001) within the `archnet-node` service and backend.

## Problem Statement

When a server is configured with multiple protocols of the same type (e.g., two VLESS instances):

1.  **Node Service Identity**: Each controller creates its own `ClientV1` using the protocol type string (e.g., "vless") as the identifier. This means all API calls (traffic push, online users, status) use the same query param `?protocol=vless`.
2.  **Cache Overwrites**: Online user reports from the second controller overwrite the first controller's data in the backend Redis cache, as the key is `node:online:subscribe:SERVER_ID:PROTOCOL_TYPE`.
3.  **Redundant Calls**: Both controllers independently fetch the user list and report server status (CPU/RAM), causing unnecessary load.
4.  **Backend Ambiguity**: The backend's `adapter` logic currently matches protocols by type only, meaning it always selects the first protocol's configuration for subscription generation, even for the second node.

## Planned Changes

### 1. Backend: Port-Based Protocol Matching

**Goal**: Ensure subscription generation and other backend logic correctly identifies the specific protocol instance.

**Implementation**:

- In `server/adapter/adapter.go`: Modify `Proxies()` to match protocols by BOTH type AND port.
  ```go
  if protocol.Type == item.Protocol && protocol.Port == item.Port {
      // ... match found
      break
  }
  ```
- In `server/internal/logic/server/getAliveListLogic.go`: Deduplicate protocol types before iterating to avoid double-counting online users.
- In `server/queue/logic/traffic/trafficStatisticsLogic.go`: Add warning logs if multiple same-type protocols have different ratios (since we can't easily distinguish traffic sources yet).

### 2. Node Service: Shared `ClientV1` Instance

**Goal**: Avoid creating multiple HTTP clients for the same protocol type.

**Implementation**:

- In `archnet-node/node/node.go`: Maintain a map of created `ClientV1` instances by protocol type.
- Reuse the existing client when initializing subsequent controllers of the same type.

### 3. Node Service: Primary Reporter Flag (`isPrimaryReporter`)

**Goal**: Prevent duplicate status reports and cache overwrites.

**Implementation**:

- Add `isPrimaryReporter bool` to the `Controller` struct.
- In `node/node.go`, set `isPrimary = true` only for the **first** controller of a given type.
- In `node/task.go`:
  - **Traffic Reporting**: All controllers continue to report their own traffic (backend aggregates this correctly).
  - **Online Users**: Only the primary controller reports online users.
  - **Server Status**: Only the primary controller reports CPU/RAM usage.

### 4. (Future) Aggregate Online Users

**Goal**: Report online users from ALL ports, not just the primary one.

**Implementation**:

- Modify the `Node` struct or `Controller` logic to aggregate online user data from all same-type controllers.
- Report the merged list via the primary controller.

## Implementation Order

1.  **Backend**: Fix `adapter.go` to use port-based matching (High Priority - fixes broken subscriptions).
2.  **Node Service**: Implement shared client and primary reporter flag.

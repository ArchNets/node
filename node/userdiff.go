package node

import (
	"strconv"

	"github.com/archnets/node/api/panel"
)

// userDiffKey is the identity + configuration fingerprint used to detect
// user changes between panel pulls. If any field in this key changes, the
// user shows up as deleted+added, which makes the controller re-provision
// them with the new settings.
//
// Fields:
//   - Uuid: identity
//   - SpeedLimit / DeviceLimit: limits enforced locally by the limiter; a
//     panel-side change must be picked up without a node restart. (DeviceLimit
//     was historically missing from this key, so device-limit changes were
//     silently ignored until restart.)
//   - ServiceId: per-user key material for WireGuard/AmneziaWG/IPsec
//     (e.g. the WG public key); empty for other protocols.
//
// The "|" separators prevent ambiguous concatenations (e.g. SpeedLimit 1,
// DeviceLimit 12 vs SpeedLimit 11, DeviceLimit 2).
func userDiffKey(u panel.UserInfo) string {
	return u.Uuid + "|" + strconv.Itoa(u.SpeedLimit) + "|" + strconv.Itoa(u.DeviceLimit) + "|" + u.ServiceId
}

// diffUserList compares two user lists and returns users to remove and to
// add. A user whose configuration changed appears in both lists (remove old,
// add new). Shared by all protocol controllers; replaces the six former
// copy-pasted compare*UserList implementations.
func diffUserList(old, new []panel.UserInfo) (deleted, added []panel.UserInfo) {
	oldMap := make(map[string]int, len(old))
	for i, u := range old {
		oldMap[userDiffKey(u)] = i
	}

	for _, u := range new {
		key := userDiffKey(u)
		if _, exists := oldMap[key]; !exists {
			added = append(added, u)
		} else {
			delete(oldMap, key)
		}
	}

	for _, index := range oldMap {
		deleted = append(deleted, old[index])
	}

	return deleted, added
}

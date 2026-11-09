package node

import (
	"testing"

	"github.com/archnets/node/api/panel"
	"github.com/stretchr/testify/assert"
)

func TestDiffUserList(t *testing.T) {
	tests := []struct {
		name        string
		oldUsers    []panel.UserInfo
		newUsers    []panel.UserInfo
		wantDeleted []panel.UserInfo
		wantAdded   []panel.UserInfo
	}{
		{
			name:        "No change",
			oldUsers:    []panel.UserInfo{{Id: 1, Uuid: "uuid1", SpeedLimit: 0, DeviceLimit: 1, ServiceId: "key1"}},
			newUsers:    []panel.UserInfo{{Id: 1, Uuid: "uuid1", SpeedLimit: 0, DeviceLimit: 1, ServiceId: "key1"}},
			wantDeleted: nil,
			wantAdded:   nil,
		},
		{
			name:        "User added",
			oldUsers:    []panel.UserInfo{},
			newUsers:    []panel.UserInfo{{Id: 1, Uuid: "uuid1", SpeedLimit: 0, DeviceLimit: 1, ServiceId: "key1"}},
			wantDeleted: nil,
			wantAdded:   []panel.UserInfo{{Id: 1, Uuid: "uuid1", SpeedLimit: 0, DeviceLimit: 1, ServiceId: "key1"}},
		},
		{
			name:        "User deleted",
			oldUsers:    []panel.UserInfo{{Id: 1, Uuid: "uuid1", SpeedLimit: 0, DeviceLimit: 1, ServiceId: "key1"}},
			newUsers:    []panel.UserInfo{},
			wantDeleted: []panel.UserInfo{{Id: 1, Uuid: "uuid1", SpeedLimit: 0, DeviceLimit: 1, ServiceId: "key1"}},
			wantAdded:   nil,
		},
		{
			name:        "Speed limit changed",
			oldUsers:    []panel.UserInfo{{Id: 1, Uuid: "uuid1", SpeedLimit: 0, DeviceLimit: 1, ServiceId: "key1"}},
			newUsers:    []panel.UserInfo{{Id: 1, Uuid: "uuid1", SpeedLimit: 100, DeviceLimit: 1, ServiceId: "key1"}},
			wantDeleted: []panel.UserInfo{{Id: 1, Uuid: "uuid1", SpeedLimit: 0, DeviceLimit: 1, ServiceId: "key1"}},
			wantAdded:   []panel.UserInfo{{Id: 1, Uuid: "uuid1", SpeedLimit: 100, DeviceLimit: 1, ServiceId: "key1"}},
		},
		{
			name:        "Device limit changed",
			oldUsers:    []panel.UserInfo{{Id: 1, Uuid: "uuid1", SpeedLimit: 0, DeviceLimit: 1, ServiceId: "key1"}},
			newUsers:    []panel.UserInfo{{Id: 1, Uuid: "uuid1", SpeedLimit: 0, DeviceLimit: 2, ServiceId: "key1"}},
			wantDeleted: []panel.UserInfo{{Id: 1, Uuid: "uuid1", SpeedLimit: 0, DeviceLimit: 1, ServiceId: "key1"}},
			wantAdded:   []panel.UserInfo{{Id: 1, Uuid: "uuid1", SpeedLimit: 0, DeviceLimit: 2, ServiceId: "key1"}},
		},
		{
			name:        "ServiceId (Key) changed",
			oldUsers:    []panel.UserInfo{{Id: 1, Uuid: "uuid1", SpeedLimit: 0, DeviceLimit: 1, ServiceId: "key1"}},
			newUsers:    []panel.UserInfo{{Id: 1, Uuid: "uuid1", SpeedLimit: 0, DeviceLimit: 1, ServiceId: "key2"}},
			wantDeleted: []panel.UserInfo{{Id: 1, Uuid: "uuid1", SpeedLimit: 0, DeviceLimit: 1, ServiceId: "key1"}},
			wantAdded:   []panel.UserInfo{{Id: 1, Uuid: "uuid1", SpeedLimit: 0, DeviceLimit: 1, ServiceId: "key2"}},
		},
		{
			name: "Delimiter collision prevention",
			// "1" + "12" vs "11" + "2" without delimiter would collide into "112"
			oldUsers:    []panel.UserInfo{{Id: 1, Uuid: "u", SpeedLimit: 1, DeviceLimit: 12, ServiceId: ""}},
			newUsers:    []panel.UserInfo{{Id: 1, Uuid: "u", SpeedLimit: 11, DeviceLimit: 2, ServiceId: ""}},
			wantDeleted: []panel.UserInfo{{Id: 1, Uuid: "u", SpeedLimit: 1, DeviceLimit: 12, ServiceId: ""}},
			wantAdded:   []panel.UserInfo{{Id: 1, Uuid: "u", SpeedLimit: 11, DeviceLimit: 2, ServiceId: ""}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotDeleted, gotAdded := diffUserList(tt.oldUsers, tt.newUsers)
			assert.ElementsMatch(t, tt.wantDeleted, gotDeleted, "deleted users mismatch")
			assert.ElementsMatch(t, tt.wantAdded, gotAdded, "added users mismatch")
		})
	}
}

func TestSplitTunnelUserDiff(t *testing.T) {
	oldUsers := []panel.UserInfo{
		{Id: 1, Uuid: "u1", SpeedLimit: 0, DeviceLimit: 1, ServiceId: "key1"},
		{Id: 2, Uuid: "u2", SpeedLimit: 0, DeviceLimit: 1, ServiceId: "key2"},
		{Id: 3, Uuid: "u3", SpeedLimit: 0, DeviceLimit: 1, ServiceId: "key3"},
	}
	newUsers := []panel.UserInfo{
		// u1: only DeviceLimit changed -> should NOT be in genDel/genAdd
		{Id: 1, Uuid: "u1", SpeedLimit: 0, DeviceLimit: 3, ServiceId: "key1"},
		// u2: ServiceId (key) changed -> MUST be in genDel and genAdd
		{Id: 2, Uuid: "u2", SpeedLimit: 0, DeviceLimit: 1, ServiceId: "key2-new"},
		// u3: removed -> MUST be in genDel
		// u4: added -> MUST be in genAdd
		{Id: 4, Uuid: "u4", SpeedLimit: 0, DeviceLimit: 1, ServiceId: "key4"},
	}

	deleted, added := diffUserList(oldUsers, newUsers)
	genDel, genAdd, limDel, limAdd := splitTunnelUserDiff(deleted, added)

	assert.Len(t, limDel, 1)
	assert.Equal(t, "u1", limDel[0].Uuid)
	assert.Len(t, limAdd, 1)
	assert.Equal(t, 3, limAdd[0].DeviceLimit)

	assert.Len(t, genDel, 2)
	assert.Len(t, genAdd, 2)
}

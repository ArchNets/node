package node

import (
	"testing"

	"github.com/archnets/node/api/panel"
	"github.com/stretchr/testify/assert"
)

func TestCompareWGUserList(t *testing.T) {
	tests := []struct {
		name        string
		oldUsers    []panel.UserInfo
		newUsers    []panel.UserInfo
		wantDeleted []panel.UserInfo
		wantAdded   []panel.UserInfo
	}{
		{
			name:        "No change",
			oldUsers:    []panel.UserInfo{{Id: 1, Uuid: "uuid1", SpeedLimit: 0, ServiceId: "key1"}},
			newUsers:    []panel.UserInfo{{Id: 1, Uuid: "uuid1", SpeedLimit: 0, ServiceId: "key1"}},
			wantDeleted: nil,
			wantAdded:   nil,
		},
		{
			name:        "User added",
			oldUsers:    []panel.UserInfo{},
			newUsers:    []panel.UserInfo{{Id: 1, Uuid: "uuid1", SpeedLimit: 0, ServiceId: "key1"}},
			wantDeleted: nil,
			wantAdded:   []panel.UserInfo{{Id: 1, Uuid: "uuid1", SpeedLimit: 0, ServiceId: "key1"}},
		},
		{
			name:        "User deleted",
			oldUsers:    []panel.UserInfo{{Id: 1, Uuid: "uuid1", SpeedLimit: 0, ServiceId: "key1"}},
			newUsers:    []panel.UserInfo{},
			wantDeleted: []panel.UserInfo{{Id: 1, Uuid: "uuid1", SpeedLimit: 0, ServiceId: "key1"}},
			wantAdded:   nil,
		},
		{
			name:        "Speed limit changed",
			oldUsers:    []panel.UserInfo{{Id: 1, Uuid: "uuid1", SpeedLimit: 0, ServiceId: "key1"}},
			newUsers:    []panel.UserInfo{{Id: 1, Uuid: "uuid1", SpeedLimit: 100, ServiceId: "key1"}},
			wantDeleted: []panel.UserInfo{{Id: 1, Uuid: "uuid1", SpeedLimit: 0, ServiceId: "key1"}},
			wantAdded:   []panel.UserInfo{{Id: 1, Uuid: "uuid1", SpeedLimit: 100, ServiceId: "key1"}},
		},
		{
			name:        "ServiceId (Key) changed",
			oldUsers:    []panel.UserInfo{{Id: 1, Uuid: "uuid1", SpeedLimit: 0, ServiceId: "key1"}},
			newUsers:    []panel.UserInfo{{Id: 1, Uuid: "uuid1", SpeedLimit: 0, ServiceId: "key2"}},
			wantDeleted: []panel.UserInfo{{Id: 1, Uuid: "uuid1", SpeedLimit: 0, ServiceId: "key1"}},
			wantAdded:   []panel.UserInfo{{Id: 1, Uuid: "uuid1", SpeedLimit: 0, ServiceId: "key2"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotDeleted, gotAdded := compareWGUserList(tt.oldUsers, tt.newUsers)
			assert.ElementsMatch(t, tt.wantDeleted, gotDeleted, "deleted users mismatch")
			assert.ElementsMatch(t, tt.wantAdded, gotAdded, "added users mismatch")
		})
	}
}

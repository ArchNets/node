package core

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTunnelRegistry(t *testing.T) {
	ip := "10.0.0.4"
	uid := 42
	uuid := "7d853e6b-3b7d-4bad-9bdd-2b0d7b3dcb6d"
	tag := "wg-40-443"

	// Register
	RegisterTunnelUser(ip, uid, uuid, tag)

	// Lookup
	user, found := LookupTunnelUser(ip)
	assert.True(t, found)
	assert.Equal(t, uid, user.UID)
	assert.Equal(t, uuid, user.UUID)
	assert.Equal(t, tag, user.Tag)

	// Lookup non-existent
	_, found = LookupTunnelUser("10.0.0.99")
	assert.False(t, found)

	// Unregister
	UnregisterTunnelUser(ip)
	_, found = LookupTunnelUser(ip)
	assert.False(t, found)

	// Blank IP handling
	RegisterTunnelUser("", 1, "test", "tag")
	_, found = LookupTunnelUser("")
	assert.False(t, found)
	UnregisterTunnelUser("")
}

func TestEnsureLogDir(t *testing.T) {
	// Should not error on special/empty keywords
	ensureLogDir("")
	ensureLogDir("none")
	ensureLogDir("stdout")
	ensureLogDir("console")

	// Should create a nested directory
	tmpDir := t.TempDir()
	logPath := tmpDir + "/nested/test/access.log"
	ensureLogDir(logPath)
	assert.DirExists(t, tmpDir+"/nested/test")
}

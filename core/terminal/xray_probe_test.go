package terminal

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	_ "github.com/archnets/node/core/distro/all"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRunXrayProbe_FreedomHTTP(t *testing.T) {
	targetSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer targetSrv.Close()

	cfgJSON := `{"log":{"loglevel":"warning"},"inbounds":[{"listen":"127.0.0.1","port":39999,"protocol":"socks"}],"outbounds":[{"protocol":"freedom"}]}`
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	out := RunXrayProbe(ctx, cfgJSON, targetSrv.URL)
	assert.Empty(t, out.Error)
	assert.True(t, out.Success)
	assert.Equal(t, http.StatusNoContent, out.HTTPCode)
}

func TestRunXrayProbe_VLESSMLKEMBuildsAndDials(t *testing.T) {
	// Start dummy TCP listener so Xray reaches dial stage cleanly and returns EOF/handshake error rather than config error
	ln := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer ln.Close()

	cfgJSON := `{
		"log": {"loglevel": "warning"},
		"inbounds": [{"listen": "127.0.0.1", "port": 39123, "protocol": "socks"}],
		"outbounds": [{
			"protocol": "vless",
			"settings": {
				"vnext": [{
					"address": "127.0.0.1",
					"port": 1,
					"users": [{
						"id": "1e2671f3-8ac8-4322-96d9-a3c517df64a5",
						"encryption": "mlkem768x25519plus.native.0rtt.gsgB9rKHZscxaFBUxC7wpSai6_S26jttZwe3n74Jgnw"
					}]
				}]
			},
			"streamSettings": {
				"network": "tcp",
				"security": "none",
				"tcpSettings": {
					"header": {
						"type": "http",
						"request": {
							"version": "1.1",
							"method": "GET",
							"path": ["/"],
							"headers": {"Host": ["www.scheme.org"]}
						}
					}
				}
			}
		}]
	}`

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	out := RunXrayProbe(ctx, cfgJSON, "http://127.0.0.1:1/generate_204")
	// Config must build and start without decode/build/init errors (will fail at dial to port 1)
	assert.NotContains(t, out.Error, "decode xray config failed")
	assert.NotContains(t, out.Error, "build xray config failed")
	assert.NotContains(t, out.Error, "init xray instance failed")
}

func TestHTTPTaskPollAndReplyShell(t *testing.T) {
	resultCh := make(chan httpTaskResultPayload, 1)
	var polledOnce bool

	mockPanel := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/server/terminal/poll":
			w.Header().Set("Content-Type", "application/json")
			if !polledOnce {
				polledOnce = true
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"code": 200,
					"data": map[string]interface{}{
						"tasks": []httpNodeTask{
							{
								ID:         "t-1",
								Action:     "shell",
								Command:    "echo ok_from_http_poll",
								TimeoutSec: 5,
							},
						},
					},
				})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"code": 200,
				"data": map[string]interface{}{"tasks": []httpNodeTask{}},
			})
		case "/v1/server/terminal/reply":
			var payload httpTaskResultPayload
			require.NoError(t, json.NewDecoder(r.Body).Decode(&payload))
			resultCh <- payload
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer mockPanel.Close()

	ctrl := NewController(mockPanel.URL, 50, "secret")
	ctrl.pollHTTPTasks()

	select {
	case res := <-resultCh:
		assert.Equal(t, "t-1", res.ID)
		assert.True(t, res.Success)
		assert.Equal(t, 0, res.ExitCode)
		assert.Equal(t, "ok_from_http_poll", res.Output)
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for HTTP task reply")
	}
}

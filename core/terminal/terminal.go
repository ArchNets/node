package terminal

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/creack/pty"
	"github.com/gorilla/websocket"
	log "github.com/sirupsen/logrus"
)

// TerminalResizeMessage describes a window dimension resize packet from client
type TerminalResizeMessage struct {
	Type string `json:"type"` // "resize"
	Cols uint16 `json:"cols"`
	Rows uint16 `json:"rows"`
}

// Controller manages remote interactive terminal sessions between backend and node
type Controller struct {
	apiHost   string
	serverID  int
	secretKey string
	stopCh    chan struct{}
	mu        sync.Mutex
	active    bool
}

// NewController creates a terminal reverse agent controller
func NewController(apiHost string, serverID int, secretKey string) *Controller {
	return &Controller{
		apiHost:   apiHost,
		serverID:  serverID,
		secretKey: secretKey,
		stopCh:    make(chan struct{}),
	}
}

// Start begins the terminal agent polling/worker loop
func (c *Controller) Start() {
	go c.listenForTerminalRequests()
}

// Close stops the terminal controller
func (c *Controller) Close() {
	close(c.stopCh)
}

func (c *Controller) listenForTerminalRequests() {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-c.stopCh:
			return
		case <-ticker.C:
			c.checkAndConnect()
		}
	}
}

func (c *Controller) checkAndConnect() {
	c.mu.Lock()
	if c.active {
		c.mu.Unlock()
		return
	}
	c.mu.Unlock()

	// Check if backend has a pending terminal connection request for this node
	u, err := url.Parse(c.apiHost)
	if err != nil {
		return
	}

	wsScheme := "ws"
	if u.Scheme == "https" {
		wsScheme = "wss"
	}

	wsURL := fmt.Sprintf("%s://%s/v1/server/terminal/connect?server_id=%d&secret_key=%s",
		wsScheme, u.Host, c.serverID, url.QueryEscape(c.secretKey))

	header := make(http.Header)
	header.Set("User-Agent", "ArchNet-Node-Terminal/1.0")

	dialer := websocket.Dialer{
		HandshakeTimeout: 5 * time.Second,
	}

	ws, resp, err := dialer.Dial(wsURL, header)
	if err != nil {
		if resp != nil && resp.Body != nil {
			resp.Body.Close()
		}
		// No pending terminal session from admin or endpoint not ready - silently ignore
		return
	}
	defer ws.Close()

	c.mu.Lock()
	c.active = true
	c.mu.Unlock()

	defer func() {
		c.mu.Lock()
		c.active = false
		c.mu.Unlock()
	}()

	log.WithField("server_id", c.serverID).Info("[Terminal] Admin terminal session connected")
	c.handleSession(ws)
	log.WithField("server_id", c.serverID).Info("[Terminal] Admin terminal session closed")
}

func (c *Controller) handleSession(ws *websocket.Conn) {
	// Pick shell
	shell := "/bin/bash"
	if _, err := os.Stat(shell); err != nil {
		shell = "/bin/sh"
	}

	cmd := exec.Command(shell, "-l")
	// Set standard root working directory so it doesn't open in /usr/local/archnets
	if homeDir, err := os.UserHomeDir(); err == nil && homeDir != "" {
		cmd.Dir = homeDir
	} else {
		cmd.Dir = "/root"
	}

	cmd.Env = append(os.Environ(),
		"TERM=xterm-256color",
		"COLORTERM=truecolor",
		"HOME=/root",
		"USER=root",
		"SHELL=/bin/bash",
		"LANG=en_US.UTF-8",
		"LC_ALL=en_US.UTF-8",
		"PROMPT_COLOR=1",
		"force_color_prompt=yes",
	)

	// Allocate PTY
	ptmx, err := pty.Start(cmd)
	if err != nil {
		log.WithField("err", err).Error("[Terminal] Failed to allocate PTY")
		_ = ws.WriteMessage(websocket.TextMessage, []byte(fmt.Sprintf("\r\nFailed to start shell: %v\r\n", err)))
		return
	}
	defer func() {
		_ = ptmx.Close()
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
	}()

	// 1. PTY stdout/stderr -> WebSocket
	stdoutDone := make(chan struct{})
	go func() {
		defer close(stdoutDone)
		buf := make([]byte, 4096)
		for {
			n, err := ptmx.Read(buf)
			if n > 0 {
				if writeErr := ws.WriteMessage(websocket.BinaryMessage, buf[:n]); writeErr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()

	// 2. WebSocket -> PTY stdin & resize control
	for {
		msgType, msg, err := ws.ReadMessage()
		if err != nil {
			break
		}

		if msgType == websocket.TextMessage {
			// Check if resize message
			var resize TerminalResizeMessage
			if err := json.Unmarshal(msg, &resize); err == nil && resize.Type == "resize" && resize.Cols > 0 && resize.Rows > 0 {
				_ = pty.Setsize(ptmx, &pty.Winsize{
					Cols: resize.Cols,
					Rows: resize.Rows,
				})
				continue
			}
		}

		// Raw input data to terminal
		if len(msg) > 0 {
			if _, err := ptmx.Write(msg); err != nil {
				break
			}
		}
	}

	// Terminate PTY and process immediately when WebSocket disconnects so stdout reader unblocks
	_ = ptmx.Close()
	if cmd.Process != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}

	select {
	case <-stdoutDone:
	case <-time.After(1 * time.Second):
	}
}

package terminal

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/creack/pty"
	"github.com/gorilla/websocket"
	log "github.com/sirupsen/logrus"

	"github.com/archnets/node/core/filesystem"
)

// FsRequest describes a file system operation forwarded from backend
type FsRequest struct {
	ID       string `json:"id"`
	Action   string `json:"action"` // list, read, write, delete
	Path     string `json:"path"`
	Content  string `json:"content,omitempty"`
	IsBase64 bool   `json:"is_base64,omitempty"`
}

// FsResponse describes a file system operation result back to backend
type FsResponse struct {
	ID       string                `json:"id"`
	Success  bool                  `json:"success"`
	Error    string                `json:"error,omitempty"`
	Path     string                `json:"path,omitempty"`
	Files    []filesystem.FileItem `json:"files,omitempty"`
	Content  string                `json:"content,omitempty"`
	IsBinary bool                  `json:"is_binary,omitempty"`
}

// TerminalResizeMessage describes a window dimension resize packet from client
type TerminalResizeMessage struct {
	Type string `json:"type"` // "resize"
	Cols uint16 `json:"cols"`
	Rows uint16 `json:"rows"`
}

// Controller manages remote interactive terminal sessions between backend and node
type Controller struct {
	apiHost             string
	serverID            int
	secretKey           string
	httpClient          *http.Client
	stopCh              chan struct{}
	mu                  sync.Mutex
	active              bool
	serviceProbeHandler func(ctx context.Context, serviceKey string) (int, error)
}

// SetServiceProbeHandler registers a callback executed when backend dispatches a service_probe task over HTTPS.
func (c *Controller) SetServiceProbeHandler(fn func(ctx context.Context, serviceKey string) (int, error)) {
	c.mu.Lock()
	c.serviceProbeHandler = fn
	c.mu.Unlock()
}

// NewController creates a terminal reverse agent controller
func NewController(apiHost string, serverID int, secretKey string) *Controller {
	return &Controller{
		apiHost:    apiHost,
		serverID:   serverID,
		secretKey:  secretKey,
		httpClient: &http.Client{Timeout: 10 * time.Second},
		stopCh:     make(chan struct{}),
	}
}

// Start begins both WebSocket reverse-terminal polling and CDN-safe HTTPS task polling
func (c *Controller) Start() {
	go c.listenForTerminalRequests()
	go c.listenForHTTPTasks()
}

// Close stops the terminal controller
func (c *Controller) Close() {
	close(c.stopCh)
}

func (c *Controller) listenForTerminalRequests() {
	ticker := time.NewTicker(1500 * time.Millisecond)
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
			// Check if heartbeat ping/pong message
			if string(msg) == `{"type":"ping"}` || string(msg) == "ping" {
				_ = ws.WriteMessage(websocket.TextMessage, []byte("pong"))
				continue
			}

			// Check if remote filesystem control message
			if len(msg) > 0 && msg[0] == '{' {
				var fsReq FsRequest
				if err := json.Unmarshal(msg, &fsReq); err == nil && fsReq.Action != "" && fsReq.ID != "" {
					go c.handleFsRequest(ws, &fsReq)
					continue
				}
			}

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

func (c *Controller) handleFsRequest(ws *websocket.Conn, req *FsRequest) {
	resp := c.runFsAction(req)
	data, err := json.Marshal(resp)
	if err == nil {
		_ = ws.WriteMessage(websocket.TextMessage, data)
	}
}

func (c *Controller) runFsAction(req *FsRequest) FsResponse {
	resp := FsResponse{
		ID:      req.ID,
		Success: true,
	}

	switch req.Action {
	case "list":
		files, err := filesystem.ListDirectory(req.Path)
		if err != nil {
			resp.Success = false
			resp.Error = err.Error()
		} else {
			resp.Path = req.Path
			resp.Files = files
		}

	case "read":
		content, isBinary, err := filesystem.ReadFile(req.Path)
		if err != nil {
			resp.Success = false
			resp.Error = err.Error()
		} else {
			resp.Path = req.Path
			resp.Content = content
			resp.IsBinary = isBinary
		}

	case "write":
		err := filesystem.WriteFile(req.Path, req.Content, req.IsBase64)
		if err != nil {
			resp.Success = false
			resp.Error = err.Error()
		} else {
			resp.Path = req.Path
		}

	case "delete":
		err := filesystem.DeletePath(req.Path)
		if err != nil {
			resp.Success = false
			resp.Error = err.Error()
		}

	default:
		resp.Success = false
		resp.Error = fmt.Sprintf("unsupported action %s", req.Action)
	}

	return resp
}

type httpNodeTask struct {
	ID         string     `json:"id"`
	Action     string     `json:"action"` // "xray_probe" | "shell" | "fs"
	Command    string     `json:"command,omitempty"`
	TimeoutSec int        `json:"timeout_sec,omitempty"`
	Fs         *FsRequest `json:"fs,omitempty"`
	ConfigJSON string     `json:"config_json,omitempty"`
	TestURL    string     `json:"test_url,omitempty"`
}

type httpTaskResultPayload struct {
	ID        string      `json:"id"`
	Success   bool        `json:"success"`
	Error     string      `json:"error,omitempty"`
	Output    string      `json:"output,omitempty"`
	ExitCode  int         `json:"exit_code,omitempty"`
	Fs        *FsResponse `json:"fs,omitempty"`
	HTTPCode  int         `json:"http_code,omitempty"`
	ConnectMs int64       `json:"connect_ms,omitempty"`
	TTFBMs    int64       `json:"ttfb_ms,omitempty"`
	TotalMs   int64       `json:"total_ms,omitempty"`
}

func (c *Controller) listenForHTTPTasks() {
	ticker := time.NewTicker(1500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-c.stopCh:
			return
		case <-ticker.C:
			c.pollHTTPTasks()
		}
	}
}

func (c *Controller) pollHTTPTasks() {
	base := strings.TrimRight(c.apiHost, "/")
	pollURL := fmt.Sprintf("%s/v1/server/terminal/poll?server_id=%d&secret_key=%s",
		base, c.serverID, url.QueryEscape(c.secretKey))

	req, err := http.NewRequest(http.MethodGet, pollURL, nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", "ArchNet-Node-Terminal/1.0")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return
	}

	var env struct {
		Code int `json:"code"`
		Data struct {
			Tasks []httpNodeTask `json:"tasks"`
		} `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 2*1024*1024)).Decode(&env); err != nil {
		return
	}
	for _, t := range env.Data.Tasks {
		taskCopy := t
		go c.executeHTTPTask(taskCopy)
	}
}

func (c *Controller) executeHTTPTask(t httpNodeTask) {
	timeout := time.Duration(t.TimeoutSec) * time.Second
	if timeout <= 0 {
		timeout = 25 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	res := httpTaskResultPayload{ID: t.ID}

	switch t.Action {
	case "xray_probe":
		outcome := RunXrayProbe(ctx, t.ConfigJSON, t.TestURL)
		res.Success = outcome.Success
		res.HTTPCode = outcome.HTTPCode
		res.ConnectMs = outcome.ConnectMs
		res.TTFBMs = outcome.TTFBMs
		res.TotalMs = outcome.TotalMs
		res.Error = outcome.Error

	case "shell":
		shell := "/bin/bash"
		if _, err := os.Stat(shell); err != nil {
			shell = "/bin/sh"
		}
		cmd := exec.CommandContext(ctx, shell, "-c", t.Command)
		out, err := cmd.CombinedOutput()
		res.Output = strings.TrimSpace(string(out))
		if err != nil {
			var exitErr *exec.ExitError
			if errors.As(err, &exitErr) {
				res.ExitCode = exitErr.ExitCode()
			} else {
				res.ExitCode = 1
				res.Error = err.Error()
			}
			res.Success = false
		} else {
			res.ExitCode = 0
			res.Success = true
		}

	case "fs":
		if t.Fs == nil {
			res.Error = "missing fs payload"
		} else {
			fsRes := c.runFsAction(t.Fs)
			res.Fs = &fsRes
			res.Success = fsRes.Success
			res.Error = fsRes.Error
		}

	case "service_probe":
		c.mu.Lock()
		handler := c.serviceProbeHandler
		c.mu.Unlock()
		if handler == nil {
			res.Error = "service probe handler not registered"
		} else {
			count, pErr := handler(ctx, t.Command)
			if pErr != nil {
				res.Error = pErr.Error()
			} else {
				res.Success = true
				res.Output = fmt.Sprintf("probed=%d", count)
			}
		}

	default:
		res.Error = fmt.Sprintf("unsupported task action %q", t.Action)
	}

	c.postHTTPTaskResult(res)
}

func (c *Controller) postHTTPTaskResult(res httpTaskResultPayload) {
	base := strings.TrimRight(c.apiHost, "/")
	replyURL := fmt.Sprintf("%s/v1/server/terminal/reply?server_id=%d&secret_key=%s",
		base, c.serverID, url.QueryEscape(c.secretKey))

	body, err := json.Marshal(res)
	if err != nil {
		return
	}
	req, err := http.NewRequest(http.MethodPost, replyURL, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "ArchNet-Node-Terminal/1.0")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
}

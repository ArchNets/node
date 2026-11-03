package core

import (
	"bufio"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

// This file implements just enough of OpenVPN's management-interface protocol
// to support:
//   - deferred client authentication (--management-client-auth), so users can
//     be added/removed at runtime without restarting the openvpn process
//   - per-client bytecount reporting, for traffic accounting
//
// Reference: https://openvpn.net/community-resources/management-interface/

// ovpnEvent represents a parsed asynchronous event from the management socket.
type ovpnEvent struct {
	kind string // "CLIENT_CONNECT", "CLIENT_REAUTH", "CLIENT_DISCONNECT", "BYTECOUNT_CLI"
	cid  string
	kid  string
	env  map[string]string // populated for CLIENT_CONNECT / CLIENT_REAUTH
	in   int64             // populated for BYTECOUNT_CLI
	out  int64             // populated for BYTECOUNT_CLI
}

type ovpnMgmtClient struct {
	conn   net.Conn
	reader *bufio.Reader

	writeMu   sync.Mutex
	closeOnce sync.Once

	// pendingReplies receives lines for synchronous command responses
	// (anything not prefixed with '>').
	pendingReplies chan string

	events chan ovpnEvent
	done   chan struct{}
}

// dialOpenVPNManagement connects to an OpenVPN management interface exposed
// as a unix domain socket.
func dialOpenVPNManagement(socketPath string) (*ovpnMgmtClient, error) {
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("dial management socket: %w", err)
	}

	c := &ovpnMgmtClient{
		conn:           conn,
		reader:         bufio.NewReader(conn),
		pendingReplies: make(chan string, 16),
		events:         make(chan ovpnEvent, 256),
		done:           make(chan struct{}),
	}

	go c.readLoop()
	return c, nil
}

func (c *ovpnMgmtClient) Close() error {
	var err error
	c.closeOnce.Do(func() {
		close(c.done)
		err = c.conn.Close()
	})
	return err
}

func drainReplies(ch <-chan string) {
	for {
		select {
		case <-ch:
		default:
			return
		}
	}
}

// send writes a raw command line and returns the synchronous reply line
// (e.g. "SUCCESS: ..."). The mutex covers the full write-and-read transaction
// to prevent concurrent callers from interleaving command replies.
func (c *ovpnMgmtClient) send(cmd string) (string, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	drainReplies(c.pendingReplies)

	if _, err := c.conn.Write([]byte(cmd + "\n")); err != nil {
		return "", err
	}

	select {
	case reply := <-c.pendingReplies:
		if strings.HasPrefix(reply, "ERROR:") {
			return reply, fmt.Errorf("management command %q failed: %s", cmd, reply)
		}
		return reply, nil
	case <-time.After(10 * time.Second):
		return "", fmt.Errorf("management command %q timed out", cmd)
	case <-c.done:
		return "", fmt.Errorf("management client closed")
	}
}

// enableByteCount turns on periodic per-client bytecount push notifications.
func (c *ovpnMgmtClient) enableByteCount(intervalSeconds int) error {
	_, err := c.send(fmt.Sprintf("bytecount %d", intervalSeconds))
	return err
}

// authorizeClient accepts a pending client with no client-specific config push.
func (c *ovpnMgmtClient) authorizeClient(cid, kid string) error {
	_, err := c.send(fmt.Sprintf("client-auth-nt %s %s", cid, kid))
	return err
}

// denyClient rejects a pending client connection with a reason string.
func (c *ovpnMgmtClient) denyClient(cid, kid, reason string) error {
	_, err := c.send(fmt.Sprintf("client-deny %s %s %q", cid, kid, reason))
	return err
}

// killClient forcibly disconnects an already-connected client by CID.
func (c *ovpnMgmtClient) killClient(cid string) error {
	_, err := c.send(fmt.Sprintf("client-kill %s", cid))
	return err
}

// readLoop continuously reads lines from the socket.
func (c *ovpnMgmtClient) readLoop() {
	defer close(c.events)

	var pendingEnv map[string]string
	var pendingCID, pendingKID, pendingKind string

	for {
		line, err := c.reader.ReadString('\n')
		if err != nil {
			log.WithError(err).Debug("openvpn management: read loop ended")
			return
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			continue
		}

		if !strings.HasPrefix(line, ">") {
			// Synchronous reply to a command we sent.
			select {
			case c.pendingReplies <- line:
			default:
				log.WithField("line", line).Warn("openvpn management: dropped unclaimed reply")
			}
			continue
		}

		// Asynchronous notification. Strip leading '>'.
		body := line[1:]

		switch {
		case strings.HasPrefix(body, "CLIENT:CONNECT,"):
			fields := strings.SplitN(body, ",", 2)
			if len(fields) < 2 {
				log.WithField("line", line).Warn("openvpn management: malformed CLIENT:CONNECT, dropping")
				continue
			}
			rest := strings.SplitN(fields[1], ",", 2)
			if len(rest) < 2 {
				log.WithField("line", line).Warn("openvpn management: malformed CLIENT:CONNECT payload, dropping")
				continue
			}
			pendingCID, pendingKID = rest[0], rest[1]
			pendingEnv = make(map[string]string)
			pendingKind = "CLIENT_CONNECT"

		case strings.HasPrefix(body, "CLIENT:REAUTH,"):
			fields := strings.SplitN(body, ",", 2)
			if len(fields) < 2 {
				log.WithField("line", line).Warn("openvpn management: malformed CLIENT:REAUTH, dropping")
				continue
			}
			rest := strings.SplitN(fields[1], ",", 2)
			if len(rest) < 2 {
				log.WithField("line", line).Warn("openvpn management: malformed CLIENT:REAUTH payload, dropping")
				continue
			}
			pendingCID, pendingKID = rest[0], rest[1]
			pendingEnv = make(map[string]string)
			pendingKind = "CLIENT_REAUTH"

		case strings.HasPrefix(body, "CLIENT:ENV,"):
			kv := strings.TrimPrefix(body, "CLIENT:ENV,")
			if kv == "END" {
				if pendingEnv != nil {
					ev := ovpnEvent{kind: pendingKind, cid: pendingCID, kid: pendingKID, env: pendingEnv}
					select {
					case c.events <- ev:
					case <-c.done:
						return
					}
				}
				pendingEnv = nil
				continue
			}
			if pendingEnv != nil {
				parts := strings.SplitN(kv, "=", 2)
				if len(parts) == 2 {
					pendingEnv[parts[0]] = parts[1]
				}
			}

		case strings.HasPrefix(body, "CLIENT:ESTABLISHED,"):
			// Informational event from OpenVPN; no action needed
			continue

		case strings.HasPrefix(body, "CLIENT:DISCONNECT,"):
			fields := strings.SplitN(body, ",", 2)
			if len(fields) < 2 {
				log.WithField("line", line).Warn("openvpn management: malformed CLIENT:DISCONNECT, dropping")
				continue
			}
			cid := fields[1]
			select {
			case c.events <- ovpnEvent{kind: "CLIENT_DISCONNECT", cid: cid}:
			case <-c.done:
				return
			}

		case strings.HasPrefix(body, "BYTECOUNT_CLI:"):
			// Format: >BYTECOUNT_CLI:<CID>,<BYTES_IN>,<BYTES_OUT>
			payload := strings.TrimPrefix(body, "BYTECOUNT_CLI:")
			parts := strings.Split(payload, ",")
			if len(parts) == 3 {
				in, errIn := strconv.ParseInt(parts[1], 10, 64)
				out, errOut := strconv.ParseInt(parts[2], 10, 64)
				if errIn != nil || errOut != nil {
					log.WithField("line", line).Warn("openvpn management: malformed integer in BYTECOUNT_CLI, dropping")
					continue
				}
				ev := ovpnEvent{kind: "BYTECOUNT_CLI", cid: parts[0], in: in, out: out}
				select {
				case c.events <- ev:
				default:
					// BYTECOUNT_CLI is cumulative, so skipping an intermediate sample under load is safe
					log.WithField("cid", parts[0]).Warn("openvpn management: events buffer full, dropped BYTECOUNT_CLI sample")
				}
			} else {
				// Don't drop silently -- if a future OpenVPN version ever
				// changes this format, we want it visible instead of
				// traffic accounting quietly going dark on that server.
				log.WithField("line", line).Warn("openvpn management: malformed BYTECOUNT_CLI, dropping")
			}

		default:
			log.WithField("line", line).Debug("openvpn management: unhandled event")
		}
	}
}

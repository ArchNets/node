package transport

import (
	"bytes"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"
)

const (
	wsAuthMagic = "ARWS"
	wsGUID      = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
)

// DialWSCarrier dials Entry over HTTP/1.1 WebSocket Upgrade (or HTTPS with Chrome uTLS when useTLS is true).
// Once the 101 Switching Protocols handshake succeeds, the raw stream is returned for zero-copy splicing.
func DialWSCarrier(dialCtx CarrierDialer, useTLS bool, sni, password, wsPath string) (net.Conn, error) {
 if sni == "" {
  sni = "localhost"
 }
 path := strings.TrimSpace(wsPath)
 if path == "" || !strings.HasPrefix(path, "/") {
  path = "/ws"
 }
 key, err := DeriveRealityKey(password, "archnet-ws-auth")
 if err != nil {
  return nil, err
 }
 token, err := GenerateRealityToken(key, wsAuthMagic)
 if err != nil {
  return nil, err
 }
 authHex := hex.EncodeToString(token[:])

 var wsKeyRaw [16]byte
 _, _ = rand.Read(wsKeyRaw[:])
 wsKey := base64.StdEncoding.EncodeToString(wsKeyRaw[:])

 rawConn, err := dialCtx()
 if err != nil {
  return nil, err
 }
 TuneTCPConn(rawConn)
 _ = rawConn.SetDeadline(time.Now().Add(6 * time.Second))

 var conn net.Conn = rawConn
 if useTLS {
  trustSelfSignedCert := true
  uConn := utls.UClient(rawConn, &utls.Config{
   ServerName:         sni,
   InsecureSkipVerify: trustSelfSignedCert,
   NextProtos:         []string{"http/1.1"},
  }, utls.HelloChrome_Auto)
  if err := uConn.Handshake(); err != nil {
   _ = rawConn.Close()
   return nil, fmt.Errorf("wss utls handshake: %w", err)
  }
  conn = uConn
 }

 req := fmt.Sprintf(
  "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\nX-Requested-With: %s\r\n\r\n",
  path, sni, wsKey, authHex,
 )
	if _, err := conn.Write([]byte(req)); err != nil {
		_ = conn.Close()
		return nil, err
	}

	headerBytes, leftover, err := readHTTPHeaderBlock(conn, 4096)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("ws read upgrade response: %w", err)
	}
	headerStr := string(headerBytes)
	if !strings.HasPrefix(headerStr, "HTTP/1.1 101") {
		_ = conn.Close()
		return nil, errors.New("ws upgrade rejected by server")
	}

	_ = conn.SetDeadline(time.Time{})
	if len(leftover) > 0 {
		return NewPrefixConn(conn, leftover), nil
	}
	return conn, nil
}

// InspectWSTraffic inspects an incoming connection on Entry for an authenticated WebSocket Upgrade.
// Unauthenticated HTTP visitors receive a realistic per-tunnel Nginx decoy response.
func InspectWSTraffic(conn net.Conn, sni, password string, hasUserForwarder bool) (InspectAction, net.Conn, error) {
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	if sni == "" {
		sni = "localhost"
	}

	var peek [4]byte
	nPeek, err := io.ReadFull(conn, peek[:])
	if err != nil {
		_ = conn.Close()
		return ActionDPIProbe, nil, err
	}
	prefix4 := string(peek[:nPeek])
	isHTTP := prefix4 == "GET " || prefix4 == "POST" || prefix4 == "HEAD" || prefix4 == "OPTI" || prefix4 == "PUT "
	if !isHTTP {
		if hasUserForwarder {
			_ = conn.SetReadDeadline(time.Time{})
			return ActionUserClient, NewPrefixConn(conn, peek[:nPeek]), nil
		}
		_ = conn.Close()
		return ActionDPIProbe, nil, errors.New("non-http traffic on ws listener")
	}

	prefixed := NewPrefixConn(conn, peek[:nPeek])
	headerBytes, leftover, err := readHTTPHeaderBlock(prefixed, 4096)
	if err != nil {
		_ = conn.Close()
		return ActionDPIProbe, nil, err
	}

	reqStr := string(headerBytes)
	var wsKey, authHex string
	for _, line := range strings.Split(reqStr, "\r\n") {
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "sec-websocket-key:") {
			wsKey = strings.TrimSpace(line[len("sec-websocket-key:"):])
		} else if strings.HasPrefix(lower, "x-requested-with:") {
			authHex = strings.TrimSpace(line[len("x-requested-with:"):])
		}
	}

	if wsKey != "" && len(authHex) == 64 {
		if tokenBytes, decErr := hex.DecodeString(authHex); decErr == nil && len(tokenBytes) == 32 {
			if key, kErr := DeriveRealityKey(password, "archnet-ws-auth"); kErr == nil {
				if VerifyRealityToken(key, tokenBytes, wsAuthMagic) {
					h := sha1.Sum([]byte(wsKey + wsGUID))
					accept := base64.StdEncoding.EncodeToString(h[:])
					resp := fmt.Sprintf(
						"HTTP/1.1 101 Switching Protocols\r\nServer: nginx\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n",
						accept,
					)
					_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
					if _, wErr := conn.Write([]byte(resp)); wErr != nil {
						_ = conn.Close()
						return ActionDPIProbe, nil, wErr
					}
					_ = conn.SetDeadline(time.Time{})
					if len(leftover) > 0 {
						return ActionReverseCarrier, NewPrefixConn(conn, leftover), nil
					}
					return ActionReverseCarrier, conn, nil
				}
			}
		}
	}

	// Serve deterministic per-tunnel Nginx decoy page to unauthenticated HTTP visitors/probes
	go ServeDecoyHTTP(conn, reqStr, password)
	return ActionDPIProbe, nil, nil
}

func readHTTPHeaderBlock(r io.Reader, maxBytes int) (header []byte, leftover []byte, err error) {
	buf := make([]byte, 0, 1024)
	tmp := make([]byte, 512)
	sep := []byte("\r\n\r\n")

	for len(buf) < maxBytes {
		n, rErr := r.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
			if idx := bytes.Index(buf, sep); idx >= 0 {
				end := idx + 4
				return buf[:end], buf[end:], nil
			}
		}
		if rErr != nil {
			return nil, nil, rErr
		}
	}
	return nil, nil, errors.New("http header too large")
}

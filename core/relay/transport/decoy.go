package transport

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

type decoyNginxBuild struct {
	version  string
	page     string
	notFound string
}

var decoyNginxBuilds = []decoyNginxBuild{
	{"1.18.0 (Ubuntu)", decoyIndexClassic, decoy404Classic},
	{"1.20.1", decoyIndexClassic, decoy404Classic},
	{"1.22.1", decoyIndexClassic, decoy404Classic},
	{"1.24.0 (Ubuntu)", decoyIndexModern, decoy404Modern},
	{"1.26.3", decoyIndexModern, decoy404Modern},
}

const decoyIndexClassic = `<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
<style>
    body {
        width: 35em;
        margin: 0 auto;
        font-family: Tahoma, Verdana, Arial, sans-serif;
    }
</style>
</head>
<body>
<h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed and
working. Further configuration is required.</p>

<p>For online documentation and support please refer to
<a href="http://nginx.org/">nginx.org</a>.<br/>
Commercial support is available at
<a href="http://nginx.com/">nginx.com</a>.</p>

<p><em>Thank you for using nginx.</em></p>
</body>
</html>
`

const decoyIndexModern = `<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
<style>
html { color-scheme: light dark; }
body { width: 35em; margin: 0 auto;
font-family: Tahoma, Verdana, Arial, sans-serif; }
</style>
</head>
<body>
<h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed and
working. Further configuration is required.</p>

<p>For online documentation and support please refer to
<a href="http://nginx.org/">nginx.org</a>.<br/>
Commercial support is available at
<a href="http://nginx.com/">nginx.com</a>.</p>

<p><em>Thank you for using nginx.</em></p>
</body>
</html>
`

const decoy404Classic = "<html>\r\n<head><title>404 Not Found</title></head>\r\n" +
	"<body bgcolor=\"white\">\r\n<center><h1>404 Not Found</h1></center>\r\n" +
	"<hr><center>%s</center>\r\n</body>\r\n</html>\r\n"

const decoy404Modern = "<html>\r\n<head><title>404 Not Found</title></head>\r\n" +
	"<body>\r\n<center><h1>404 Not Found</h1></center>\r\n" +
	"<hr><center>%s</center>\r\n</body>\r\n</html>\r\n"

// ServeDecoyHTTP writes a deterministic per-tunnel nginx static server response to conn
// when an unauthenticated visitor or GFW probe sends an HTTP request to a WS/WSS carrier port.
func ServeDecoyHTTP(conn net.Conn, reqHeader string, seedToken string) {
	defer conn.Close()
	_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))

	mac := hmac.New(sha256.New, []byte("archnet-decoy-salt"))
	mac.Write([]byte(seedToken))
	h := mac.Sum(nil)
	build := decoyNginxBuilds[int(h[0])%len(decoyNginxBuilds)]

	serverHdr := "nginx"
	if h[1]&1 == 0 {
		serverHdr = "nginx/" + build.version
	}

	anchor := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	if now := time.Now().UTC(); now.Before(anchor) {
		anchor = now
	}
	days := int(binary.BigEndian.Uint16(h[2:4]))%870 + 30
	secs := int(binary.BigEndian.Uint32(h[4:8]) % 86400)
	modTime := anchor.Add(-time.Duration(days)*24*time.Hour - time.Duration(secs)*time.Second)

	firstLine := reqHeader
	if idx := strings.Index(reqHeader, "\r\n"); idx > 0 {
		firstLine = reqHeader[:idx]
	}
	parts := strings.Fields(firstLine)
	method := "GET"
	path := "/"
	if len(parts) >= 2 {
		method = parts[0]
		path = parts[1]
	}

	nowStr := time.Now().UTC().Format(http.TimeFormat)
	if (method == "GET" || method == "HEAD") && (path == "/" || path == "/index.html") {
		etag := fmt.Sprintf(`"%x-%x"`, modTime.Unix(), len(build.page))
		lastMod := modTime.UTC().Format(http.TimeFormat)
		resp := fmt.Sprintf(
			"HTTP/1.1 200 OK\r\nServer: %s\r\nDate: %s\r\nContent-Type: text/html\r\nContent-Length: %d\r\nLast-Modified: %s\r\nConnection: close\r\nETag: %s\r\nAccept-Ranges: bytes\r\n\r\n",
			serverHdr, nowStr, len(build.page), lastMod, etag,
		)
		if method == "GET" {
			resp += build.page
		}
		_, _ = conn.Write([]byte(resp))
		return
	}

	body404 := fmt.Sprintf(build.notFound, serverHdr)
	resp := fmt.Sprintf(
		"HTTP/1.1 404 Not Found\r\nServer: %s\r\nDate: %s\r\nContent-Type: text/html\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		serverHdr, nowStr, len(body404), body404,
	)
	_, _ = conn.Write([]byte(resp))
}

package transport

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	certutil "github.com/archnets/node/common/cert"
	utls "github.com/refraction-networking/utls"
)

// resolveFallbackCertPaths checks standard ArchNet (/etc/archnets/) and Let's Encrypt
// (/etc/letsencrypt/live/<sni>/) directories if certFile/keyFile were not explicitly set.
func resolveFallbackCertPaths(sni string) (string, string) {
	if sni == "" {
		return "", ""
	}
	// 1. Check /etc/archnets/{sanitized_sni}-*.crt
	pattern := filepath.Join(certutil.CertDir, certutil.SanitizeDomain(sni)+"-*.crt")
	if matches, err := filepath.Glob(pattern); err == nil {
		for _, crt := range matches {
			key := crt[:len(crt)-4] + ".key"
			if _, err1 := os.Stat(crt); err1 == nil {
				if _, err2 := os.Stat(key); err2 == nil {
					return crt, key
				}
			}
		}
	}
	// 2. Check /etc/letsencrypt/live/<sni>/fullchain.pem & privkey.pem
	leCert := filepath.Join("/etc/letsencrypt/live", sni, "fullchain.pem")
	leKey := filepath.Join("/etc/letsencrypt/live", sni, "privkey.pem")
	if _, err1 := os.Stat(leCert); err1 == nil {
		if _, err2 := os.Stat(leKey); err2 == nil {
			return leCert, leKey
		}
	}
	return "", ""
}

// BuildRelayTLSConfig builds a server *tls.Config for TLS-based relay transports.
// It supports:
// - certMode == "file": inline PEM content in certFile & keyFile (or file paths if written by EnsureNodeCertificate)
// - certMode == "path" / "http" / "dns": filesystem paths to fullchain.pem and privkey.pem
// - certMode == "self" / "none" / "": loads generated self-signed file or ephemeral in-memory ECDSA P-256 cert
func BuildRelayTLSConfig(sni, certMode, certFile, keyFile string) (*tls.Config, error) {
	mode := strings.ToLower(strings.TrimSpace(certMode))
	cf := strings.TrimSpace(certFile)
	kf := strings.TrimSpace(keyFile)

	if (cf == "" || kf == "") && mode != "none" && mode != "self" && sni != "" {
		cf, kf = resolveFallbackCertPaths(sni)
	}

	if cf != "" && kf != "" && mode != "none" {
		if strings.Contains(cf, "-----BEGIN") && strings.Contains(kf, "-----BEGIN") {
			cert, err := tls.X509KeyPair([]byte(cf), []byte(kf))
			if err != nil {
				return nil, fmt.Errorf("parse inline tls certificate/key PEM: %w", err)
			}
			return &tls.Config{
				Certificates: []tls.Certificate{cert},
				MinVersion:   tls.VersionTLS13,
			}, nil
		}
		cert, err := tls.LoadX509KeyPair(cf, kf)
		if err != nil {
			return nil, fmt.Errorf("load tls certificate/key files (%s, %s): %w", cf, kf, err)
		}
		return &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS13,
		}, nil
	}

	return GenerateSelfSignedTLSConfig(sni)
}

// GenerateSelfSignedTLSConfig generates an in-memory ECDSA P-256 TLS certificate for the given SNI.
func GenerateSelfSignedTLSConfig(sni string) (*tls.Config, error) {
	if sni == "" {
		sni = "archnet.local"
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, err
	}

	tmpl := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   sni,
			Organization: []string{sni},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{sni},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}

	cert := tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  priv,
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	}, nil
}

// buildSelfSignedReverseClientTLSConfig constructs client TLS config for self-signed carrier connections.
func buildSelfSignedReverseClientTLSConfig(sni string) *tls.Config {
	trustSelfSignedCert := true
	return &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: trustSelfSignedCert,
		MinVersion:         tls.VersionTLS13,
	}
}

// DialTLSReverseCarrier connects to EntryServerIP:CarrierPort over TLS 1.3 and authenticates with Password.
func DialTLSReverseCarrier(dialCtx CarrierDialer, sni, password string) (net.Conn, error) {
	key, err := DeriveRealityKey(password, "archnet-tls-auth")
	if err != nil {
		return nil, err
	}
	token, err := GenerateRealityToken(key, realityMagic)
	if err != nil {
		return nil, err
	}

	rawConn, err := dialCtx()
	if err != nil {
		return nil, err
	}
	TuneTCPConn(rawConn)

	uConn := utls.UClient(rawConn, &utls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true,
	}, utls.HelloChrome_Auto)
	if err := uConn.BuildHandshakeState(); err == nil && uConn.HandshakeState.Hello != nil {
		if sessionToken, sErr := DeriveRealitySessionID(password, sni); sErr == nil {
			uConn.HandshakeState.Hello.SessionId = make([]byte, 32)
			copy(uConn.HandshakeState.Hello.SessionId, sessionToken[:])
			uConn.HandshakeState.Hello.Raw = nil
		}
	}

	_ = uConn.SetDeadline(time.Now().Add(6 * time.Second))
	if err := uConn.Handshake(); err != nil {
		_ = rawConn.Close()
		return nil, fmt.Errorf("tls-reverse handshake: %w", err)
	}
	tlsConn := uConn

	if _, err := tlsConn.Write(token[:]); err != nil {
		_ = tlsConn.Close()
		return nil, fmt.Errorf("write tls-reverse auth token: %w", err)
	}

	var ack [32]byte
	if _, err := io.ReadFull(tlsConn, ack[:]); err != nil {
		_ = tlsConn.Close()
		return nil, fmt.Errorf("read tls-reverse ack: %w", err)
	}
	if !VerifyRealityToken(key, ack[:], realityAckMagic) {
		_ = tlsConn.Close()
		return nil, fmt.Errorf("invalid tls-reverse ack token")
	}

	_ = tlsConn.SetDeadline(time.Time{})
	return tlsConn, nil
}

// AcceptTLSReverseCarrier upgrades an accepted TCP connection to TLS 1.3 and verifies the peer token.
func AcceptTLSReverseCarrier(rawConn net.Conn, tlsCfg *tls.Config, sni, password string) (net.Conn, error) {
	TuneTCPConn(rawConn)
	tlsConn := tls.Server(rawConn, tlsCfg)
	_ = tlsConn.SetDeadline(time.Now().Add(6 * time.Second))
	if err := tlsConn.Handshake(); err != nil {
		_ = rawConn.Close()
		return nil, err
	}

	key, err := DeriveRealityKey(password, "archnet-tls-auth")
	if err != nil {
		_ = tlsConn.Close()
		return nil, err
	}

	var token [32]byte
	if _, err := io.ReadFull(tlsConn, token[:]); err != nil {
		_ = tlsConn.Close()
		return nil, err
	}
	if !VerifyRealityToken(key, token[:], realityMagic) {
		_ = tlsConn.Close()
		return nil, fmt.Errorf("unauthorized tls-reverse peer")
	}

	ack, err := GenerateRealityToken(key, realityAckMagic)
	if err != nil {
		_ = tlsConn.Close()
		return nil, err
	}
	if _, err := tlsConn.Write(ack[:]); err != nil {
		_ = tlsConn.Close()
		return nil, err
	}

	_ = tlsConn.SetDeadline(time.Time{})
	return tlsConn, nil
}

// ExtractSNIFromClientHello extracts the server_name extension from a raw TLS ClientHello record body.
func ExtractSNIFromClientHello(body []byte) string {
	if len(body) < 42 || body[0] != 0x01 {
		return ""
	}
	// Skip HandshakeType (1B) + HandshakeLength (3B) + LegacyVersion (2B) + Random (32B) = 38B
	curr := 38
	if curr >= len(body) {
		return ""
	}
	// SessionID length
	sidLen := int(body[curr])
	curr += 1 + sidLen
	if curr+2 > len(body) {
		return ""
	}
	// CipherSuites length
	csLen := int(binary.BigEndian.Uint16(body[curr : curr+2]))
	curr += 2 + csLen
	if curr+1 > len(body) {
		return ""
	}
	// CompressionMethods length
	cmLen := int(body[curr])
	curr += 1 + cmLen
	if curr+2 > len(body) {
		return ""
	}
	// Extensions length
	extsLen := int(binary.BigEndian.Uint16(body[curr : curr+2]))
	curr += 2
	end := curr + extsLen
	if end > len(body) {
		end = len(body)
	}

	for curr+4 <= end {
		extType := binary.BigEndian.Uint16(body[curr : curr+2])
		extLen := int(binary.BigEndian.Uint16(body[curr+2 : curr+4]))
		curr += 4
		if curr+extLen > end {
			break
		}
		if extType == 0x0000 { // server_name
			if extLen < 5 {
				break
			}
			// list_len (2B) + type (1B) + name_len (2B)
			nameLen := int(binary.BigEndian.Uint16(body[curr+3 : curr+5]))
			if curr+5+nameLen <= end {
				return strings.ToLower(string(body[curr+5 : curr+5+nameLen]))
			}
		}
		curr += extLen
	}
	return ""
}

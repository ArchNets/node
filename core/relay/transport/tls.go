package transport

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	"time"
)

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

// DialTLSReverseCarrier connects to EntryServerIP:CarrierPort over TLS 1.3 and authenticates with Password.
func DialTLSReverseCarrier(dialCtx CarrierDialer, sni, password string) (net.Conn, error) {
	key, err := DeriveRealityKey(password, sni)
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

	tlsConn := tls.Client(rawConn, &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS13,
	})

	_ = tlsConn.SetDeadline(time.Now().Add(6 * time.Second))
	if err := tlsConn.Handshake(); err != nil {
		_ = rawConn.Close()
		return nil, fmt.Errorf("tls-reverse handshake: %w", err)
	}

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

	key, err := DeriveRealityKey(password, sni)
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

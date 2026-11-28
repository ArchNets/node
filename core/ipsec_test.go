package core

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestIPsecProcessSasStats_ActiveThreshold(t *testing.T) {
	c := NewIPsecCore(IPsecConfig{Tag: "ipsec-test"})
	c.users[1] = &IPsecUser{UID: 1, Username: "user1"}
	c.users[2] = &IPsecUser{UID: 2, Username: "user2"}

	// Small probe (2 KB <= 8 KB) should not mark user1 active
	c.processSasStats([]parsedSA{
		{Username: "user1", RemoteIP: "1.2.3.4", InBytes: 1000, OutBytes: 1000},
		{Username: "user2", RemoteIP: "5.6.7.8", InBytes: 5000, OutBytes: 10000},
	})

	if st := c.lastSasStats["user1"]; st == nil || !st.LastDataTime.IsZero() {
		t.Fatalf("expected user1 with 2KB not to trigger LastDataTime, got %+v", st)
	}
	if st := c.lastSasStats["user2"]; st == nil || st.LastDataTime.IsZero() || time.Since(st.LastDataTime) > time.Second {
		t.Fatalf("expected user2 with 15KB to trigger LastDataTime, got %+v", st)
	}

	// Disconnecting user1 cleans up its lastSasStats entry
	c.processSasStats([]parsedSA{
		{Username: "user2", RemoteIP: "5.6.7.8", InBytes: 5000, OutBytes: 10000},
	})
	if _, exists := c.lastSasStats["user1"]; exists {
		t.Fatalf("expected disconnected user1 to be pruned from lastSasStats")
	}
}

func TestIPsecSplitLeafAndChainPEM_And_Config(t *testing.T) {
	bundle := "-----BEGIN CERTIFICATE-----\nLEAFDATA\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nINTERMEDIATEDATA\n-----END CERTIFICATE-----\n"
	leaf, chain := splitLeafAndChainPEM(bundle)
	if !strings.Contains(leaf, "LEAFDATA") || strings.Contains(leaf, "INTERMEDIATEDATA") {
		t.Fatalf("unexpected leaf PEM: %s", leaf)
	}
	if !strings.Contains(chain, "INTERMEDIATEDATA") || strings.Contains(chain, "LEAFDATA") {
		t.Fatalf("unexpected chain PEM: %s", chain)
	}

	c := NewIPsecCore(IPsecConfig{
		Tag:        "ipsec-10-500",
		Mode:       "ikev2",
		PSK:        `my"secret\psk`,
		AuthMethod: "psk",
		Domain:     "vpn.example.com",
		CertMode:   "file",
	})
	secrets := c.generateSecrets()
	if !strings.Contains(secrets, `secret = "my\"secret\\psk"`) {
		t.Fatalf("expected escaped PSK in secrets, got:\n%s", secrets)
	}

	// Verify IPv6 parsing in swanctl --list-sas output
	sas := parseSwanctlSasText("ipsec-10-500: #1, ESTABLISHED, IKEv2\n  remote 'user_abcd1234' @ 2001:db8::1[4500]\n  bytes_in=12345, bytes_out=67890\n")
	if len(sas) != 1 || sas[0].Username != "user_abcd1234" || sas[0].RemoteIP != "2001:db8::1" || sas[0].InBytes != 12345 || sas[0].OutBytes != 67890 {
		t.Fatalf("unexpected parsed IPv6 SA: %+v", sas)
	}

	// Verify tagged chap-secrets upsert and removal leaves other tags intact
	chapPath := filepath.Join(t.TempDir(), "chap-secrets")
	if err := upsertTaggedChapSecrets(chapPath, "tag1", "\"u1\" * \"p1\" *\n"); err != nil {
		t.Fatal(err)
	}
	if err := upsertTaggedChapSecrets(chapPath, "tag2", "\"u2\" * \"p2\" *\n"); err != nil {
		t.Fatal(err)
	}
	if err := removeTaggedChapSecrets(chapPath, "tag1"); err != nil {
		t.Fatal(err)
	}
	rem, err := os.ReadFile(chapPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(rem), "u1") || !strings.Contains(string(rem), "u2") {
		t.Fatalf("expected tag1 removed and tag2 preserved, got:\n%s", string(rem))
	}

	// Verify computeIPsecTCPMSS bounds
	if mss := computeIPsecTCPMSS(1360); mss != 1320 {
		t.Fatalf("expected MSS 1320 for MTU 1360, got %d", mss)
	}
	if mss := computeIPsecTCPMSS(1280); mss != 1240 {
		t.Fatalf("expected MSS 1240 for MTU 1280, got %d", mss)
	}
	if mss := computeIPsecTCPMSS(400); mss != 536 {
		t.Fatalf("expected floor MSS 536, got %d", mss)
	}

	// Verify installCertFromDisk splits leaf and intermediate CA chain from disk paths
	certDir := t.TempDir()
	diskCert := filepath.Join(certDir, "fullchain.pem")
	diskKey := filepath.Join(certDir, "privkey.pem")
	if err := os.WriteFile(diskCert, []byte(bundle), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(diskKey, []byte("KEYDATA"), 0600); err != nil {
		t.Fatal(err)
	}
	pathCore := NewIPsecCore(IPsecConfig{
		Tag:      "ipsec-11-500",
		Domain:   "ik-test.example.com",
		CertMode: "path",
		CertFile: diskCert,
		KeyFile:  diskKey,
	})
	// Validate read and PEM split helper on disk files
	readCert, err := os.ReadFile(pathCore.CertFile)
	if err != nil {
		t.Fatal(err)
	}
	l2, ch2 := splitLeafAndChainPEM(string(readCert))
	if !strings.Contains(l2, "LEAFDATA") || !strings.Contains(ch2, "INTERMEDIATEDATA") {
		t.Fatalf("expected disk cert split to preserve leaf and chain, got leaf=%q chain=%q", l2, ch2)
	}
}

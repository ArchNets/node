package core

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/archnets/node/api/panel"
)

func TestIPsecProcessSasStats_ActiveThreshold(t *testing.T) {
	c := NewIPsecCore(IPsecConfig{Tag: "ipsec-test"})
	u1 := &IPsecUser{UID: 1, Username: "user1"}
	u2 := &IPsecUser{UID: 2, Username: "user2"}
	c.users[1] = u1
	c.users[2] = u2
	c.usersByName["user1"] = u1
	c.usersByName["user2"] = u2

	// Small probe (2 KB <= 8 KB) should not mark user1 active
	c.processSasStats([]parsedSA{
		{SAKey: "ipsec-test:#1", SAId: "1", Username: "user1", RemoteIP: "1.2.3.4", InBytes: 1000, OutBytes: 1000},
		{SAKey: "ipsec-test:#2", SAId: "2", Username: "user2", RemoteIP: "5.6.7.8", InBytes: 5000, OutBytes: 10000},
		// Multi-device session for user2 (#3) must track independently without resetting #2's counters
		{SAKey: "ipsec-test:#3", SAId: "3", Username: "user2", RemoteIP: "9.9.9.9", InBytes: 2000, OutBytes: 3000},
	})

	if st := c.lastSasStats["ipsec-test:#1"]; st == nil || !st.LastDataTime.IsZero() {
		t.Fatalf("expected user1 with 2KB not to trigger LastDataTime, got %+v", st)
	}
	if st := c.lastSasStats["ipsec-test:#2"]; st == nil || st.LastDataTime.IsZero() || time.Since(st.LastDataTime) > time.Second {
		t.Fatalf("expected user2 #2 with 15KB to trigger LastDataTime, got %+v", st)
	}
	if tr := c.traffic[2]; tr == nil || tr.Upload != 7000 || tr.Download != 13000 {
		t.Fatalf("expected multi-device user2 traffic sum Upload=7000 Download=13000, got %+v", tr)
	}
	if online := c.GetOnlineUsers(); len(online) != 1 || online[0].UID != 2 {
		t.Fatalf("expected exactly UID 2 online, got %+v", online)
	}

	// Disconnecting user1 cleans up its lastSasStats entry
	c.processSasStats([]parsedSA{
		{SAKey: "ipsec-test:#2", SAId: "2", Username: "user2", RemoteIP: "5.6.7.8", InBytes: 5000, OutBytes: 10000},
	})
	if _, exists := c.lastSasStats["ipsec-test:#1"]; exists {
		t.Fatalf("expected disconnected user1 to be pruned from lastSasStats")
	}

	// Verify excess DeviceLimit selection keeps newest SAs and returns oldest ones for termination
	excess := findExcessDeviceSAs([]parsedSA{
		{SAKey: "ipsec-test:#10", SAId: "10", Username: "user2"},
		{SAKey: "ipsec-test:#4", SAId: "4", Username: "user2"},
		{SAKey: "ipsec-test:#7", SAId: "7", Username: "user2"},
	}, map[string]int{"user2": 1})
	if len(excess) != 2 || excess[0].SAId != "4" || excess[1].SAId != "7" {
		t.Fatalf("expected oldest SAs #4 and #7 to be evicted for DeviceLimit=1, got %+v", excess)
	}

	// Verify UpdateUserLimits updates DeviceLimit without dropping the user
	c.UpdateUserLimits([]panel.UserInfo{{Id: 2, DeviceLimit: 3}})
	if c.users[2].DeviceLimit != 3 {
		t.Fatalf("expected DeviceLimit=3 after UpdateUserLimits, got %d", c.users[2].DeviceLimit)
	}

	if got := compactCmdOutput([]byte("line1\n  line2\tline3\n")); got != "line1 line2 line3" {
		t.Fatalf("unexpected compactCmdOutput: %q", got)
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

	eapCore := NewIPsecCore(IPsecConfig{
		Tag:        "ipsec-10-500",
		Mode:       "ikev2",
		PSK:        "should-not-emit-for-eap",
		AuthMethod: "eap-mschapv2",
	})
	if eapSecrets := eapCore.generateSecrets(); strings.Contains(eapSecrets, "ike-ipsec-10-500") {
		t.Fatalf("expected EAP-MSCHAPv2 IKEv2 not to emit id=%%any ike PSK secret, got:\n%s", eapSecrets)
	}
	ikeConf := c.generateIKEv2SwanctlConf()
	if !strings.Contains(ikeConf, "mobike = no") {
		t.Fatalf("expected mobike = no in IKEv2 swanctl conf, got:\n%s", ikeConf)
	}
	if !strings.Contains(ikeConf, "aes256gcm16-sha256-ecp256") {
		t.Fatalf("expected iOS proposal aes256gcm16-sha256-ecp256 in IKEv2 swanctl conf, got:\n%s", ikeConf)
	}

	l2tpCore := NewIPsecCore(IPsecConfig{Tag: "ipsec-10-1701", Mode: "l2tp", L2TPSharedSecret: "l2tpsecret"})
	l2tpConf := l2tpCore.generateL2TPSwanctlConf()
	if !strings.Contains(l2tpConf, "local_ts = dynamic[udp/1701]") || !strings.Contains(l2tpConf, "remote_ts = dynamic[udp]") {
		t.Fatalf("expected L2TP transport selectors local=dynamic[udp/1701] remote=dynamic[udp], got:\n%s", l2tpConf)
	}
	pppOpts := l2tpCore.generatePPPOptions()
	if strings.Contains(pppOpts, "\nlock\n") || strings.HasPrefix(pppOpts, "lock\n") {
		t.Fatalf("expected PPP options not to contain unsupported 'lock' option, got:\n%s", pppOpts)
	}

	// Verify IPv6 parsing in swanctl --list-sas output + real strongSwan 5.9.x EAP + in/out bytes format
	sas := parseSwanctlSasText("ipsec-10-500: #1, ESTABLISHED, IKEv2\n  remote 'user_abcd1234' @ 2001:db8::1[4500]\n  bytes_in=12345, bytes_out=67890\n")
	if len(sas) != 1 || sas[0].Username != "user_abcd1234" || sas[0].RemoteIP != "2001:db8::1" || sas[0].InBytes != 12345 || sas[0].OutBytes != 67890 || sas[0].SAId != "1" {
		t.Fatalf("unexpected parsed IPv6 SA: %+v", sas)
	}

	realSwanctl := `ipsec-8-500: #4, ESTABLISHED, IKEv2, 8ed3c3e1f9eeef92_i 3626de952182b5a5_r*
  local  'asentra.archlio.com' @ 127.0.0.1[4500]
  remote '192.168.0.176' @ 127.0.0.1[55181] EAP: 'user_405aa312' [10.10.0.1]
  AES_GCM_16-256/PRF_HMAC_SHA2_256/MODP_2048
  ipsec-8-500-child: #2, reqid 1, INSTALLED, TUNNEL-in-UDP, ESP:AES_GCM_16-256
    in  c117deee,  19952 bytes,   308 packets,     0s ago
    out 093d975b,  44120 bytes,   112 packets,     0s ago
`
	realSAs := parseSwanctlSasText(realSwanctl)
	if len(realSAs) != 1 || realSAs[0].Username != "user_405aa312" || realSAs[0].SAId != "4" || realSAs[0].InBytes != 19952 || realSAs[0].OutBytes != 44120 {
		t.Fatalf("unexpected parsed real swanctl SA: %+v", realSAs)
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

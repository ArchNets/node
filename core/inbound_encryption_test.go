package core

import (
	"encoding/json"
	"testing"

	"github.com/archnets/node/api/panel"
	coreConf "github.com/xtls/xray-core/infra/conf"
)

func TestBuildVLessEncryption(t *testing.T) {
	// A valid 32-byte X25519 base64url private key
	validPrivKey := "x18DaqB1ta3iK1M8nuEoKRuM2_dPM0xvKvwUNiCcOOs"

	tests := []struct {
		name               string
		encryption         string
		mode               string
		ticket             string
		privKey            string
		expectedDecryption string
		wantErr            bool
	}{
		{
			name:               "None encryption",
			encryption:         "none",
			expectedDecryption: "none",
			wantErr:            false,
		},
		{
			name:               "mlkem768x25519plus with empty ticket and mode (defaults applied)",
			encryption:         "mlkem768x25519plus",
			mode:               "",
			ticket:             "",
			privKey:            validPrivKey,
			expectedDecryption: "mlkem768x25519plus.native.600s." + validPrivKey,
			wantErr:            false,
		},
		{
			name:               "mlkem768x25519plus with 300s ticket (trailing s stripped)",
			encryption:         "mlkem768x25519plus",
			mode:               "native",
			ticket:             "300s",
			privKey:            validPrivKey,
			expectedDecryption: "mlkem768x25519plus.native.300s." + validPrivKey,
			wantErr:            false,
		},
		{
			name:       "mlkem768x25519plus with missing private key",
			encryption: "mlkem768x25519plus",
			mode:       "native",
			ticket:     "600",
			privKey:    "",
			wantErr:    true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			nodeInfo := &panel.NodeInfo{
				Protocol: &panel.Protocol{
					Transport:            "tcp",
					Encryption:           tc.encryption,
					EncryptionMode:       tc.mode,
					EncryptionTicket:     tc.ticket,
					EncryptionPrivateKey: tc.privKey,
				},
			}
			inbound := &coreConf.InboundDetourConfig{}
			err := buildVLess(nodeInfo, inbound)
			if (err != nil) != tc.wantErr {
				t.Fatalf("buildVLess() error = %v, wantErr %v", err, tc.wantErr)
			}
			if tc.wantErr {
				return
			}

			var vlessConfig coreConf.VLessInboundConfig
			if err := json.Unmarshal([]byte(*inbound.Settings), &vlessConfig); err != nil {
				t.Fatalf("failed to unmarshal vless inbound settings: %v", err)
			}
			if vlessConfig.Decryption != tc.expectedDecryption {
				t.Errorf("decryption = %s, want %s", vlessConfig.Decryption, tc.expectedDecryption)
			}

			// Validate with Xray's inbound parser to ensure Xray builds it without error
			_, buildErr := vlessConfig.Build()
			if buildErr != nil {
				t.Errorf("Xray VLessInboundConfig.Build() failed on %s: %v", vlessConfig.Decryption, buildErr)
			}
		})
	}
}

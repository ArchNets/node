package node

import (
	"fmt"
	"testing"
)

// getBackendProtocolName simulates the backend's GetProtocolName(type, count)
// which returns type for count==0 and "<type>-<count+1>" for count>0.
func getBackendProtocolName(protoType string, count int) string {
	if count == 0 {
		return protoType
	}
	return fmt.Sprintf("%s-%d", protoType, count+1)
}

func TestProtocolNamesAgree(t *testing.T) {
	protoType := "vless"
	for count := 0; count <= 4; count++ {
		// Map backend's count (0-indexed) to protocolIndex (1-indexed)
		protocolIndex := count + 1

		backendName := getBackendProtocolName(protoType, count)
		nodeName := getIndexedProtocolName(protoType, protocolIndex)

		if backendName != nodeName {
			t.Errorf("Mismatch for count %d (protocolIndex %d): backend=%q, node=%q",
				count, protocolIndex, backendName, nodeName)
		}
	}
}

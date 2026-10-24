package protocol

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
)

const (
	RouteProtoTCP   byte = 0x01
	RouteProtoUDP   byte = 0x02
	RouteProtoProbe byte = 0xFF

	MaxUDPFrameSize = 65505

	activationMinPadding = 64
	activationMaxPadding = 512
)

// WriteRoutingHeader writes a TLS 1.3 ApplicationData (0x17 0x03 0x03) record containing
// the 3-byte routing header [Proto, TargetPort_Hi, TargetPort_Lo] followed by variable-length
// CSPRNG padding (64..512 bytes), matching WaterWall ReverseServer's variable-size activation.
func WriteRoutingHeader(w io.Writer, proto byte, targetPort uint16) error {
	var randLenBuf [2]byte
	_, _ = rand.Read(randLenBuf[:])
	padSpan := activationMaxPadding - activationMinPadding + 1
	padLen := activationMinPadding + (int(binary.BigEndian.Uint16(randLenBuf[:])) % padSpan)

	recLen := 3 + padLen
	frame := make([]byte, 5+recLen)
	frame[0] = 0x17
	frame[1] = 0x03
	frame[2] = 0x03
	binary.BigEndian.PutUint16(frame[3:5], uint16(recLen))
	frame[5] = proto
	binary.BigEndian.PutUint16(frame[6:8], targetPort)
	_, _ = rand.Read(frame[8:])

	_, err := w.Write(frame)
	return err
}

// ReadRoutingHeader reads either a TLS 1.3 framed variable-size activation record
// or a legacy 3-byte routing header from stream.
func ReadRoutingHeader(r io.Reader) (proto byte, targetPort uint16, err error) {
	var first3 [3]byte
	if _, err := io.ReadFull(r, first3[:]); err != nil {
		return 0, 0, err
	}

	// TLS 1.3 ApplicationData framed variable-length activation record
	if first3[0] == 0x17 && first3[1] == 0x03 && first3[2] == 0x03 {
		var lenBuf [2]byte
		if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
			return 0, 0, err
		}
		recLen := int(binary.BigEndian.Uint16(lenBuf[:]))
		if recLen < 3 || recLen > 4096 {
			return 0, 0, fmt.Errorf("invalid routing activation record length: %d", recLen)
		}
		body := make([]byte, recLen)
		if _, err := io.ReadFull(r, body); err != nil {
			return 0, 0, err
		}
		return body[0], binary.BigEndian.Uint16(body[1:3]), nil
	}

	// Legacy raw 3-byte header fallback
	return first3[0], binary.BigEndian.Uint16(first3[1:3]), nil
}

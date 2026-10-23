package protocol

import (
	"encoding/binary"
	"io"
)

const (
	RouteProtoTCP   byte = 0x01
	RouteProtoUDP   byte = 0x02
	RouteProtoProbe byte = 0xFF

	MaxUDPFrameSize = 65505
)

// WriteRoutingHeader writes the 3-byte routing header [Proto, TargetPort_Hi, TargetPort_Lo] to stream.
func WriteRoutingHeader(w io.Writer, proto byte, targetPort uint16) error {
	var hdr [3]byte
	hdr[0] = proto
	binary.BigEndian.PutUint16(hdr[1:3], targetPort)
	_, err := w.Write(hdr[:])
	return err
}

// ReadRoutingHeader reads the 3-byte routing header from stream.
func ReadRoutingHeader(r io.Reader) (proto byte, targetPort uint16, err error) {
	var hdr [3]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, 0, err
	}
	return hdr[0], binary.BigEndian.Uint16(hdr[1:3]), nil
}

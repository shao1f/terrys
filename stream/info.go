package stream

import (
	"encoding/binary"
	"net"
)

var Info []byte = []byte{0x10, 0x09, 0x35, 0x41}

func NextNonce(b []byte) {
	i := binary.LittleEndian.Uint64(b[:8])
	i += 1
	binary.LittleEndian.PutUint64(b[2:8], i)
}

func WaitReadErr(conn net.Conn) {
	var b [2048]byte
	for {
		if _, err := conn.Read(b[:]); err != nil {
			return
		}
	}
}

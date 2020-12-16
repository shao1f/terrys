package stream

import (
	"crypto/cipher"
	"net"
)

type StreamServer struct {
	Client   net.Conn
	cn       []byte
	ca       cipher.AEAD
	sn       []byte
	sa       cipher.AEAD
	RB       []byte
	WB       []byte
	Timeout  int
	Network  string
	ConnFunc func(net.Conn) net.Conn
}

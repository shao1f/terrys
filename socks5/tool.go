package socks5

import (
	"encoding/binary"
	"net"
	"strconv"
)

func ToAddress(a byte, addr []byte, port []byte) string {
	var h, p string
	if a == AddressIPV4 || a == AddressIPV6 {
		h = net.IP(addr).String()
	}
	if a == AddressDomain {
		if len(addr) < 1 {
			return ""
		}
		if len(addr) < int(addr[0])+1 {
			return ""
		}
		h = string(addr[1:])
	}
	p = strconv.Itoa(int(binary.BigEndian.Uint16(port)))
	return net.JoinHostPort(h, p)
}

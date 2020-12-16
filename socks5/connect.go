package socks5

import (
	"bytes"
	"encoding/binary"
	"io"
	"log"
	"net"
	"strconv"
)

func (req *Request) Connect(w io.Writer) (*net.TCPConn, error) {
	log.Println("connect to:", req.Address())
	tmp, err := net.Dial("tcp", req.Address())
	if err != nil {
		var p *Response
		if req.AddressType == AddressIPV4 || req.AddressType == AddressDomain {
			p = NewResponse(RspCmdNotSupposed, AddressIPV4, []byte{0x00, 0x00, 0x00, 0x00}, []byte{0x00, 0x00})
		} else if req.AddressType == AddressIPV6 {
			p = NewResponse(RspCmdNotSupposed, AddressIPV6, []byte(net.IPv6zero), []byte{0x00, 0x00})
		}
		if _, err := p.WriteTo(w); err != nil {
			return nil, err
		}
		return nil, err
	}
	rc := tmp.(*net.TCPConn)
	typ, addr, port, err := ParseAddress(rc.LocalAddr().String())
	if err != nil {
		var p *Response
		if req.AddressType == AddressIPV4 || req.AddressType == AddressDomain {
			p = NewResponse(RspCmdNotSupposed, AddressIPV4, []byte{0x00, 0x00, 0x00, 0x00}, []byte{0x00, 0x00})
		} else if req.AddressType == AddressIPV6 {
			p = NewResponse(RspCmdNotSupposed, AddressIPV6, []byte(net.IPv6zero), []byte{0x00, 0x00})
		}
		if _, err := p.WriteTo(w); err != nil {
			return nil, err
		}
		return nil, err
	}
	rsp := NewResponse(RspSuccess, typ, addr, port)
	if _, err := rsp.WriteTo(w); err != nil {
		return nil, err
	}
	return rc, nil
}

func (req *Request) Address() string {
	var s string
	if req.AddressType == AddressDomain {
		s = bytes.NewBuffer(req.DstAddr[1:]).String()
	} else {
		s = net.IP(req.DstAddr).String()
	}
	p := strconv.Itoa(int(binary.BigEndian.Uint16(req.DstPort)))
	return net.JoinHostPort(s, p)
}

func ParseAddress(address string) (a byte, addr []byte, port []byte, err error) {
	var h, p string
	h, p, err = net.SplitHostPort(address)
	if err != nil {
		return
	}
	ip := net.ParseIP(h)
	if ip4 := ip.To4(); ip4 != nil {
		a = AddressIPV4
		addr = []byte(ip4)
	} else if ip6 := ip.To16(); ip6 != nil {
		a = AddressIPV6
		addr = []byte(ip6)
	} else {
		a = AddressDomain
		addr = []byte{byte(len(h))}
		addr = append(addr, []byte(h)...)
	}
	i, _ := strconv.Atoi(p)
	port = make([]byte, 2)
	binary.BigEndian.PutUint16(port, uint16(i))
	return
}

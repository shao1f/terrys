package socks5

import (
	"io"
	"log"
)

func NewNegotiationRequest(methods []byte) *NegotiationReq {
	return &NegotiationReq{
		Version:      Socks5Ver,
		MethodsCount: byte(len(methods)),
		Methods:      methods,
	}
}

func (nr *NegotiationReq) WriteTo(w io.Writer) (int64, error) {
	var n int
	i, err := w.Write([]byte{nr.Version, nr.MethodsCount})
	n = n + i
	if err != nil {
		log.Println("negotiation write to err:", err)
		return int64(n), err
	}
	i, err = w.Write(nr.Methods)
	n = n + i
	if err != nil {
		log.Println("negotiation write methods err:", err)
		return int64(n), err
	}
	log.Println("")
	return int64(n), nil
}

func NewNegotiationRspFrom(r io.Reader) (*NegotiationRsp, error) {
	bb := make([]byte, 2)
	if _, err := io.ReadFull(r, bb); err != nil {
		log.Println("new negotiation rsp from err:", err)
		return nil, err
	}
	if bb[0] != Socks5Ver {
		log.Println("new negotiation resp err socks5 ver")
		return nil, ErrVersion
	}
	log.Printf("Get negotiation from | ver:%v | method:%v\n", bb[0], bb[1])
	return &NegotiationRsp{
		Version: bb[0],
		Method:  bb[1],
	}, nil
}

func NewUserPassNegotiationReq(userName, passWd []byte) *UserPasswdNegotiationReq {
	return &UserPasswdNegotiationReq{
		Version:     Socks5Ver,
		UserNameLen: byte(len(userName)),
		UserName:    userName,
		PasswdLen:   byte(len(passWd)),
		Passwd:      passWd,
	}
}

func (upr *UserPasswdNegotiationReq) WriteTo(w io.Writer) (int64, error) {
	var n int
	i, err := w.Write([]byte{upr.Version, upr.UserNameLen})
	n += i
	if err != nil {
		log.Println("user passwd negotiation req write to err:", err)
		return int64(n), err
	}
	i, err = w.Write(upr.UserName)
	n += i
	if err != nil {
		log.Println("user passwd negotiation req write username err:", err)
		return int64(n), err
	}
	i, err = w.Write(append([]byte{upr.PasswdLen}, upr.Passwd...))
	n += i
	if err != nil {
		log.Println("user passwd negotiation req write passwd err:", err)
		return int64(n), err
	}
	log.Printf("user passwd negotiation req write ver=%v,usernameLen=%v,userName=%v,passwdLen=%v,passwd=%v\n",
		upr.Version, upr.UserNameLen, upr.UserName, upr.PasswdLen, upr.Passwd)
	return int64(n), nil
}

func NewUserPassNegotiationRspFrom(r io.Reader) (*UserPasswdNegotiationRsp, error) {
	bb := make([]byte, 2)
	if _, err := io.ReadFull(r, bb); err != nil {
		log.Println("new user pass negotiation rsp from err", err)
		return nil, err
	}
	log.Printf("new user pass negotiation rsp ver:%v,status:%v\n", bb[0], bb[1])
	return &UserPasswdNegotiationRsp{
		Version: bb[0],
		Status:  bb[1],
	}, nil
}

func NewRequest(cmd, addresstyp byte, dstAddr, dstPort []byte) *Request {
	if addresstyp == AddressDomain {
		dstAddr = append([]byte{byte(len(dstAddr))}, dstAddr...)
	}
	return &Request{
		Version:     Socks5Ver,
		Cmd:         cmd,
		Rsv:         0x00,
		AddressType: addresstyp,
		DstAddr:     dstAddr,
		DstPort:     dstPort,
	}
}

func (req *Request) WriteTo(w io.Writer) (int64, error) {
	var n int
	i, err := w.Write([]byte{req.Version, req.Cmd, req.Rsv, req.AddressType})
	n += i
	if err != nil {
		log.Println("request write step one err:", err)
		return int64(n), err
	}
	i, err = w.Write(req.DstAddr)
	n += i
	if err != nil {
		log.Println("request write addr err:", err)
		return int64(n), err
	}
	i, err = w.Write(req.DstPort)
	n += i
	if err != nil {
		log.Println("request write port err:", err)
		return int64(n), err
	}
	log.Printf("response write to,ver=%v,cmd=%v,rsv=%v,addressTyp=%v,addr=%v,port=%v", req.Version, req.Cmd, req.Rsv, req.AddressType, req.DstAddr, req.DstPort)
	return int64(n), nil
}

func NewResponseFrom(r io.Reader) (*Response, error) {
	bb := make([]byte, 4)
	if _, err := io.ReadFull(r, bb); err != nil {
		log.Println("new response from err:", err)
		return nil, err
	}
	if bb[0] != Socks5Ver {
		log.Println("new response,err socks5 ver")
		return nil, ErrVersion
	}
	var addr []byte
	switch bb[3] {
	case AddressIPV4:
		// 四个字节的地址
		addr = make([]byte, 4)
		if _, err := io.ReadFull(r, addr); err != nil {
			log.Println("address ipv4 err:", err)
			return nil, err
		}
	case AddressDomain:
		dal := make([]byte, 1)
		if _, err := io.ReadFull(r, dal); err != nil {
			log.Println("address domain read len err:", err)
			return nil, err
		}
		if dal[0] == 0 {
			log.Println("address domain len is 0")
			return nil, ErrBadRequest
		}
		domain := make([]byte, int(dal[0]))
		if _, err := io.ReadFull(r, domain); err != nil {
			log.Println("address domain read doamin err:", err)
			return nil, err
		}
		addr = append(dal, domain...)
	case AddressIPV6:
		log.Println("not supposed ipv6")
		return nil, ErrBadRequest
	default:
		log.Println("not supposed address")
		return nil, ErrBadRequest
	}
	port := make([]byte, 2)
	if _, err := io.ReadFull(r, port); err != nil {
		log.Println("new request read port err", err)
		return nil, err
	}
	log.Printf("Get response from conn,version=%v,cmd=%v,rsv=%v,addressType=%v,bndAddr=%v,bndPort=%v\n", bb[0], bb[1], bb[2], bb[3], addr, port)
	return &Response{
		Version:     bb[0],
		Rsp:         bb[1],
		Rsv:         bb[2],
		AddressType: bb[3],
		BndAddr:     addr,
		BndPort:     port,
	}, nil
}

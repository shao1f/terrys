package socks5

import (
	"errors"
	"io"
	"log"
)

var (
	ErrVersion           = errors.New("socks version error")
	ErrUserPasswdVersion = errors.New("socks user pass ver err")
	ErrBadRequest        = errors.New("bad request")
)

func NewNegotiationRequestFrom(r io.Reader) (*NegotiationReq, error) {
	bb := make([]byte, 2)
	if _, err := io.ReadFull(r, bb); err != nil {
		log.Printf("[ERROR]new negotiation request err,err=%v\n", err)
		return nil, err
	}
	if bb[0] != Socks5Ver {
		return nil, ErrVersion
	}
	if bb[1] == 0 {
		return nil, ErrBadRequest
	}
	ms := make([]byte, int(bb[1]))
	if _, err := io.ReadFull(r, ms); err != nil {
		log.Printf("[ERROR]read methods error,err=%v\n", err)
		return nil, err
	}
	return &NegotiationReq{
		Version:      bb[0],
		MethodsCount: bb[1],
		Methods:      ms,
	}, nil
}

func NewNegotiationRsp(method byte) *NegotiationRsp {
	return &NegotiationRsp{
		Version: Socks5Ver,
		Method:  method,
	}
}

func (nr *NegotiationRsp) WriteTo(w io.Writer) (int64, error) {
	var n int
	i, err := w.Write([]byte{nr.Version, nr.Method})
	n += i
	if err != nil {
		log.Println("err negotiation rsp write to", err)
		return int64(n), err
	}
	return int64(n), nil
}

func NewUserPasswdNegotiationReqFrom(r io.Reader) (*UserPasswdNegotiationReq, error) {
	bb := make([]byte, 2)
	if _, err := io.ReadFull(r, bb); err != nil {
		log.Println("new user passwd req err:", err)
		return nil, err
	}
	if bb[0] != UserPassVer {
		return nil, ErrUserPasswdVersion
	}
	if bb[1] == 0 {
		return nil, ErrBadRequest
	}
	ub := make([]byte, int(bb[1])+1) // 为什么+1呢，因为用户名后面紧跟的一个字节就是pass的length。因此可以一起读出来
	if _, err := io.ReadFull(r, ub); err != nil {
		log.Println(err)
		return nil, err
	}
	if ub[int(bb[1])] == 0 {
		return nil, ErrBadRequest
	}
	pb := make([]byte, int(ub[int(bb[1])]))
	if _, err := io.ReadFull(r, pb); err != nil {
		log.Println("err new user pass from", err)
		return nil, err
	}
	return &UserPasswdNegotiationReq{
		Version:     bb[0],
		UserNameLen: bb[1],
		UserName:    ub[:int(bb[1])],
		PasswdLen:   ub[int(bb[1])],
		Passwd:      pb,
	}, nil
}

func NewUserPassNegotiationRsp(status byte) *UserPasswdNegotiationRsp {
	return &UserPasswdNegotiationRsp{
		Version: UserPassVer,
		Status:  status,
	}
}

func (upn *UserPasswdNegotiationRsp) WriteTo(w io.Writer) (int64, error) {
	var n int
	i, err := w.Write([]byte{upn.Version, upn.Version})
	n = n + i
	if err != nil {
		log.Println("err user pass write to", err)
		return int64(n), err
	}
	return int64(n), nil
}

func NewRequestFrom(r io.Reader) (*Request, error) {
	bb := make([]byte, 4)
	if n, err := io.ReadFull(r, bb); err != nil {
		log.Println("err new request from", err, n)
	}
	if bb[0] != Socks5Ver {
		log.Println("new request,err socks5 ver")
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
	log.Printf("Get request from conn,version=%v,cmd=%v,rsv=%v,addressType=%v,dstAddr=%v,dstPort=%v\n", bb[0], bb[1], bb[2], bb[3], addr, port)
	return &Request{
		Version:     bb[0],
		Cmd:         bb[1],
		Rsv:         bb[2],
		AddressType: bb[3],
		DstAddr:     addr,
		DstPort:     port,
	}, nil
}

func NewResponse(rsp, addressTyp byte, bndAddr, bndPort []byte) *Response {
	if addressTyp == AddressDomain {
		bndAddr = append([]byte{byte(len(bndAddr))}, bndAddr...)
	}
	return &Response{
		Version:     Socks5Ver,
		Rsp:         rsp,
		Rsv:         0x00,
		AddressType: addressTyp,
		BndAddr:     bndAddr,
		BndPort:     bndPort,
	}
}

func (rsp *Response) WriteTo(w io.Writer) (int64, error) {
	var n int
	i, err := w.Write([]byte{rsp.Version, rsp.Rsp, rsp.Rsv, rsp.AddressType})
	n = n + i
	if err != nil {
		log.Println("response write step one err:", err)
		return int64(n), err
	}
	i, err = w.Write(rsp.BndAddr)
	n = n + i
	if err != nil {
		log.Println("response write addr err:", err)
		return int64(n), err
	}
	i, err = w.Write(rsp.BndPort)
	n = n + i
	if err != nil {
		log.Println("response write port err:", err)
		return int64(n), err
	}
	log.Printf("response write to,ver=%v,rsp=%v,rsv=%v,addressTyp=%v,addr=%v,port=%v", rsp.Version, rsp.Rsp, rsp.Rsv, rsp.AddressType, rsp.BndAddr, rsp.BndPort)
	return int64(n), nil
}

package socks5

import (
	"io"
	"log"
	"net"
	"time"
)

type Socks5Server struct {
	UserName     string
	PassWord     string
	Method       byte
	SupposedCmds []byte
	Taddr        *net.TCPAddr
	TListener    *net.TCPListener
	TCPTimeout   int
	Handler      Handler
}

func NewSocks5Server(userName, passWord, addr string, tcpTimeout int) (*Socks5Server, error) {
	tAddr, err := net.ResolveTCPAddr("tcp4", addr)
	if err != nil {
		log.Printf("[ERROR]new socks5,resolve tcp addr failed,err=%v\n", err)
		return nil, err
	}
	me := MethodsNone
	if userName != "" && passWord != "" {
		me = MethodsUserPass
	}
	return &Socks5Server{
		UserName:     userName,
		PassWord:     passWord,
		Method:       me,
		SupposedCmds: []byte{CmdConnect},
		Taddr:        tAddr,
		TCPTimeout:   tcpTimeout,
	}, nil
}

func (s *Socks5Server) Negotiation(rw io.ReadWriter) error {
	rq, err := NewNegotiationRequestFrom(rw)
	if err != nil {
		return err
	}
	var got bool
	var m byte
	for _, m = range rq.Methods {
		if m == s.Method {
			got = true
			break
		}
	}
	if !got {
		rsp := NewNegotiationRsp(MethodsNotSupposed)
		if _, err := rsp.WriteTo(rw); err != nil {
			return err
		}
	}
	rsp := NewNegotiationRsp(MethodsUserPass)
	if _, err := rsp.WriteTo(rw); err != nil {
		return err
	}
	if s.Method == MethodsUserPass {
		upReq, err := NewUserPasswdNegotiationReqFrom(rw)
		if err != nil {
			return err
		}
		if string(upReq.UserName) != s.UserName || string(upReq.Passwd) != s.PassWord {
			upRsp := NewUserPassNegotiationRsp(UserPassStatusFailed)
			if _, err := upRsp.WriteTo(rw); err != nil {
				return err
			}
		}
		upRsp := NewUserPassNegotiationRsp(UserPassStatusSucc)
		if _, err := upRsp.WriteTo(rw); err != nil {
			return err
		}
	}
	return nil
}

func (s *Socks5Server) GetRequest(rw io.ReadWriter) (*Request, error) {
	req, err := NewRequestFrom(rw)
	if err != nil {
		return nil, err
	}
	var supposed bool
	for _, v := range s.SupposedCmds {
		if req.Cmd == v {
			supposed = true
			break
		}
	}
	if !supposed {
		var p *Response
		if req.AddressType == AddressIPV4 || req.AddressType == AddressDomain {
			p = NewResponse(RspCmdNotSupposed, AddressIPV4, []byte{0x00, 0x00, 0x00, 0x00}, []byte{0x00, 0x00})
		} else if req.AddressType == AddressIPV6 {
			p = NewResponse(RspCmdNotSupposed, AddressIPV6, []byte(net.IPv6zero), []byte{0x00, 0x00})
		}
		if _, err := p.WriteTo(rw); err != nil {
			return nil, err
		}
	}
	return req, nil
}

func (s *Socks5Server) ListenAndServer(h Handler) error {
	ln, err := net.ListenTCP("tcp", s.Taddr)
	if err != nil {
		log.Printf("[ERROR]listen tcp err,err=%v\n", err)
		return err
	}
	s.TListener = ln
	defer s.TListener.Close()
	for {
		cn, err := s.TListener.AcceptTCP()
		if err != nil {
			return err
		}
		go func(c *net.TCPConn) {
			defer c.Close()
			if s.TCPTimeout != 0 {
				if err := c.SetDeadline(time.Now().Add(time.Duration(s.TCPTimeout) * time.Second)); err != nil {
					log.Println(err)
					return
				}
			}
			// 握手
			if err := s.Negotiation(c); err != nil {
				return
			}
			req, err := s.GetRequest(c)
			if err != nil {
				return
			}
			if err := s.Handler.TCPHandler(s, c, req); err != nil {
				log.Println("socks5 server run tcp handler err", err)
				return
			}
			// 获取请求
			// 转发
		}(cn)
	}

}

type Handler interface {
	TCPHandler(*Socks5Server, *net.TCPConn, *Request) error
}

type DefaultHandler struct{}

func (dh *DefaultHandler) TCPHandler(s *Socks5Server, tcpConn *net.TCPConn, req *Request) error {
	if req.Cmd == CmdConnect {
		rc, err := req.Connect(tcpConn)
		if err != nil {
			log.Println("tcp handler req connect err", err)
			return err
		}
		defer rc.Close()
		Socks5Forward(tcpConn, rc)
	}
	return nil
}

func Socks5Forward(client, target *net.TCPConn) {
	forward := func(src, dest *net.TCPConn) {
		io.Copy(src, dest)
	}
	go forward(client, target)
	go forward(target, client)
}

package server

import (
	"log"
	"net"
	"time"

	"github.com/terrys/socks5"
	"github.com/terrys/stream"
)

type Server struct {
	Password   []byte
	TCPAddr    *net.TCPAddr
	TCPListen  *net.TCPListener
	TCPTimeout int
}

// NewServer.
func NewServer(addr, password string, tcpTimeout int) (*Server, error) {
	taddr, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return nil, err
	}

	s := &Server{
		Password:   []byte(password),
		TCPAddr:    taddr,
		TCPTimeout: tcpTimeout,
	}
	return s, nil
}

// Run server.
func (s *Server) ListenAndServe() error {
	return s.RunTCPServer()
}

// RunTCPServer starts tcp server.
func (s *Server) RunTCPServer() error {
	var err error
	s.TCPListen, err = net.ListenTCP("tcp", s.TCPAddr)
	if err != nil {
		return err
	}
	defer s.TCPListen.Close()
	for {
		c, err := s.TCPListen.AcceptTCP()
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
			if err := s.TCPHandle(c); err != nil {
				log.Println(err)
			}
		}(c)
	}
}

func (s *Server) TCPHandle(c *net.TCPConn) error {
	ss, dst, err := stream.NewStreamServer(s.Password, c, s.TCPTimeout)
	if err != nil {
		return err
	}
	defer ss.Clean()
	address := socks5.ToAddress(dst[0], dst[1:len(dst)-2], dst[len(dst)-2:])
	log.Println("dial tcp", address)
	rc, err := net.Dial("tcp", address)
	if err != nil {
		return err
	}
	defer rc.Close()
	if s.TCPTimeout != 0 {
		if err := rc.SetDeadline(time.Now().Add(time.Duration(s.TCPTimeout) * time.Second)); err != nil {
			return err
		}
	}
	if err := ss.Exchange(rc); err != nil {
		return nil
	}
	return nil
}

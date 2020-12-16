package client

import (
	"errors"
	"fmt"
	"log"
	"net"

	"github.com/terrys/socks5"
)

type Client struct {
	Server        *socks5.Socks5Server
	ServerAddress string
	Password      []byte
	TCPTimeout    int
}

func NewClient(addr, server, password string, tcpTimeout, udpTimeout int) (*Client, error) {
	s5, err := socks5.NewSocks5Server("", "", addr, 0)
	if err != nil {
		return nil, err
	}
	x := &Client{
		ServerAddress: server,
		Server:        s5,
		Password:      []byte(password),
		TCPTimeout:    tcpTimeout,
	}
	return x, nil
}

func (x *Client) ListenAndServer() error {
	return x.Server.ListenAndServer(x)
}

// TCPHandle handles tcp request.
func (x *Client) TCPHandler(s *socks5.Socks5Server, c *net.TCPConn, r *socks5.Request) error {
	if r.Cmd == socks5.CmdConnect {
		log.Println("dial tcp", r.Address())

		rc, err := net.Dial("tcp", x.ServerAddress)
		if err != nil {
			return err
		}
		defer rc.Close()
		a, addr, port, err := socks5.ParseAddress(rc.LocalAddr().String())
		fmt.Printf("a=%v,addr=%v,port=%v,err=%v", a, addr, port, err)

	}
	return errors.New("not supposed methods")
}

package stream

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"io"
	"log"
	"net"
	"time"

	"github.com/terrys/pool"
	"golang.org/x/crypto/hkdf"
)

type StreamClient struct {
	Server        net.Conn
	cn            []byte      // 客户端 salt
	ca            cipher.AEAD // 客户端aes的密钥
	sn            []byte      // 服务端 salt
	sa            cipher.AEAD // 服务端aes的密钥
	RB            []byte      // 读缓冲区
	WB            []byte      // 写缓冲区
	Timeout       int
	Network       string
	RemoteAddress net.Addr
}

func NewStreamClient(network string, passwd, addr []byte, server net.Conn, timeout int) (*StreamClient, error) {
	if timeout != 0 {
		if err := server.SetDeadline(time.Now().Add(time.Duration(timeout) * time.Second)); err != nil {
			return nil, err
		}
	}
	c := &StreamClient{
		Server:  server,
		Timeout: timeout,
		Network: network,
	}
	c.cn = pool.BP10.Get().([]byte)
	if _, err := io.ReadFull(rand.Reader, c.cn); err != nil {
		pool.BP10.Put(c.cn)
		log.Println("c read rand err:", err)
		return nil, err
	}
	ck := pool.BP32.Get().([]byte)
	if _, err := io.ReadFull(hkdf.New(sha256.New, passwd, c.cn, Info), ck); err != nil {
		pool.BP10.Put(c.cn)
		pool.BP32.Put(ck)
		log.Println("c hkdf new err:", err)
		return nil, err
	}
	if _, err := c.Server.Write(c.cn); err != nil {
		pool.BP10.Put(c.cn)
		pool.BP32.Put(ck)
		log.Println("c write salt to s err:", err)
		return nil, err
	}
	cb, err := aes.NewCipher(ck)
	if err != nil {
		pool.BP10.Put(c.cn)
		pool.BP32.Put(ck)
		log.Println("c new cipher err:", err)
		return nil, err
	}
	pool.BP32.Put(ck)
	c.ca, err = cipher.NewGCM(cb)
	if err != nil {
		pool.BP10.Put(c.cn)
		log.Println("c new gcm err:", err)
		return nil, err
	}
	c.WB = pool.BP2048.Get().([]byte)
	return c, nil
}

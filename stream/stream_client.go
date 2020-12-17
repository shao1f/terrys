package stream

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"log"
	"net"
	"strings"
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
	c.cn = pool.BP12.Get().([]byte)
	if _, err := io.ReadFull(rand.Reader, c.cn); err != nil {
		pool.BP12.Put(c.cn)
		log.Println("c read rand err:", err)
		return nil, err
	}
	ck := pool.BP32.Get().([]byte)
	if _, err := io.ReadFull(hkdf.New(sha256.New, passwd, c.cn, Info), ck); err != nil {
		pool.BP12.Put(c.cn)
		pool.BP32.Put(ck)
		log.Println("c hkdf new err:", err)
		return nil, err
	}
	if _, err := c.Server.Write(c.cn); err != nil {
		pool.BP12.Put(c.cn)
		pool.BP32.Put(ck)
		log.Println("c write salt to s err:", err)
		return nil, err
	}
	cb, err := aes.NewCipher(ck)
	if err != nil {
		pool.BP12.Put(c.cn)
		pool.BP32.Put(ck)
		log.Println("c new cipher err:", err)
		return nil, err
	}
	pool.BP32.Put(ck)
	c.ca, err = cipher.NewGCM(cb)
	if err != nil {
		pool.BP12.Put(c.cn)
		log.Println("c new gcm err:", err)
		return nil, err
	}
	c.WB = pool.BP2048.Get().([]byte)
	i := time.Now().Unix()
	if strings.HasPrefix(network, "tcp") && i%2 != 0 {
		i += 1
	}
	if strings.HasPrefix(network, "udp") && i%2 != 1 {
		i += 1
	}
	binary.BigEndian.PutUint32(c.WB[2+16:2+16+4], uint32(i))
	copy(c.WB[2+16+4:2+16+4+len(addr)], addr)
	if err := c.WriteL(4 + len(addr)); err != nil {
		pool.BP12.Put(c.cn)
		pool.BP2048.Put(c.WB)
		log.Println("c writeL err:", err)
		return nil, err
	}

	c.sn = pool.BP12.Get().([]byte)
	if _, err := io.ReadFull(c.Server, c.sn); err != nil {
		pool.BP12.Put(c.sn)
		pool.BP12.Put(c.cn)
		pool.BP12.Put(c.WB)
		log.Println("c read sn from server err:", err)
		return nil, err
	}
	sk := pool.BP32.Get().([]byte)
	if _, err := io.ReadFull(hkdf.New(sha256.New, passwd, c.sn, Info), sk); err != nil {
		pool.BP12.Put(c.sn)
		pool.BP32.Put(sk)
		pool.BP12.Put(c.cn)
		pool.BP2048.Put(c.WB)
		log.Println("c read sk err:", err)
		return nil, err
	}
	sb, err := aes.NewCipher(sk)
	if err != nil {
		pool.BP12.Put(c.sn)
		pool.BP32.Put(sk)
		pool.BP12.Put(c.cn)
		pool.BP2048.Put(c.WB)
		log.Println("c new sb err:", err)
		return nil, err
	}
	pool.BP32.Put(sk)
	c.sa, err = cipher.NewGCM(sb)
	if err != nil {
		pool.BP12.Put(c.sn)
		pool.BP12.Put(c.cn)
		pool.BP2048.Put(c.WB)
		log.Println("c new gcm err:", err)
		return nil, err
	}

	c.RB = pool.BP2048.Get().([]byte)
	return streamClientInit(c)
}

var streamClientInit func(*StreamClient) (*StreamClient, error) = func(c *StreamClient) (*StreamClient, error) {
	if c.Timeout != 0 {
		if err := c.Server.SetDeadline(time.Now().Add(time.Duration(c.Timeout) * time.Second)); err != nil {
			return nil, err
		}
	}
	return c, nil
}

func (c *StreamClient) WriteL(l int) error {
	binary.BigEndian.PutUint16(c.WB[:2], uint16(l))
	c.ca.Seal(c.WB[:0], c.cn, c.WB[:2], nil)
	NextNonce(c.cn)
	c.ca.Seal(c.WB[:2+16], c.cn, c.WB[2+16:2+16+l], nil)
	if _, err := c.Server.Write(c.WB); err != nil {
		return err
	}
	NextNonce(c.cn)
	return nil
}

func (c *StreamClient) ReadL() (int, error) {
	if _, err := io.ReadFull(c.Server, c.RB[:2+16]); err != nil {
		log.Println("readL length from server error:", err)
		return 0, err
	}
	if _, err := c.ca.Open(c.RB[:0], c.sn, c.RB[:2+16], nil); err != nil {
		log.Println("readL ca open length error:", err)
		return 0, err
	}
	l := int(binary.BigEndian.Uint16(c.RB[:2]))
	if _, err := io.ReadFull(c.Server, c.RB[2+16:2+16+l+16]); err != nil {
		log.Println("readL content from server err:", err)
		return 0, err
	}
	NextNonce(c.sn)
	if _, err := c.ca.Open(c.RB[:2+16], c.cn, c.RB[2+16:2+16+l+16], nil); err != nil {
		log.Println("read L ca open content error:", err)
		return 0, err
	}
	NextNonce(c.sn)
	return l, nil
}

func (c *StreamClient) Exchange(local net.Conn) error {
	go func() {
		if c.Timeout != 0 {
			if err := c.Server.SetDeadline(time.Now().Add(time.Duration(c.Timeout) * time.Second)); err != nil {
				log.Println("c exchange set deadline err:", err)
				return
			}
			l, err := c.ReadL()
			if err != nil {
				return
			}
			if _, err := local.Write(c.RB[2+16 : 2+16+l]); err != nil {
				log.Println("c erite to local err", err)
				return
			}
		}
	}()
	for {
		if c.Timeout != 0 {
			if err := local.SetDeadline(time.Now().Add(time.Duration(c.Timeout) * time.Second)); err != nil {
				log.Println("c set local deadline err:", err)
				return err
			}
		}
		l, err := local.Read(c.WB[2+16 : len(c.WB)-16])
		if err != nil {
			log.Println("c local read err:", err)
			return err
		}
		if err := c.WriteL(l); err != nil {
			log.Println("c writeL to server err:", err)
			return err
		}
	}
}

func (c *StreamClient) Clean() {
	pool.BP12.Put(c.cn)
	pool.BP12.Put(c.sn)
	pool.BP2048.Put(c.WB)
	pool.BP2048.Put(c.RB)
}

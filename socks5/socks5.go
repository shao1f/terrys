package socks5

// socks5 protoc define

const (
	// Socks5Ver socks5版本
	Socks5Ver byte = 0x05

	// MethodsNone 不需要认证
	MethodsNone byte = 0x00
	// MethodsGSSAPI GSSAPI认证
	MethodsGSSAPI byte = 0x01
	// MethodsUserPass 用户名密码校验方式
	MethodsUserPass byte = 0x02
	// 0x03-0x07 IANA保留
	// 0x80 私有方法保留

	// MethodsNotSupposed 不支持的方法
	MethodsNotSupposed byte = 0xFF

	// UserPassVer 用户名密码认证version
	UserPassVer byte = 0x01

	// UserPassStatusSucc 0x00为认证成功
	UserPassStatusSucc byte = 0x00
	// UserPassStatusFailed 大于0x00为认证失败
	UserPassStatusFailed byte = 0x01

	// CmdConnect 连接上游服务器命令
	CmdConnect byte = 0x01
	// CmdBind 绑定
	CmdBind byte = 0x02
	// CmdUDP udp
	CmdUDP byte = 0x03

	AddressIPV4   byte = 0x01
	AddressDomain byte = 0x03
	AddressIPV6   byte = 0x04

	/*
		RESPONSE 响应命令
			0x00 代理服务器连接目标服务器成功
			0x01 代理服务器故障
			0x02 代理服务器规则集不允许连接
			0x03 网络无法访问
			0x04 目标服务器无法访问（主机名无效）
			0x05 连接目标服务器被拒绝
			0x06 TTL已过期
			0x07 不支持的命令
			0x08 不支持的目标服务器地址类型
			0x09 - 0xFF 未分配
	*/
	RspSuccess               byte = 0x00
	RspServerErr             byte = 0x01
	RspRuleForbidden         byte = 0x02
	RspNetWorkError          byte = 0x03
	RspRemoteError           byte = 0x04
	RspRemoteRefused         byte = 0x05
	RspTTLExpired            byte = 0x06
	RspCmdNotSupposed        byte = 0x07
	RspRemoteAddrNotSupposed byte = 0x08
	// 0x09 - 0xFF 未分配
)

type NegotiationReq struct {
	Version      byte
	MethodsCount byte
	Methods      []byte // 1-255 bytes
}

type NegotiationRsp struct {
	Version byte
	Method  byte
}

type UserPasswdNegotiationReq struct {
	Version     byte
	UserNameLen byte
	UserName    []byte // 1-255 bytes
	PasswdLen   byte
	Passwd      []byte // 1-255 bytes
}

type UserPasswdNegotiationRsp struct {
	Version byte
	Status  byte
}

type Request struct {
	Version     byte
	Cmd         byte
	Rsv         byte // 0x00
	AddressType byte
	DstAddr     []byte // 1-255 bytes
	DstPort     []byte // 2 bytes
}

type Response struct {
	Version     byte
	Rsp         byte
	Rsv         byte // 0x00
	AddressType byte
	BndAddr     []byte // 1-255 bytes
	BndPort     []byte // 2 bytes
}

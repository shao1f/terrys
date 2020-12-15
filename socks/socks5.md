1 客户端发出请求
客户端连接服务器之后将直接发出该数据包给代理服务器

| VERSION      |    METHODS_COUNT | METHODS...  |
| :-------- | --------:| :--: |
| 1字节  | 1字节 |  1～255字节，长度由METHODS_COUNT决定   |
| 0x05     |   0x03 |  0x00 0x01 0x02  |

VERSION SOCKS协议版本，目前固定0x05
METHODS_COUNT 客户端支持的认证方法数量
METHODS... 客户端支持的认证方法，每个方法占用1个字节
METHOD定义

0x00 不需要认证（常用）
0x01 GSSAPI认证
0x02 账号密码认证（常用）
0x03 - 0x7F IANA分配
0x80 - 0xFE 私有方法保留
0xFF 无支持的认证方法
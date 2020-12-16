# 1 客户端发出请求
客户端连接服务器之后将直接发出该数据包给代理服务器

| VERSION      |    METHODS_COUNT | METHODS...  |
| :--------: | :--------:| :--: |
| 1字节  | 1字节 |  1～255字节，长度由METHODS_COUNT决定   |
| 0x05     |   0x03 |  0x00 0x01 0x02  |

VERSION SOCKS协议版本，目前固定0x05<br>
METHODS_COUNT 客户端支持的认证方法数量<br>
METHODS... 客户端支持的认证方法，每个方法占用1个字节<br>
METHOD定义<br>
>>    0x00 不需要认证（常用）<br>
    0x01 GSSAPI认证<br>
    0x02 账号密码认证（常用）<br>
    0x03 - 0x7F IANA分配<br>
    0x80 - 0xFE 私有方法保留<br>
    0xFF 无支持的认证方法<br>


# 2 服务端返回选择的认证方法
接收完客户端支持的认证方法列表后，代理服务器从中选择一个受支持的方法返回给客户端
## 2.1 无需认证
| VERSION      |  METHOD  |
| :-------- | --------:|
| 1字节  | 1字节 |
| 0x05     |   0x00 |

VERSION SOCKS协议版本，目前固定0x05<br>
METHOD 本次连接所用的认证方法，上例中为无需认证<br>

## 2.2 账号密码认证
| VERSION      |  METHOD  |
| :-------- | --------:|
| 1字节  | 1字节 |
| 0x05     |   0x02 |

## 2.3 客户端发送账号密码
服务端返回的认证方法为0x02(账号密码认证)时，客户端会发送账号密码数据给代理服务器
| VERSION      |    USERNAME_LENGTH | USERNAME  | PASSWORD_LENGTH | PASSWORD |
| :--------: | :--------:| :--: | :--: | :--: |
| 1字节  | 1字节 |  1～255字节  | 1字节 | 1~255字节 |
| 0x05     |   0x03 |  0x0a  | 0x01 | 0x0a |

VERSION 认证子协商版本（与SOCKS协议版本的0x05无关系）<br>
USERNAME_LENGTH 用户名长度<br>
USERNAME 用户名字节数组，长度为USERNAME_LENGTH<br>
PASSWORD_LENGTH 密码长度<br>
PASSWORD 密码字节数组，长度为PASSWORD_LENGTH<br>

## 2.4 服务端响应账号密码认证结果
收到客户端发来的账号密码后，代理服务器加以校验，并返回校验结果
| VERSION | STATUS |
| :--: | :--: |
| 1字节 | 1字节 |

VERSION 认证子协商版本，与客户端VERSION字段一致<br>
STATUS 认证结果<br>
>>    0x00 认证成功<br>
    大于0x00 认证失败<br>
    
# 4 命令过程
认证成功后，客户端会发送连接命令给代理服务器，代理服务器会连接目标服务器，并返回连接结果<br>
## 4.1 客户端请求
| VERSION | COMMAND | RSV | ADDRESS_TYPE | DST.ADDR | DST.PORT |
|:--:|:--:|:--:|:--:|:--:|:--:|
| 1字节 | 1字节 | 1字节 | 1字节 | 1字节 | 1字节 |

VERSION SOCKS协议版本，固定0x05<br>
COMMAND 命令<br>
>>    0x01 CONNECT 连接上游服务器<br>
    0x02 BIND 绑定，客户端会接收来自代理服务器的链接，著名的FTP被动模式<br>
    0x03 UDP ASSOCIATE UDP中继<br>
RSV 保留字段<br>
DDRESS_TYPE 目标服务器地址类型<br>
>>    0x01 IP V4地址<br>
    0x03 域名地址(没有打错，就是没有0x02)，域名地址的第1个字节为域名长度，剩下字节为域名名称字节数组<br>
    0x04 IP V6地址<br>
DST.ADDR 目标服务器地址<br>
DST.PORT 目标服务器端口<br>
## 4.2 代理服务器响应
| VERSION | RESPONSE | RSV | ADDRESS_TYPE | BND.ADDR | BND.PORT |
|:--:|:--:|:--:|:--:|:--:|:--:|
| 1字节 | 1字节 | 1字节 | 1字节 | 1字节 | 1字节 |

VERSION SOCKS协议版本，固定0x05<br>
RESPONSE 响应命令<br>
>>    0x00 代理服务器连接目标服务器成功<br>
    0x01 代理服务器故障<br>
    0x02 代理服务器规则集不允许连接<br>
    0x03 网络无法访问<br>
    0x04 目标服务器无法访问（主机名无效）<br>
    0x05 连接目标服务器被拒绝<br>
    0x06 TTL已过期<br>
    0x07 不支持的命令<br>
    0x08 不支持的目标服务器地址类型<br>
    0x09 - 0xFF 未分配<br>
RSV 保留字段<br>
BND.ADDR 代理服务器连接目标服务器成功后的代理服务器IP<br>
BND.PORT 代理服务器连接目标服务器成功后的代理服务器端口<br>
# 5通信过程
　经过认证与命令过程后，客户端与代理服务器进入正常通信，客户端发送需要请求到目标服务器的数据给代理服务器，代理服务器转发这些数据，并把目标服务器的响应转发给客户端，起到一个“透明代理”的功能。

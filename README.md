# diydnsserver
一个使用dns协议（只支持UDP），查询微步情报的工具，运行在域名的ns解析服务器。由于使用txt缓存记录，当数据过大时可能出现超时的情况。
## 1.背景
安服仔啥都要干，最近就被派去驻场；去当一个监控仔，然后甲方爸爸让看监控，查IP，然后手动封。
监控的机器不通外网，最后经过测试只有DNS协议出网。 查询IP只能用自己电脑一个一个IP的查，然后根据查询结果还要在不出网的电脑上去手动封。
感觉查询太太太太太麻烦，于是想到用DNS协议进行查询。
封禁规则是查看是否为境外外IP，在看是否为中国大陆IP，再看是否为动态IP，网关，基站IP.....
## 2.使用
在设置好域名的ns解析记录后，在域名的ns解析服务器运行脚本，指定解析的域名为*.ip.xxx.xxx，

例如：你的域名是example.com，你的某台服务器是1.1.1.1;

> 设置要解析的域名则是*.ip.example.com。
> 在域名的DNS的A记录设置上设置ns.example.com->1.1.1.1。
> ip.example.com的NS解析设置为ip.example.com->ns.example.com。
> 
> **一定记得开防火墙**

然后就在源码中设置一下微步的查询key
```
get_ipststus(key="",ip="1.1.1.1")
```
在服务器上启动脚本，
```
python3 dnstxt.py
```
就可以随意在某台机器上查询ip，例如查询114.114.114.114
```
nslookup -type=txt 114.114.114.114.ip.example.com
```
就可以收到结果了，nslookup自动将十六进制的数据转换成这种情况。
```
Non-authoritative answer:
114.114.114.114.ip.example.com	text = "\230\177\159\232\139\143\231\156\129IDC\230\156\141\229\138\161\229\153\168"
```
将text中的内容的十进制数据转换成十六禁止
例如此处。
```
\230-> \xe6
```
逐个转换，得到
```python
\xe6\xb1\x9f\xe8\x8b\x8f\xe7\x99\xbd\xe5\x90\x8d\xe5\x8d\x95
```
在python3中转成bytes类型，然后使用utf-8解码即可得到结果
```python
江苏白名单
```

## 3.存在的问题
a. ~~解码复杂（可以在源码中修改，修改为unicode的模式，但是一个中文占6个字节，比较费字节~~

windows中文情况下直接使用gbk编码（2个字节一个中文字），可直接解析中文

b. 只使用txt类型进行解析

c. 因为网络问题延迟原因导致客户端超时中断

d. 由于递归查询一次会出现好几次查询，故使用txt进行存储，当数据量过大时，时间会大幅度增加
## 请勿用户非法用途，作者不承担任何责任
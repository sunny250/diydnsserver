# -*- coding: utf-8 -*-
import socket
import requests

# 查询微步情报
def get_ipststus(key="",ip="1.1.1.1"):
    url="https://api.threatbook.cn/v3/scene/ip_reputation?apikey={}&resource={}&lang=zh".format(key,ip)
    res_data=requests.get(url).json()
    country=res_data['data'][ip]['basic']['location']['country']
    province=res_data['data'][ip]['basic']['location']['province']
    judgments=res_data['data'][ip]['judgments']
    severity=res_data['data'][ip]['severity']
    malicious=res_data['data'][ip]['is_malicious']
    print("-"*30)
    print("[+] threadboot_data: ",res_data)
    print("-" * 30)
    if country!="中国" :
        ipdata=country
    elif "中国" in province:
        ipdata=province

    elif province=="":
        ipdata = country
        if "白名单" in judgments:
            ipdata += "白名单"
        elif "移动基站" in judgments:
            ipdata += "移动基站"
        elif "动态IP" in judgments:
            ipdata += "动态IP"
        elif "网关" in judgments:
            ipdata += "网关"
        elif "骨干网" in judgments:
            ipdata+="骨干网"
        elif "教育" in judgments:
            ipdata += "教育"
        elif "CDN服务器" in judgments:
            ipdata +='CDN服务器'
        elif "DNS服务器" in judgments:
            ipdata+="DNS服务器"
        elif "BT服务器" in judgments:
            ipdata+="BT服务器"
        elif "广告" in judgments:
            ipdata+="广告"
        elif "IDC服务器" in judgments:
            ipdata += "IDC服务器"
        else:
            ipdata += "".join(judgments)
    else:
        ipdata = province
        if "白名单" in judgments:
            ipdata += "白名单"
        elif "移动基站" in judgments:
            ipdata += "移动基站"
        elif "动态IP" in judgments:
            ipdata += "动态IP"
        elif "网关" in judgments:
            ipdata += "网关"
        elif "骨干网" in judgments:
            ipdata += "骨干网"
        elif "教育" in judgments:
            ipdata += "教育"
        elif "CDN服务器" in judgments:
            ipdata += 'CDN服务器'
        elif "DNS服务器" in judgments:
            ipdata += "DNS服务器"
        elif "BT服务器" in judgments:
            ipdata += "BT服务器"
        elif "广告" in judgments:
            ipdata += "广告"
        elif "IDC服务器" in judgments:
            ipdata += "IDC服务器"
        else:
            ipdata += "".join(judgments)
    print("-" * 30)
    print("ipdata: ",ipdata)
    print("-" * 30)
    with open("ipstat.txt", "a+") as file:
        file.write(ip+","+ipdata+"\n")
    return ipdata

# 设置返回包
def set_res(req_data):
    charset="gbk"
    response_data=bytes()
    # Set Header
    response_data+=req_data["Header"]['ID']+b"\x85\x80"+b"\x00\x01"+b"\x00\x01"+bytes(4)
    # Set Queries
    response_data+=from_domaim_get_bytes(req_data["Question"]['QNAME'])+b'\x00'+req_data["Question"]["QTYPE"]+req_data["Question"]["QCLASS"]
    #set Answer:QNAME
    response_data+=bytes.fromhex("c00c")
    # set Answer:QTYPE, QCLASS
    response_data +=req_data["Question"]["QTYPE"]+req_data["Question"]["QCLASS"]
    #set Answer:TTl
    response_data +=bytes.fromhex("00001b7e")
    #set Answer:data,txtlength,txtdata
    ip=req_data["Question"]['QNAME'].split(".ip.")[0]
    if req_data["Question"]["QTYPE"] != b'\x00\x10':
        return response_data + bytes.fromhex("00047f000001")
    # 如果ip格式不正确 直接返回空信息
    if len(ip.split("."))!=4:
        print("-" * 30)
        print(" [-] IP地址长度不够")
        print("-" * 30)
        return response_data+bytes.fromhex("000100")# 返回空数据
    for x in ip.split("."):
        if int(x) >255:
            print("-" * 30)
            print(" [-] IP地址格式错误")
            print("-" * 30)
            return response_data + bytes.fromhex("000100") # 返回空数据
    ipdata=''
    with open("ipstat.txt", "r") as file:
        ipstats=file.readlines()
        # print("-" * 30)
        # print(ipstats)
        # print("-" * 30)
        for ipstat in ipstats:
            if ip in ipstat:
                # print(ipstat)
                ipdata=ipstat.split(",")[1].replace("\n","")
    if len(ipdata) :
        pass
    else:
        ipdata=get_ipststus(ip=ip)

    lens=len(ipdata.encode(charset))
    if lens <16:
        txtlens="0"+hex(lens)[2:]
    else:
        txtlens=hex(lens)[2:]
    datalens=lens+1
    if datalens <16:
        datalens="0"+hex(datalens)[2:]
    else:
        datalens=hex(datalens)[2:]

    response_data += bytes.fromhex("00"+datalens+txtlens)+ipdata.encode(charset)
    return response_data

# 解析请求报文
def paser_req(request_data):
    req_data = dict()
    # 读取Header
    Header = dict()
    Header['ID'] = request_data[:2]  # 2 bytes
    Header['QR'] = request_data[2] >> 7  # 1 bit
    Header['Opcode'] = (request_data[2] ^ 0b01111000) >> 3  # 4 bits
    Header['AA'] = (request_data[2] ^ 0b00000100) >> 2  # 1 bit
    Header['TC'] = (request_data[2] ^ 0b00000010) >> 1  # 1 bit
    Header['RD'] = (request_data[2] ^ 0b00000001)  # 1 bit
    Header['RA'] = request_data[3] >> 7  # 1 bit
    Header['Z'] = (request_data[3] ^ 0b01110000) >> 4  # 3 bits
    Header['RCODE'] = (request_data[3] ^ 0b00001111)  # 4 bits
    Header['QDCOUNT'] = request_data[4:6]  # 2 bytes
    Header['ANCOUNT'] = request_data[6:8]  # 2 bytes
    Header['NSCOUNT'] = request_data[8:10]  # 2 bytes
    Header['ARCOUNT'] = request_data[10:12]  # 2 bytes
    req_data['Header']=Header
    # 读取Question
    Question = dict()

    offset = 12

    Question['QNAME'], offset = get_domain(offset, request_data)  # n bytes
    Question['QTYPE'] = request_data[offset+1:offset + 3]  # 2 bytes
    Question['QCLASS'] = request_data[offset + 3:offset + 5]  # 2 bytes

    req_data['Question']=Question

    # 读取 Answer/Authority/Additional
    if Header['ANCOUNT'][1] + Header['NSCOUNT'][1] + Header['ARCOUNT'][1] >= 1:
        pass


    # print(req_data)
    return req_data

# 提取在数据包中的域名
def get_domain(offset,bytes):
    domain = list()
    i = offset
    count = bytes[i]
    while count != 0:
        # print("[+] count:", count)

        domain.append(bytes[i + 1:i + 1 + count].decode())
        # print("[+] domain:", domain)
        i = i + count + 1
        count = bytes[i]
    offset=i
    return ".".join(domain),offset

# 把域名转换成dns协议中的数据包指定的字节格式
def from_domaim_get_bytes(domain="qq.com"):
    domain_bytes=bytes()
    domains=domain.split(".")
    for x in domains:
        # print(x)
        if len(x)<16:
            domain_bytes+=bytes.fromhex("0"+hex(len(x))[2:])
        else:
            domain_bytes += bytes.fromhex(hex(len(x))[2:])
        domain_bytes+=x.encode()
    return domain_bytes

def test():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.sendto(b'aaaaaaaaaaaaaaa', ("127.0.0.1", 53))

if __name__ == "__main__":
    # test()

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("0.0.0.0", 53))
    print("[+] DNS Server start .....")
    while True:

        request_data,clent=s.recvfrom(1024)
        print("-" * 30)
        print(clent)
        print("-" * 30)
        try:
            req_data=paser_req(request_data)
            print("-" * 30)
            print("[+] req_data :", req_data)
            print("-" * 30)
            response_data=set_res(req_data)
            print("-" * 30)
            print("[+] response_data :", response_data)
            print("-" * 30)
            s.sendto(response_data,clent)
        except Exception as e:
            print(e)

        # req_data = paser_req(request_data)
        # print("-" * 30)
        # print("[+] req_data :",req_data)
        # print("-" * 30)
        # response_data = set_res(req_data)
        # print("-" * 30)
        # print("[+] response_data :",response_data)
        # print("-" * 30)
        # s.sendto(response_data, clent)


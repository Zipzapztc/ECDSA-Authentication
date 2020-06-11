3
from socket import socket, SOCK_STREAM, AF_INET
from ecdsa import SigningKey,VerifyingKey,NIST384p
from time import time
from random import randint
import json


def AuthenticationAP(MN,ID,vk_AP,sk_MN,vk_MN):
    while True:
        #发送问询信息，ID加随机数加时间戳
        rand=str(randint(1,10000000000))
        curr_time=str(int(time()))
        query=ID+'-'+rand+curr_time
        MN.send(query.encode('utf-8'))
    
        try:
            #收到AP签名，验证签名
            recv_sig=MN.recv(1024)
            if vk_AP.verify(recv_sig,query.encode('utf-8')):
                MN.send('认证成功'.encode('utf-8'))
        except Exception as e:
            MN.send('认证失败'.encode('utf-8'))
            MN.close()
            break

        try:
            #收到AP问询信息，进行签名
            recv_query=MN.recv(1024)
            sig=sk_MN.sign(recv_query)
            MN.send(sig)
        except Exception as e:
            print(e)
            break

        try:
            #收到认证结果
            recv_msg=MN.recv(1024)
            if recv_msg.decode('utf-8')=='认证成功':
                print('成功连接到AP')
            else:
                print('连接失败')
                MN.close()
                break
        except Exception as e:
            print(e)
            break
        break


def main():
    with open('document_MN.json','r',encoding='utf-8') as f:
        data=json.load(f)
    addr_AP=data['AP'][0]
    port_AP=data['AP'][1]
    vk_AP=VerifyingKey.from_string(bytes.fromhex(data['AP'][2]),curve=NIST384p)
    sk_MN=SigningKey.from_string(bytes.fromhex(data['MN'][0]),curve=NIST384p)
    vk_MN=VerifyingKey.from_string(bytes.fromhex(data['MN'][1]),curve=NIST384p)

    MN = socket(family=AF_INET,type=SOCK_STREAM)
    MN.connect((addr_AP, port_AP))    
    ID=input('请输入ID:')
    AuthenticationAP(MN,ID,vk_AP,sk_MN,vk_MN)
    
    MN.close()


if __name__ == '__main__':
    main()
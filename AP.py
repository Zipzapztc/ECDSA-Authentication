from socket import socket, SOCK_STREAM, AF_INET
from threading import Thread
from ecdsa import SigningKey,VerifyingKey,NIST384p
from time import time
from random import randint
import json

#继承多线程
class AuthenticationMN(Thread):
    def __init__(self,MN,sk_AP,vk_AP,MNdict):
        super().__init__()
        self.MN=MN
        self.sk_AP=sk_AP
        self.vk_AP=vk_AP
        self.MNdict=MNdict
    
    def run(self):
        while True:
            try:
                #收到MN问询信息
                recv_query=self.MN.recv(1024)
                ID_MN=recv_query.decode('utf-8').split('-')[0]
                #判断ID
                if self.MNdict.get(ID_MN)!=None:
                    #进行签名
                    sig=self.sk_AP.sign(recv_query)
                    self.MN.send(sig)
                else:
                    #未知ID直接断开连接
                    print('未知ID')
                    self.MN.close()
                    break
            except Exception as e:
                print(e)
                break
        
            try:
                #收到认证结果
                recv_msg=self.MN.recv(1024)
                if recv_msg.decode('utf-8')!='认证成功':
                    print('连接失败')
                    self.MN.close()
                    break
            except Exception as e:
                print(e)
                break

            #发送问询信息，随机数加时间戳
            rand=str(randint(1,10000000000))
            curr_time=str(int(time()))
            query=rand+curr_time
            self.MN.send(query.encode('utf-8'))

            try:
                #收到MN签名，验证签名
                recv_sig=self.MN.recv(1024)
                vk_MN=VerifyingKey.from_string(bytes.fromhex(self.MNdict[ID_MN]),curve=NIST384p)
                if vk_MN.verify(recv_sig,query.encode('utf-8')):
                    self.MN.send('认证成功'.encode('utf-8'))
                    print('成功连接')
            except Exception as e:
                self.MN.send('认证失败'.encode('utf-8'))
                print('连接失败',e)
                self.MN.close()
                break
            break


def main():
    with open('document_AP.json','r',encoding='utf-8') as f:
        data=json.load(f)
    addr_AP=data['AP'][0]
    port_AP=data['AP'][1]
    sk_AP=SigningKey.from_string(bytes.fromhex(data['AP'][2]),curve=NIST384p)
    vk_AP=VerifyingKey.from_string(bytes.fromhex(data['AP'][3]),curve=NIST384p)
    MNdict=data['MN']

    AP = socket(family=AF_INET,type=SOCK_STREAM)
    AP.bind((addr_AP, port_AP))
    AP.listen(512)
    print('AP启动开始监听')
    MNlist = []
    while True:
        curr_MN, addr_MN = AP.accept()
        print(addr_MN[0], '请求连接AP.')
        MNlist.append(curr_MN)
        AuthenticationMN(curr_MN,sk_AP,vk_AP,MNdict).start()

if __name__ == "__main__":
    main()
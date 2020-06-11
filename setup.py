from ecdsa import SigningKey,VerifyingKey,NIST384p
import json

#生成AP签名密钥和验证密钥
sk_AP=SigningKey.generate(curve=NIST384p)
sk_AP_string=sk_AP.to_string().hex()
vk_AP=sk_AP.get_verifying_key()
vk_AP_string=vk_AP.to_string().hex()

#生成MN签名密钥和验证密钥
sk_MN=SigningKey.generate(curve=NIST384p)
sk_MN_string=sk_MN.to_string().hex()
vk_MN=sk_MN.get_verifying_key()
vk_MN_string=vk_MN.to_string().hex()


#放入两个字典
dict1={'AP':['192.168.43.28',12345,sk_AP_string,vk_AP_string],'MN':{'111':vk_MN_string}}
dict2={'AP':['192.168.43.28',12345,vk_AP_string],'MN':[sk_MN_string,vk_MN_string]}

#写入json文件
with open('document_AP.json','w',encoding='utf-8') as f1:
        json.dump(dict1,f1,indent=4)
with open('document_MN.json','w',encoding='utf-8') as f2:
        json.dump(dict2,f2,indent=4)



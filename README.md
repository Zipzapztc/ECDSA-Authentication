# ECDSA-Authentication
基于ECDSA的简单双向认证


ECDSA：椭圆曲线采用384位NIST素域椭圆曲线，HASH算法采用SHA1杂凑算法

setup.py：创建密钥对，将地址、端口及密钥等信息保存在各自的json文件中

AP:AP端运行程序

MN：MN端运行程序


AP端：

①载入AP的ID,打开端口监听。

②收到连接请求,判断MN的ID是否存在，不存在，则关闭socket。

③接收MN发过来的质询文本(随机数+时戳),签字并将签字发给MN,接受MN对其身份的认证。若成功则MN收到AP发送的认证成功消息,继续步骤④;失败则关闭socket。

④向MN发送质询文本。

⑤接收MN的签字并认证，向MN发送认证成功或失败消息，完成认证。



MN端：

①得到AP的域名或IP地址。

②向AP发送质询文本。

③接收AP的签字并认证,认证成功则向AP发送认证成功消息，并执行步骤④;失败则向AP发送认证失败消息，同时关闭socket。

④接收AP发过来的质询文本,签字并将签字发给AP,接受AP对其身份的认证。

⑤收到AP的认证成功消息,完成认证,同时将网关设为AP地址，实现接入;若收到认证失败消息则退出。

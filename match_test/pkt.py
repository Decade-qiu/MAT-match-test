from time import sleep
from scapy.all import *
from scapy.layers.inet import *

# 配置
conf.L3socket = L3RawSocket  
# 添加规则
# rules = [
#     'ip netns exec MAT iptables -A OUTPUT -j LOG -m comment --comment "log"',
#     'ip netns exec MAT iptables -A OUTPUT -p tcp --dport 80 -j REJECT -m comment --comment "reject"',
#     'ip netns exec MAT iptables -A POSTROUTING -j MASQUERADE -m comment --comment "masquerade" -t nat'
# ]
# for rule in rules:
#     ret = os.system(rule)
#     if ret < 0: print(rule+" 插入失败！")
os.system("truncate -s 0 /var/log/kern.log")
sleep(2)
# 发送数据包
N = 0
for i in range(1, N+1):
    # 随机生成源 IP 和目的 IP
    src_ip = ".".join(str(random.randint(0, 255)) for _ in range(4))
    dst_ip = ".".join(str(random.randint(0, 255)) for _ in range(4))
    # 随机生成协议
    protocols = [TCP, UDP, ICMP]
    protocol = random.choice(protocols)
    # 构造数据包
    pkt = None
    if protocol == TCP or protocol == UDP:
        # 随机生成源端口和目的端口
        src_port = random.randint(1024, 65535)
        dst_port = random.randint(1, 1023)
        pkt = IP(src=src_ip, dst=dst_ip, tos=255, id=i)/protocol(sport=src_port, dport=dst_port)
    else:
        pkt = IP(src=src_ip, dst=dst_ip, tos=255, id=i)/protocol()
    # pkt.show()
    send(pkt)
send(IP(src="192.168.0.1", dst="10.40.6.10", tos=255, id=1)/UDP())
send(IP(src="192.16.0.1", dst="10.40.6.1", tos=255, id=2)/ICMP())
send(IP(src="192.16.0.1", dst="10.40.6.1", tos=255, id=3)/TCP(dport=22))
# 获取/var/log/kern.log中的开头为"PKT"的日志行
sleep(5)
ret = os.system("grep PKT_255 /var/log/kern.log > /home/qzj/src/match_test/pkt.log")
with open("/home/qzj/src/match_test/pkt.log", "r") as f:
    lines = f.readlines()
    for line in lines:
        print(line)
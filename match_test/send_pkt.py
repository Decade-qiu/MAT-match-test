# -*- coding: utf-8 -*-
"""
cd ./match_test && sudo ip netns exec MAT python3 -u "./send_pkt.py" && cd ..
"""
from time import sleep
from scapy.all import *
from scapy.layers.inet import *
from scapy.contrib.igmp import IGMP
# 配置
conf.L3socket = L3RawSocket 

# 整数转点分十进制
def l2ip(ip):
    return ".".join([str(ip >> (i << 3) & 0xff) for i in range(3, -1, -1)])

# 构造数据包
def generate_pkt(src, dst, sport, dport, protocol, pkt_num):
    pkt = None
    if protocol == 6:
        pkt = IP(src=src, dst=dst, tos=255, id=pkt_num)/TCP(sport=sport, dport=dport)
    elif protocol == 17:
        pkt = IP(src=src, dst=dst, tos=255, id=pkt_num)/UDP(sport=sport, dport=dport)
    elif protocol == 1:
        pkt = IP(src=src, dst=dst, tos=255, id=pkt_num)/ICMP()
    else: 
        pkt = IP(src=src, dst=dst, tos=255, id=pkt_num, proto=protocol)
    return pkt

# debug
# x = IP(src='58.249.190.113', dst='128.0.0.0', tos=255, id=222, proto=47)
# x.show()
# send(x)
# exit()

# 清空日志  
os.system("truncate -s 0 /var/log/kern.log")
sleep(2)

# 读取classbench-ng下的filter_tuple_trace 封装成数据包发送
pkt_num = 0
pkt_map = dict()
with open("./filter_tuple_trace", "r") as f:
    pkts = f.readlines()
    pkt_num = len(pkts)
    for num in range(1, pkt_num+1):
        line = pkts[num-1].strip()
        if len(line) == 0: continue
        tuples = line.split("\t")
        src, dst, sport, dport, protocol = [int(tuples[i]) for i in range(5)]
        # 去除广播地址
        if (dst == 4294967295 or dst == 2147483647): dst = 1
        # 去除本地地址
        if (src == 0): src = 1
        src, dst = l2ip(src), l2ip(dst)
        pkt = generate_pkt(src, dst, sport, dport, protocol, num)
        send(pkt)
        pkt_map[num] = [src, dst, sport, dport, protocol]

# 获取前，重新发送几个数据包，刷新日志缓冲区
for i in range(100): 
    send(IP(src="0.0.0.0", dst="1.1.1.1", tos=255, id=65535))
sleep(2)

# 获取/var/log/kern.log中的开头为"PKT_255"的日志行
ret = os.system("grep PKT_255 /var/log/kern.log > ./pkt.log")
match_out = dict()
with open("./pkt.log", "r") as f:
    lines = f.readlines()
    for line in lines:
        index = line.find("PKT_255")
        line = line.strip()[index:].split()
        x, y = int(line[1]), int(line[9])
        if (line[1] not in match_out): 
            match_out[x] = y

# 记录结果 <pkt, rule>
pkt_not_match = open("./pkt_not_match", "w")
with open("./match_out", "w") as f:
    for item in range(1, pkt_num+1):
        f.write("{} {}\n".format(item, match_out.get(item, -1)))
        if (match_out.get(item, -1) == -1): 
            pkt_not_match.write(" ".join([str(i) for i in pkt_map[item]])+"\n")
pkt_not_match.close()

# 记录没有任何数据包匹配的rule
rule_not_match = open("./rule_not_match", "w")
with open("./rule_set", "r") as f:
    rule_set = f.readlines()
    rule_num = len(rule_set)
    for i in range(1, rule_num+1):
        if (i not in match_out.values()): 
            rule_not_match.write("{}".format(str(rule_set[i-1])))
rule_not_match.close()
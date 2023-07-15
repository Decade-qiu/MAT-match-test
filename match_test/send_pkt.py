# -*- coding: utf-8 -*-
# !!!!!!!!!!一定要在ip netns exec MAT中运行!!!!!!!!!
"""
cd /home/qzj/src/match_test && sudo ip netns exec MAT python3 -u "/home/qzj/src/match_test/send_pkt.py"
"""
from time import sleep
from scapy.all import *
from scapy.layers.inet import *
# 协议映射
protocol_map = {
    0: 'ip',
    1: 'icmp',
    2: 'igmp',
    4: 'ipip',
    6: 'tcp',
    8: 'egp',
    12: 'pup',
    17: 'udp',
    22: 'idp',
    29: 'tp',
    33: 'dccp', 
    41: 'ipv6',
    46: 'rsvp',
    47: 'gre',
    50: 'esp',
    51: 'ah',
    92: 'mtp',
    94: 'beetph',
    98: 'encap',
    103: 'pim',
    108: 'comp',
    132: 'sctp',
    136: 'udplite',
    137: 'mpls',
    255: 'raw'
}
# 整数转点分十进制
def l2ip(ip):
    return ".".join([str(ip >> (i << 3) & 0xff) for i in range(3, -1, -1)])
# 配置
conf.L3socket = L3RawSocket  
# x = IP(src="0.0.0.0", dst="192.168.100.1", tos=255, id=3899)/UDP(sport=1024, dport=65535)
# x.show()
# exit()
# 清空日志  
os.system("truncate -s 0 /var/log/kern.log")
sleep(2)
# 读取classbench-ng下的filter_tuple_trace 封装成数据包发送
pkt_num = 0
pkt_map = dict()
with open("../classbench-ng/filter_tuple_trace", "r") as f:
    pkts = f.readlines()
    pkt_num = len(pkts)
    for pkt_num in range(1, pkt_num+1):
        line = pkts[pkt_num-1].strip()
        if len(line) == 0: continue
        tuples = line.split("\t")
        src, dst, sport, dport, protocol = [tuples[i] for i in range(5)]
        src, dst = l2ip(int(src)), l2ip(int(dst))
        protocol, pf = protocol_map.get(int(protocol), ''), int(protocol)
        pkt = None
        if protocol == 'tcp':
            pkt = IP(src=src, dst=dst, tos=255, id=pkt_num)/TCP(sport=int(sport), dport=int(dport))
        elif protocol == 'udp':
            pkt = IP(src=src, dst=dst, tos=255, id=pkt_num)/UDP(sport=int(sport), dport=int(dport))
        elif protocol == 'icmp':
            pkt = IP(src=src, dst=dst, tos=255, id=pkt_num)/ICMP()
        elif protocol == 'gre':
            pkt = IP(src=src, dst=dst, tos=255, id=pkt_num)/GRE()
        elif protocol == 'ip':
            pkt = IP(src=src, dst=dst, tos=255, id=pkt_num)
        else:
            pkt = IP(src=src, dst=dst, tos=255, id=pkt_num, proto=pf)
        send(pkt)
        pkt_map[pkt_num] = [src, dst, sport, dport, protocol]
# 获取/var/log/kern.log中的开头为"PKT_255"的日志行
# 获取前，重新发送几个数据包，刷新日志缓冲区
for i in range(100): 
    send(IP(src="0.0.0.0", dst="1.1.1.1", tos=255, id=65535))
sleep(2)
ret = os.system("grep PKT_255 /var/log/kern.log > ./pkt.log")
hs = dict()
with open("./pkt.log", "r") as f:
    lines = f.readlines()
    for line in lines:
        index = line.find("PKT_255")
        line = line.strip()[index:].split()
        x, y = int(line[1]), int(line[9])
        if (line[1] not in hs): hs[x] = y
# 记录结果 <pkt, rule_id>
print(pkt_num, min(hs.keys()), max(hs.keys()))
error = open("./error", "w")
with open("./match_out.txt", "w") as f:
    for item in range(1, pkt_num+1):
        f.write("{} {}\n".format(item, hs.get(item, 0)))
        if (hs.get(item, 0) == 0): 
            error.write(" ".join(pkt_map[item])+"\n")
error.close()
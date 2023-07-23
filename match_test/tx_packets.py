# -*- coding: utf-8 -*-
from time import sleep
from scapy.all import *
from scapy.layers.inet import *
from scapy.contrib.igmp import IGMP
from ipaddress import *

# 配置
conf.L3socket = L3RawSocket 
conf.verb = 0

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

def main(pkt_file):
    pkts = None
    ac_num = 0
    with open(pkt_file, "r") as f:
        pkts = f.readlines()
        pkt_num = len(pkts)
        for num in range(1, pkt_num+1):
            line = pkts[num-1].strip()
            if len(line) == 0: continue
            tuples = line.split()
            _, src, dst, protocol, sport, dport = [tuples[i] for i in range(6)]
            protocol, sport, dport = int(protocol), int(sport), int(dport)
            num = int(_[3:])
            pkt = generate_pkt(src, dst, sport, dport, protocol, num)
            send(pkt, verbose=False)
            ac_num += 1
    sleep(1)
    for i in range(100): 
        send(IP(src="0.0.1.0", dst="1.1.1.1", tos=255, id=65535))
    sleep(2)
    print("Has send {} packets.".format(ac_num))
    return pkts, ac_num
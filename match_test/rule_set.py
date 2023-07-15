# -*- coding: utf-8 -*-
"""
cd /home/qzj/src/match_test && sudo python3 -u "/home/qzj/src/match_test/rule_set.py"
"""
import os
import time

# 网络命名空间
NETNS = "MAT"
os.system("ip netns exec {} iptables -F".format(NETNS))
# 禁止所有icmp非requst-echo报文
os.system("ip netns exec {} iptables -A OUTPUT -p icmp ! --icmp-type echo-request -j DROP".format(NETNS))
# 禁止所有tcp, ACK FIN PSH RST URG报文
os.system("ip netns exec {} iptables -A OUTPUT -p tcp --tcp-flags ACK ACK -j DROP".format(NETNS))
os.system("ip netns exec {} iptables -A OUTPUT -p tcp --tcp-flags FIN FIN -j DROP".format(NETNS))
os.system("ip netns exec {} iptables -A OUTPUT -p tcp --tcp-flags PSH PSH -j DROP".format(NETNS))
os.system("ip netns exec {} iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP".format(NETNS))
os.system("ip netns exec {} iptables -A OUTPUT -p tcp --tcp-flags URG URG -j DROP".format(NETNS))

# 读取规则并执行
total_rules = 0
with open("../classbench-ng/rule_set.txt", "r") as f:
    for line in f.readlines():
        line = line.strip()
        cmd = "ip netns exec {} {}".format(NETNS, line)
        status = os.system(cmd)
        if status != 0:
            print("Error: {}".format(line))
            break
        total_rules += 1
print("Total rules: {}".format(total_rules))

# 添加一个默认规则
os.system("ip netns exec {} iptables -A OUTPUT -j ACCEPT -m comment --comment 99999".format(NETNS))
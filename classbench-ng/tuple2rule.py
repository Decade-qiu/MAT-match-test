# -*- coding: utf-8 -*-

"""
cd /home/qzj/src/classbench-ng && sudo python3 -u "/home/qzj/src/classbench-ng/tuple2rule.py"
"""
import os
import random

# 常用端口号
port = [20, 21, 22, 23, 25, 53, 69, 80, 110, 119, 123, 135, 137, 138, 139, 143, 161, 389, 443, 445, 465, 873, 1080, 1158, 1433, 1521, 2100, 3128, 3389, 3306, 5432, 5601, 6379, 8080, 8081, 8888, 9000, 9080, 9090, 9200, 10050, 10051, 11211, 22122, 27017]

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

# 全局规则列表
RULE_IDX = 1
rule_set = []

# 每个seed规则生成数
pre_cnt = 50

# trace_generate参数
a, b, scale = 1, 0.001, 1

# 添加规则
def add(src, dst, protocol, sport, dport, pf, sf, df):
    global RULE_IDX
    rule = None
    if (sport == -1 and dport == -1):
        rule = "iptables -A OUTPUT -s {} -d {} {} -p {} -j ACCEPT -m comment --comment \"{}\"".format(src, dst, pf, protocol, RULE_IDX)
    else:
        rule = "iptables -A OUTPUT -s {} -d {} {} -p {} {} --sport {} {} --dport {} -j ACCEPT -m comment --comment \"{}\"".format(src, dst, pf, protocol, sf, sport, df, dport, RULE_IDX)
    rule_set.append(rule)
    RULE_IDX += 1

# ip tuple -> iptables rule
def tuple2rule(t):
    src, dst = t[0], t[1]
    sport = ':'.join([tp.strip() for tp in t[2].split(":")])
    dport = ':'.join([tp.strip() for tp in t[3].split(":")])
    p_num = int(t[4].split('/')[0], 16)&int(t[4].split('/')[1], 16)
    if (p_num not in protocol_map): return
    protocol = protocol_map[p_num]
    # 是否有端口号
    if protocol in ['tcp', 'udp', 'sctp', 'dccp']:
        add(src, dst, protocol, sport, dport, '', '', '')
        # 单一端口号取反
        # if (sport.split(':')[0] == sport.split(':')[1]):
        #     tport = str(random.choice(port))
        #     add(src, dst, protocol, tport+":"+tport, dport, '', '!', '')
        # if (dport.split(':')[0] == dport.split(':')[1]):
        #     tport = str(random.choice(port))
        #     add(src, dst, protocol, sport, tport+":"+tport, '', '', '!')
    else:
        add(src, dst, protocol, -1, -1, '', '', '')
        # 协议取反 
        # 1.不能对IP协议取反 2.如果协议后面带端口号，则不能取反
        # if (protocol != 'ip'): add(src, dst, protocol, -1, -1, '!', '', '')

# 保存tuple规则
filter_tuple = open("filter_tuple", "w")
# 读取参数文件
dir_path = './vendor/parameter_files'
for filename in os.listdir(dir_path):
    if os.path.isfile(os.path.join(dir_path, filename)):
        command = "./classbench generate v4 ./vendor/parameter_files/{} --count={}".format(filename, pre_cnt)
        output = os.popen(command).read()
        filter_tuple.write(output)
        lines = output.split("\t\n")
        for line in lines:
            line = line.lstrip().rstrip()
            if (len(line)==0 or line[0] != '@'): continue
            fd = line.split("\t")
            fd[0] = fd[0][1:]
            tuple2rule(fd)
filter_tuple.close()
# 通过tuple规则生成pkt头部信息
cmd = "./trace_generator/trace_generator {} {} {} {}".format(a, b, scale, "filter_tuple")
status = os.system(cmd)
if (status != 0): print("ERROR: trace_generator!")

# 写规则到文件
with open("rule_set.txt", 'w') as f:
    for r in rule_set:
        f.write(r)
        f.write('\n')

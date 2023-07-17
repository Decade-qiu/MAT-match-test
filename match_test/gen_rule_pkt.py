# -*- coding: utf-8 -*-
"""
cd ./match_test && sudo python3 -u "./gen_rule_pkt.py"
"""
import os, random
# 常用端口号
port_set = [0, 13, 20, 21, 22, 23, 25, 37, 53, 67, 69, 79, 80, 88, 109, 110, 113, 119, 123, 137, 138, 139, 143, 161, 162, 179, 443, 464, 513, 514, 540, 544, 700, 749, 750, 754, 800, 802, 871, 873, 879, 1023, 1024, 1999, 2001, 2055, 2105, 2401, 3128, 3780, 5998, 5999, 6000, 6001, 6499, 6667, 7000, 7007, 7326, 7648, 7649, 7777, 7778, 7790, 7791, 8080, 9000, 9001, 9002, 9090, 9091, 10080, 13000, 24032, 29003, 29006, 33434, 33600, 40000, 65535]
# 全局规则列表
rule_set = set()
# 每个seed生成的规则数量
pre_cnt = 1000
# 实际生成的tuple
tuple_set = set()
# trace_generate参数
a, b, scale = 1, 0, 10

# 添加规则
def add(src, dst, protocol, sport, dport, pf, sf, df, t_sport, t_dport, t_protocol):
    rule, tuples = None, None
    if (sport == -1 and dport == -1):
        rule = "iptables -A OUTPUT -s {} -d {} {} -p {} -j ACCEPT ".format(src, dst, pf, protocol)
        tuples = "@{}\t{}\t{}\t{}\t{}\t0x0000/0x0000".format(src, dst, "0 : 65535", "0 : 65535", t_protocol)
    else:
        rule = "iptables -A OUTPUT -s {} -d {} {} -p {} {} --sport {} {} --dport {} -j ACCEPT ".format(src, dst, pf, protocol, sf, sport, df, dport)
        tuples = "@{}\t{}\t{}\t{}\t{}\t0x0000/0x0000".format(src, dst, t_sport, t_dport, t_protocol)
    rule_set.add(rule)
    tuple_set.add(tuples)

# ip tuple -> iptables rule
def tuple2rule(t):
    src, dst = t[0], t[1]
    t_sport, t_dport, t_protocol = t[2], t[3], t[4]
    sport = ':'.join([tp.strip() for tp in t[2].split(":")])
    dport = ':'.join([tp.strip() for tp in t[3].split(":")])
    protocol = int(t[4].split('/')[0], 16)&int(t[4].split('/')[1], 16)
    # 去除匹配条件只有协议的规则
    if (src=="0.0.0.0/0" and dst=="0.0.0.0/0" and sport=="0:65535" and dport=="0:65535"):
        return
    # 是否有端口号
    if protocol in [6, 17]:
        add(src, dst, protocol, sport, dport, '', '', '', t_sport, t_dport, t_protocol)
        # 端口号取反
        # if (sport.split(':')[0] == sport.split(':')[1]):
        #     tport = str(random.choice(port))
        #     add(src, dst, protocol, tport+":"+tport, dport, '', '!', '')
        # if (dport.split(':')[0] == dport.split(':')[1]):
        #     tport = str(random.choice(port))
        #     add(src, dst, protocol, sport, tport+":"+tport, '', '', '!')
    else:
        add(src, dst, protocol, -1, -1, '', '', '', t_sport, t_dport, t_protocol)
        # 协议取反
        # add(src, dst, protocol, -1, -1, '!', '', '')

# 读取参数文件
dir_path = '../classbench-ng/vendor/parameter_files'
for filename in os.listdir(dir_path):
    if (not filename.startswith("fw")): continue
    if os.path.isfile(os.path.join(dir_path, filename)):
        command = "../classbench-ng/classbench generate v4 ../classbench-ng/vendor/parameter_files/{} --count={}".format(filename, pre_cnt)
        output = os.popen(command).read()
        # filter_tuple.write(output)
        lines = output.split("\t\n")
        for line in lines:
            line = line.strip()
            if (len(line)==0 or line[0] != '@'): continue
            fd = line.split("\t")
            fd[0] = fd[0][1:]
            tuple2rule(fd)

# filter_tuple保存tuples
filter_tuple = open("filter_tuple", "w")
for t in tuple_set:
    filter_tuple.write(t+"\t\n")
filter_tuple.close()

# 通过tuples生成pkt头部信息
cmd = "../classbench-ng/trace_generator/trace_generator {} {} {} {}".format(a, b, scale, "filter_tuple")
status = os.system(cmd)
if (status != 0): print("ERROR: trace_generator!")

# 写规则到文件
with open("rule_set.txt", 'w') as f:
    rule_list = list(rule_set)
    for rule_id in range(0, len(rule_list)):
        f.write('{}-m comment --comment "{}"\n'.format(rule_list[rule_id], rule_id+1))

print("tuples num: {}\nrules num: {}".format(len(tuple_set), len(rule_set)))
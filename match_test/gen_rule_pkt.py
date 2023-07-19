# -*- coding: utf-8 -*-
"""
cd match_test && sudo python3 -u "./gen_rule_pkt.py" && cd ..
"""
import os, random, re
from collections import defaultdict
from ipaddress import *
# 协议类型
total_pf = ["0x00/0x00", "0x06/0xFF", "0x11/0xFF", "0x01/0xFF", "0x2F/0xFF", "0x02/0xFF", "0x03/0xFF", "0x04/0xFF", "0x05/0xFF", "0x07/0xFF", "0x08/0xFF"]
total_protocol = ["0", "6", "17", "1", "47", "2", "3", "4", "5", "7", "8"]
# iptables规则集合
rule_set = set()
rule_list = list()
# tuple规则集合
tuple_set = set()
# db_generate参数
filter_num, smooth, address_scope, port_scope = 6000, 3, -0.7, -0.75
# trace_generate参数
a, b, scale = 1, 0, 5
# 已经生成的rules中<src, dst>集合
address_pair = set()

# 生成随机子网
def getSubnet():
    ip = random.randint(0, 2**32-1)
    mask = random.randint(1, 32)
    mask_str = '1' * mask + '0' * (32 - mask)
    mask_num = int(mask_str, 2)
    ip = ip&mask_num
    return str(IPv4Network((ip, mask)))

# 获取iptables rule头部的<src, dst>
def get_head_address_pair(rule):
    res = re.search(r'-s (\S+) -d (\S+)', rule)
    return res.group(1)+" "+res.group(2)

# 获取iptables rule头部的五元组信息
def get_head(rule):
    src = re.search(r'-s (\S+)', rule).group(1)
    dst = re.search(r'-d (\S+)', rule).group(1)
    proto = re.search(r'-p (\S+)', rule).group(1)
    sport_match = re.search(r'--sport (\S+)', rule)
    sport = "0:65535" if sport_match==None else sport_match.group(1)
    dport_match = re.search(r'--dport (\S+)', rule)
    dport = "0:65535" if dport_match==None else dport_match.group(1)
    return src, dst, sport, dport, proto, "! -p" in rule, "! --sport" in rule, "! --dport" in rule

# iptables rule规则排序
def sort_rules(r):
    src, dst, sport, dport, protocol, pf, sf, df = get_head(r)
    # print(get_head(r))
    src_ip, src_mask = src.split('/')
    dst_ip, dst_mask = dst.split('/')
    sport_start, sport_end = map(int, sport.split(':'))
    dport_start, dport_end = map(int, dport.split(':'))
    return (-int(src_mask), -int(IPv4Address(src_ip)), -int(dst_mask), -int(IPv4Address(dst_ip)), -int(protocol) if not pf else 0, (sport_end - sport_start+1) if not sf else 65535, (dport_end - dport_start+1) if not df else 65535)

# 计算给定规则端口范围（范围，取反，精确值）
def calculate_port_range(sport, dport, sf=False, df=False):
    sport_start, sport_end = map(int, sport.split(':'))
    dport_start, dport_end = map(int, dport.split(':'))
    if sf:
        sport_range = [(0, sport_start - 1), (sport_end + 1, 65535)]
    else:
        sport_range = [(sport_start, sport_end)]
    if df:
        dport_range = [(0, dport_start - 1), (dport_end + 1, 65535)]
    else:
        dport_range = [(dport_start, dport_end)]
    port_range = []
    for start, end in sport_range:
        for start2, end2 in dport_range:
            port_range.append((start, end, start2, end2))
    return port_range

# 检查同一<src, dst, protocol>条件下的规则是否有端口冲突
def check(sport, dport, pf_port):
    for start, end, start2, end2 in pf_port:
        if (sport >= start and sport <= end and dport >= start2 and dport <= end2):
            return False
    return True

# 获取packet的<sport, dport>
def get_sport_dport(port_range, pf_port):
    for start, end, start2, end2 in port_range:
        for sport in range(start, end + 1):
            for dport in range(start2, end2 + 1):
                if (check(sport, dport, pf_port)):
                    return sport, dport
    return None

# 根据iptables规则生成packet测试集
def gen_pkt_iptables():
    global rule_list, rule_set
    rule_list = list(rule_set)
    rule_list.sort(key=sort_rules)
    rules = rule_list
    res_rules = []
    packets = []
    ip_set = set()
    idx, n = 0, len(rules)
    while (idx < n):
        pre_ip = get_head_address_pair(rules[idx])
        src, smask = int(IPv4Address(pre_ip.split()[0].split('/')[0])), int(pre_ip.split()[0].split('/')[1])
        dst, dmask = int(IPv4Address(pre_ip.split()[1].split('/')[0])), int(pre_ip.split()[1].split('/')[1])
        pf_port = defaultdict(list)
        flag = 0
        for si in range(0, 2**(32-smask)):
            for di in range(0, 2**(32-dmask)):
                if (str(src+si)+" "+str(dst+di) not in ip_set): 
                    src += si
                    dst += di
                    ip_set.add(str(src)+" "+str(dst))
                    flag = 1
                    break
            if (flag == 1):
                break
        while (idx < n and get_head_address_pair(rules[idx]) == pre_ip):
            print("processing rule {}".format(idx))
            _, _, sport, dport, protocol, pf, sf, df = get_head(rules[idx])
            if pf:
                cur_pf = random.choice(total_protocol)
                while (cur_pf == protocol):
                    cur_pf = random.choice(total_protocol)
                packets.append("{}\t{}\t{}\t{}\t{}\t0\t0".format(src, dst, 0, 0, cur_pf))
                res_rules.append(rules[idx])
            else:
                port_range = calculate_port_range(sport, dport, sf, df)
                port = get_sport_dport(port_range, pf_port[protocol])
                if (port != None):
                    pf_port[protocol].extend(port_range)
                    packets.append("{}\t{}\t{}\t{}\t{}\t0\t0".format(src, dst, port[0], port[1], protocol))
                    res_rules.append(rules[idx])
            idx += 1
    rule_list = res_rules
    return packets

# 保存通过iptables生成pkt的头部信息
def save_pkt_iptabes(model='w'):
    packets = open("filter_tuple_trace", model)
    pkt = gen_pkt_iptables()
    for p in pkt:
        packets.write(p+"\n")
    packets.close()

# 保存通过tuples生成pkt头部信息
def save_pkt_tuples():
    global a, b, scale
    cmd = "../classbench-ng/trace_generator/trace_generator {} {} {} {}".format(a, b, scale, "filter_tuple")
    status = os.system(cmd)
    if (status != 0): 
        print("ERROR: trace_generator!")

# 添加规则
def add(src, dst, protocol, sport, dport, t_sport, t_dport, t_protocol):
    if (sport == -1 and dport == -1):
        rule = "iptables -A OUTPUT -s {} -d {} -p {} -j ACCEPT ".format(src, dst, protocol)
        tuples = "@{}\t{}\t{}\t{}\t{}\t0x0000/0x0000".format(src, dst, "0 : 65535", "0 : 65535", t_protocol)
    else:
        rule = "iptables -A OUTPUT -s {} -d {} -p {} --sport {} --dport {} -j ACCEPT ".format(src, dst, protocol, sport, dport)
        tuples = "@{}\t{}\t{}\t{}\t{}\t0x0000/0x0000".format(src, dst, t_sport, t_dport, t_protocol)
    src, dst = [ip.split('/')[0] for ip in [src, dst]]
    key = src+" "+dst
    address_pair.add(key)
    rule_set.add(rule)
    tuple_set.add(tuples)

# tuple规则转换为iptables规则
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
        add(src, dst, protocol, sport, dport, t_sport, t_dport, t_protocol)
    else:
        add(src, dst, protocol, -1, -1, t_sport, t_dport, t_protocol)

# 协议取反类型的规则
def gen_invert_protocol():
    for pf in total_pf:
        if (pf == "0x00/0x00"): continue
        # 生成随机src dst
        src, dst = 0, 0
        while 1:
            src, dst = getSubnet(), getSubnet()
            if (src.split('/')[0]+" "+dst.split('/')[0] not in address_pair):
                break
        address_pair.add(src.split('/')[0]+" "+dst.split('/')[0])
        rule = "iptables -A OUTPUT -s {} -d {} ! -p {} -j ACCEPT ".format(src, dst, int(pf[:4], 16))
        rule_set.add(rule)
        for ac_pf in total_pf:
            if (pf == ac_pf): continue
            tuples = "@{}\t{}\t{}\t{}\t{}\t0x0000/0x0000".format(src, dst, "0 : 65535", "0 : 65535", ac_pf)
            tuple_set.add(tuples)

# 端口取反的规则
def gen_invert_port():
    for pf in ["0x11/0xFF", "0x06/0xFF"]:
        for i in range(10):
            src, dst = 0, 0
            while 1:
                src, dst = getSubnet(), getSubnet()
                if (src.split('/')[0]+" "+dst.split('/')[0] not in address_pair):
                    break
            address_pair.add(src.split('/')[0]+" "+dst.split('/')[0])
            for st in ["! ", " !", "!!"]:
                sport = random.randint(0, 1024)
                dport = random.randint(1024, 65535)
                rule = "iptables -A OUTPUT -s {} -d {} -p {} {} --sport {}:{} {} --dport {}:{} -j ACCEPT ".format(src, dst, int(pf[:4], 16), st[0], sport, sport, st[1], dport, dport)
                rule_set.add(rule)
                tuples = None
                if (st == "! "):
                    tuples = "@{}\t{}\t{} : {}\t{} : {}\t{}\t0x0000/0x0000".format(src, dst, 1024, 65535, dport, dport, pf)
                elif (st == " !"):
                    tuples = "@{}\t{}\t{} : {}\t{} : {}\t{}\t0x0000/0x0000".format(src, dst, sport, sport, 0, 1023, pf)
                else:
                    tuples = "@{}\t{}\t{} : {}\t{} : {}\t{}\t0x0000/0x0000".format(src, dst, 1024, 65535, 0, 1023, pf)
                tuple_set.add(tuples)

# 使用classbench中Filter set generator生成tuple规则
def gen_filter_tuple():
    # command = "../classbench-ng/vendor/db_generator/db_generator -c ../classbench-ng/vendor/parameter_files/fw1_seed {} {} {} {} filter_tuple".format(filter_num, smooth, address_scope, port_scope)
    # os.system(command)
    with open("filter_tuple", "w") as f: 
        dir_path = "../classbench-ng/vendor/parameter_files"
        for file in os.listdir(dir_path):
            if (not file.startswith("fw1")): continue
            if os.path.isfile(os.path.join(dir_path, file)):
                print("Generating {}!".format(file))
                command = "../classbench-ng/classbench generate v4 ../classbench-ng/vendor/parameter_files/{} --count={} --db-generator=../classbench-ng/vendor/db_generator/db_generator".format(file, filter_num)
                output = os.popen(command).read()
                f.write(output)

gen_filter_tuple()
# 读取tuple规则并进行iptables规则转换
filter_tuple = open("filter_tuple", "r")
tuples_list = filter_tuple.readlines()
for tuples in tuples_list:
    line = tuples.strip()
    if (len(line)==0 or line[0] != '@'): 
        continue
    fd = line.split("\t")
    fd[0] = fd[0][1:]
    tuple2rule(fd)
filter_tuple.close()

# 生成取反规则
gen_invert_port()
gen_invert_protocol()

# 保存tuple规则到文件
filter_tuple = open("filter_tuple", "w")
for tuples in tuple_set:
    filter_tuple.write(tuples+"\t\n")
filter_tuple.close()

# 保存通过tuples生成pkt头部信息
save_pkt_tuples()

# 保存通过iptables规则生成pkt的头部信息
save_pkt_iptabes('a')

# 保存iptables规则到文件（排序）
filter_rule = open("rule_set", 'w')
for dx in range(0, len(rule_list)):
    t = rule_list[dx]
    filter_rule.write('{} -m comment --comment "{}"\n'.format(rule_list[dx],dx+1))
filter_rule.close()

print("tuples num: {}\nrules num: {}".format(len(tuple_set), len(rule_list)))

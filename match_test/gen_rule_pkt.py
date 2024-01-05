# -*- coding: utf-8 -*-
import argparse, os, random, re
from collections import defaultdict
from ipaddress import *
import sys
from time import sleep
from scapy.all import *
from scapy.layers.inet import *
# 文件路径
cur_path = os.path.dirname(__file__)
parent_path = os.path.dirname(cur_path)
sys.path.append(cur_path)
# 协议类型
total_pf = ["0x00/0x00", "0x06/0xFF", "0x11/0xFF", "0x01/0xFF", "0x2F/0xFF", "0x02/0xFF", "0x03/0xFF", "0x04/0xFF", "0x05/0xFF", "0x07/0xFF", "0x08/0xFF"]
total_protocol = ["0", "6", "17", "1", "47", "2", "3", "4", "5", "7", "8"]
# iptables规则集合
rule_set = set()
rule_list = list()
# tuple规则集合
tuple_set = set()
# db_generate参数
filter_num, smooth, address_scope, port_scope = 10000, 4, 0, 0
# trace_generate参数
a, b, scale = 1, 0, 5
# 已经生成的rules中<src, dst>集合
address_pair = defaultdict(dict)
address_src_mask = defaultdict(int)

# init
def init(args1, args2):
    global filter_num, scale
    filter_num = args1
    scale = args2

# finish
def finish():
    global tuple_set, rule_list
    pkts_num = 0
    lines = None
    with open(os.path.join(cur_path, "filter_tuple_trace")) as f:
        lines = f.readlines()
        pkts_num = len(lines)
    with open(os.path.join(parent_path, "output", "packets"), "w") as f:
        for idx, line in enumerate(lines):
            tuples = line.split("\t")
            src, dst, sport, dport, protocol = [int(tuples[i]) for i in range(5)]
            # # 去除广播地址
            # if (dst == 4294967295 or dst == 2147483647 or dst == 0): dst = 1
            # # 去除本地地址
            # if (src == 4294967295 or src == 2147483647 or src == 0): src = 1
            f.write("ID={} {} {} {} {} {}\n".format(idx+1, src, dst, protocol, sport, dport))
    print("Total tuples: {}".format(len(tuple_set)))
    print("Total rules: {}".format(len(rule_list)))
    print("Total packets: {}".format(pkts_num))

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
    global rule_list, rule_set, filter_rule
    print("Generate packets from iptables rules...")
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
    print(f"Rules filter: {len(rule_list)} -> {len(res_rules)}")
    rule_list = res_rules
    return packets

def prefix_length_to_mask(prefix_length):
    mask = 0xFFFFFFFF << (32 - prefix_length)
    return (mask >> 24) & 0xFF, (mask >> 16) & 0xFF, (mask >> 8) & 0xFF, mask & 0xFF

def prefix_to_mask(ip_with_prefix):
    ip_parts = ip_with_prefix.split("/")
    ip = ip_parts[0]
    prefix_length = int(ip_parts[1])
    mask_parts = prefix_length_to_mask(prefix_length)
    mask_str = ".".join(map(str, mask_parts))
    return f"{int(IPv4Address(ip))}/{int(IPv4Address(mask_str))}"

# 保存iptables规则
def save_pkt_iptabes(model='w'):
    with open(os.path.join(cur_path, "filter_tuple_trace"), model) as packets:
        pkts = gen_pkt_iptables()
        for p in pkts:
            packets.write(p+"\n")
    with open(os.path.join(parent_path, "output", "rule_set"), 'w') as filter_rule:
        for dx in range(0, len(rule_list)):
            t = rule_list[dx]
            src, dst, sport, dport, protocol, pf, sf, df = get_head(rule_list[dx])
            filter_rule.write('{} {} {} {} {} {} {} {} {}\n'.format(prefix_to_mask(src), prefix_to_mask(dst), protocol, sport, dport, int(pf), int(sf), int(df), dx+1))

# 保存tuples并生成对应pkt头部信息
def save_pkt_tuples():
    global a, b, scale
    with open(os.path.join(cur_path, "filter_tuple"), "w") as filter_tuple:
        for tuples in tuple_set:
            filter_tuple.write(tuples+"\t\n")
    cmd = os.path.join(parent_path, "classbench-ng", "trace_generator", "trace_generator")+" {} {} {} {}".format(a, b, scale, os.path.join(cur_path, "filter_tuple"))
    status = os.system(cmd)
    if (status != 0): 
        print("ERROR: trace_generator!")

# 判断rule中ip对是否可以插入
def ip_prefix(src, dst):
    _src, _dst = [ip.split('/')[0] for ip in [src, dst]]
    _src_mask, _dst_mask = [ip.split('/')[1] for ip in [src, dst]]
    if (_src in address_src_mask.keys()):
        if (_src_mask != address_src_mask[_src]):
            return False
        if (_dst in address_pair[_src].keys()):
            if (_dst_mask != address_pair[_src][_dst]):
                return False
    address_src_mask[_src] = _src_mask
    address_pair[_src][_dst] = _dst_mask
    return True

# 添加规则
def add(src, dst, protocol, sport, dport, t_sport, t_dport, t_protocol):
    global address_pair, rule_set, tuple_set
    if (sport == -1 and dport == -1):
        rule = "iptables -A OUTPUT -s {} -d {} -p {} -j ACCEPT ".format(src, dst, protocol)
        tuples = "@{}\t{}\t{}\t{}\t{}\t0x0000/0x0000".format(src, dst, "0 : 65535", "0 : 65535", t_protocol)
    else:
        rule = "iptables -A OUTPUT -s {} -d {} -p {} --sport {} --dport {} -j ACCEPT ".format(src, dst, protocol, sport, dport)
        tuples = "@{}\t{}\t{}\t{}\t{}\t0x0000/0x0000".format(src, dst, t_sport, t_dport, t_protocol)
    if (ip_prefix(src, dst)):
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
    if (src == "0.0.0.0/0" and dst != "0.0.0.0/0"):
        src = dst
    # 是否有端口号
    if protocol in [6, 17]:
        add(src, dst, protocol, sport, dport, t_sport, t_dport, t_protocol)
    else:
        add(src, dst, protocol, -1, -1, t_sport, t_dport, t_protocol)

# 协议取反类型的规则
def gen_invert_protocol_rule():
    global address_pair, rule_set, tuple_set, total_pf
    print("Generate invert protocol rules...")
    for pf in total_pf:
        if (pf == "0x00/0x00"): continue
        # 生成随机src dst
        src, dst = 0, 0
        while 1:
            src, dst = getSubnet(), getSubnet()
            if (ip_prefix(src, dst)):
                break
        rule = "iptables -A OUTPUT -s {} -d {} ! -p {} -j ACCEPT ".format(src, dst, int(pf[:4], 16))
        rule_set.add(rule)
        for ac_pf in total_pf:
            if (pf == ac_pf): continue
            tuples = "@{}\t{}\t{}\t{}\t{}\t0x0000/0x0000".format(src, dst, "0 : 65535", "0 : 65535", ac_pf)
            tuple_set.add(tuples)

# 端口取反的规则
def gen_invert_port_rule():
    global address_pair, rule_set, tuple_set
    print("Generate invert port rules...")
    for pf in ["0x11/0xFF", "0x06/0xFF"]:
        for i in range(10):
            for st in ["! ", " !", "!!"]:
                src, dst = 0, 0
                while 1:
                    src, dst = getSubnet(), getSubnet()
                    if (ip_prefix(src, dst)):
                        break
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

# 生成iptables规则
def gen_filter_rule():
    print("Generate iptables rules...")
    with open(os.path.join(cur_path, "filter_tuple"), "r") as filter_tuple:
        tuples_list = filter_tuple.readlines()
        for tuples in tuples_list:
            line = tuples.strip()
            if (len(line)==0 or line[0] != '@'): 
                continue
            fd = line.split("\t")
            fd[0] = fd[0][1:]
            tuple2rule(fd)

# 使用classbench中Filter set generator生成tuple规则
def gen_filter_tuple():
    global filter_num, smooth, address_scope, port_scope
    rrr_num, ff = 0, 1
    # print(os.path.join(cur_path, "filter_tuple"))
    cnt, total = 0, 5
    with open(os.path.join(cur_path, "filter_tuple"), "w") as f: 
        dir_path = os.path.join(parent_path, "classbench-ng", "vendor", "parameter_files")
        for i in range(total):
            for file in os.listdir(dir_path):
                cnt += 1
                # if (not file.startswith("fw1")): continue
                if os.path.isfile(os.path.join(dir_path, file)):
                    print("Generate tuples from {}.".format(file), end=' ')
                    if ff == 1:
                        command = os.path.join(parent_path, "classbench-ng", "classbench")+" generate v4 "+os.path.join(dir_path, file)+" --count={} --db-generator=".format(filter_num)+os.path.join(parent_path, "classbench-ng", "vendor", "db_generator", "db_generator")
                        # print(os.path.join(dir_path, file), cnt)
                        output = os.popen(command).read()
                    else:
                        command = "{} -c {} {} {} {} {} filter_tuple".format(os.path.join(parent_path,'classbench-ng','vendor','db_generator', 'db_generator'), os.path.join(dir_path, file), filter_num, smooth, address_scope, port_scope)
                        # print(command)
                        output = os.popen(command).read()
                    tp = len(output.split("\n"))
                    rrr_num += tp
                    print(tp, datetime.now(), cnt)
                    f.write(output)
    with open(os.path.join(cur_path, "filter_tuple"), "r") as f:
        lines = f.readlines()
        print(len(lines), rrr_num)

# 记录未匹配的数据包
def log_pkt_error(pkt_not_match):
    with open(os.path.join(parent_path, "output", "pkt_not_match"), "w") as f:
        for pkt in pkt_not_match:
            pkt = pkt.strip()
            f.write(pkt+"\n")

# 记录未匹配的规则
def log_rule_error(rule_not_match):
    with open(os.path.join(parent_path, "output", "rule_not_match"), "w") as f:
        for rule in rule_not_match:
            rule = rule.strip()
            f.write(rule+"\n")

# 构造数据包
def generate_pkt(pkt_num, src, dst, sport, dport, protocol, rule_id):
    pkt = None
    if protocol == 6:
        pkt = IP(src=src, dst=dst, tos=255, id=rule_id)/TCP(sport=sport, dport=dport)
    elif protocol == 17:
        pkt = IP(src=src, dst=dst, tos=255, id=rule_id)/UDP(sport=sport, dport=dport)
    elif protocol == 1:
        pkt = IP(src=src, dst=dst, tos=255, id=rule_id)/ICMP()
    else: 
        pkt = IP(src=src, dst=dst, tos=255, id=rule_id, proto=protocol)
    return pkt

def value_match(t: int, v: list)->bool:
    if (v[2] == 0):
        if (v[0] == 0 or (t&v[1]) == v[0]): return 1^v[3]
        return 0^v[3]
    f = 0
    if (t >= v[0] and t <= v[1]): f = 1
    return f ^ v[3]

def query(packet):
    global rule_list
    pkt = packet
    pkt_src, pkt_dst, pkt_protocol, pkt_sport, pkt_dport = map(int, pkt[1:6])
    rule_list = open(os.path.join(parent_path, "output", "rule_set")).readlines()
    for rule in rule_list:
        # print(rule)
        rule = rule.strip().split()
        src, smask = map(int, rule[0].split('/'))
        dst, dmask = map(int, rule[1].split('/'))
        protocol = int(rule[2])
        sp_st, sp_ed = map(int, rule[3].split(':'))
        dp_st, dp_ed = map(int, rule[4].split(':'))
        f1, f2, f3 = map(int, rule[5:8])
        rule_id = int(rule[8])
        if ((pkt_src&smask)==src and (pkt_dst&dmask)==dst and
            value_match(pkt_protocol, list((protocol, 255, 0, f1))) and
            value_match(pkt_sport, list((sp_st, sp_ed, 1, f2))) and
            value_match(pkt_dport, list((dp_st, dp_ed, 1, f3)))):
            return rule_id
    return 0

# 获取匹配的输出结果<packet_id, rule_id>
def get_match_out():
    pkts = os.path.join(parent_path, "output", "packets")
    packet_set, ac_num = [], 0
    # 获取/var/log/kern.log
    match_out = dict()
    print("Start query! --{}".format(datetime.now()))
    time = 0
    with open(pkts, "r") as f:
        packet_set = f.readlines()
        for line in packet_set:
            ac_num += 1
            line = line.strip()
            if len(line) == 0: continue
            tuples = line.split()
            match_out[int(tuples[0][3:])] = query(tuples) 
            time += 1
            if (time%10000 == 0):
                print("Query {} packets! --{}".format(time, datetime.now()))
    print("Query end! --{}".format(datetime.now()))
    # 记录结果
    pkt_not_match = []
    rule_not_match = []
    with open(os.path.join(parent_path, "output", "match_out"), "w") as f:
        final_pkts = open(os.path.join(parent_path, "output", "packets"), 'w')
        for item in range(1, ac_num+1):
            final_pkts.write("{} {}".format(packet_set[item-1].strip(), match_out.get(item, -1))+"\n")
            f.write("{} {}\n".format(item, match_out.get(item, -1)))
            if (match_out.get(item, -1) == -1): 
                pkt_not_match.append(packet_set[item-1])
    for idx in range(1, len(rule_list)+1):
        if (idx not in match_out.values()):
            rule_not_match.append("ID="+str(idx)+" "+rule_list[idx-1])
    log_pkt_error(pkt_not_match)
    log_rule_error(rule_not_match)
    print("Finish, related matching record information is located in the output folder!")

def main(rules_num, scale):
    init(rules_num, scale)
    gen_filter_tuple()
    gen_filter_rule()
    gen_invert_port_rule()
    gen_invert_protocol_rule()
    # save_pkt_tuples()
    save_pkt_iptabes('w')
    finish()
    # update_iptables_rules(netspace)
    get_match_out()

if __name__ == "__main__":
    # update_iptables_rules("MAT")
    get_match_out()
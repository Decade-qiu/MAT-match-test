# -*- coding: utf-8 -*-
import argparse
import os
from match_test import gen_rule_pkt

parser = argparse.ArgumentParser()
# rule数量
parser.add_argument('--rules_num', type=int, default=1000, help='Number of filters')
# packet数量与rule数量的比例
parser.add_argument('--pkt_factor', type=int, default=2, help='Scale factor')
# 网络命名空间名称
parser.add_argument('--netspace', type=str, default="MAT", help='name of netspace')
args = parser.parse_args()

# 调用核心函数
gen_rule_pkt.main(args.rules_num, args.pkt_factor, args.netspace)

# 删除多余输出
os.system("rm gmon.out")
os.system("rm {}".format(os.path.join(os.path.dirname(__file__), "match_test", "tp.log")))
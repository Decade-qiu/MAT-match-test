# -*- coding: utf-8 -*-
import argparse
import os
from match_test import gen_rule_pkt

parser = argparse.ArgumentParser()
# rule数量
parser.add_argument('--rules_num', type=int, default=1000, help='Number of filters')
# packet数量与rule数量的比例
parser.add_argument('--pkt_factor', type=int, default=2, help='Scale factor')

args = parser.parse_args()

# 调用核心函数
gen_rule_pkt.main(args.rules_num, args.pkt_factor)


# -*- coding: utf-8 -*-
"""
cd /home/qzj/src/match_test && sudo python3 -u "/home/qzj/src/match_test/rule_set.py"
"""
import os

# 网络命名空间
NETNS = "MAT"

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
print(total_rules)

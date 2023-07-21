# -*- coding: utf-8 -*-
import argparse
from collections import defaultdict
import os
cur_path = os.path.dirname(__file__)

# 读取匹配文件
def get_kv(file):
    with open(file, "r") as f:
        lines = f.readlines()
        kv = dict()
        for line in lines:
            line = line.strip()
            if len(line) == 0: continue
            tuples = list( map(int, line.split()))
            kv[tuples[0]] = tuples[1]
        return kv

parser = argparse.ArgumentParser()
parser.add_argument('--result', type=str, default=os.path.join(cur_path, "result.txt"), help='result file path')

result_file = parser.parse_args().result
match_file = os.path.join(cur_path, "output", "match_out")
match_record = os.path.join(cur_path, "output", "match_record")

error, total = 0, 0
with open(match_record, "w") as f:
    result, match = get_kv(result_file), get_kv(match_file)
    for pkt in match.keys():
        total += 1
        if (pkt not in result.keys()):
            f.write("Missing packet {}!\n".format(pkt))
            error += 1
        elif (match[pkt] != result[pkt]):
            f.write("Packet {} should match rule {}, but your result is {}!\n".format(pkt, match[pkt], result[pkt]))
            error += 1
        else:
            f.write("Pass.\n")
print("Total: {}, passed: {}\nThe detailed information is in the 'match_error' under the output folder.".format(total, total-error))
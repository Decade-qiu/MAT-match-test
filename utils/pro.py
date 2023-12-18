# -*- coding: utf-8 -*-
def ip_to_binary(ip_str):
    parts = ip_str.split('.')
    binary_parts = [format(int(part), '08b') for part in parts]
    return ''.join(binary_parts)

def count_ones(binary_str):
    return binary_str.count('1')

# 读取文件
with open('/home/qzj/MAT-match-test/output/rule_set', 'r') as file:
    t = open('/home/qzj/MAT-match-test/utils/rule_set', 'w')
    lines = file.readlines()
    for line in lines:
        src, _, _, _, _, _, _, _, rule_id = line.split()
        src_ip, src_mask = src.split('/')
        
        src_ip_binary = ip_to_binary(src_ip)
        src_mask_ones = count_ones(ip_to_binary(src_mask))

        t.write(src_ip_binary + '/' + str(src_mask_ones) + ' ' + rule_id + '\n')
        

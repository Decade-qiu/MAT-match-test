# 生成指定名称的网络命名空间
> sudo python3 -u build_netspace.py --netspace name
> example: sudo python3 -u build_netspace.py --netspace MAT

# 生成iptbales rule和packets，并记录匹配信息到output文件夹
> name 为网络命名空间名称; a 为生成的rule数量; b 为生成的pkt数量与rule数量比值
> sudo ip netns exec name python3 -u gen_packet_rule.py [--rules_num a] [--pkt_factor b] --netspace name
> example: sudo ip netns exec MAT python3 -u gen_packet_rule.py --rules_num 1000 --pkt_factor 1 --netspace MAT

# 发送数据包，处理匹配信息
> cd ./match_test && sudo ip netns exec MAT python3 -u "./send_pkt.py" && cd ..

# 生成iptables规则和数据
cd ./match_test && sudo python3 -u "./gen_rule_pkt.py" && cd ..

# 配置网络命名空间MAT
cd ./match_test && sudo python3 -u "./build_netspace.py" && cd ..

# 规则写入iptables（网络命名空间为MAT）
cd ./match_test && sudo python3 -u "./set_iptables.py" && cd ..

# 发送数据包，处理匹配信息
cd ./match_test && sudo ip netns exec MAT python3 -u "./send_pkt.py" && cd ..

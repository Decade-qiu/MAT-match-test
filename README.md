### 生成指定名称的网络命名空间
```
sudo python3 -u build_netspace.py --netspace name
```
- name 网络命名空间名称
- example: sudo python3 -u build_netspace.py --netspace MAT

### 生成iptbales rule和packet，并记录对应的匹配信息到output文件夹
```
sudo ip netns exec name python3 -u gen_packet_rule.py [--rules_num a] [--pkt_factor b] --netspace name
```
- name 为网络命名空间名称
- a 为生成的rule数量
- b 为生成的pkt数量与rule数量比值
- example: sudo ip netns exec MAT python3 -u gen_packet_rule.py --rules_num 3000 --pkt_factor 2 --netspace MAT


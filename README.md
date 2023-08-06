### 生成指定名称的网络命名空间
```
sudo python3 -u build_netspace.py --netspace name
```
- example 
```
sudo python3 -u build_netspace.py --netspace MAT
```
- name 网络命名空间名称

### 生成iptbales rule和packet，并记录对应的匹配信息到output文件夹
```
sudo ip netns exec name python3 -u gen_packet_rule.py [--rules_num a] [--pkt_factor b] --netspace name
```
- example 
```
sudo ip netns exec MAT python3 -u gen_packet_rule.py --rules_num 3000 --pkt_factor 2 --netspace MAT
```
- name 为网络命名空间名称
- a 为生成的rule数量
- b 为生成的pkt数量与rule数量比值

### 发送数据包文件进行测试
```
./packets/send pcap_file_path interface_name
```
- example  
```
sudo ./packets/send output/packets.pcap ens33 
```
- pcap_file_path 为pcap数据包文件位置
- interface_name 为指定的发送接口
- 发送出去的数据包格式
```
|---| Ether 14bytes
    |---| Ip 20bytes (`TOS=0xff` `ID=该数据包匹配的Rule编号`)
        |----| Transport 
             |----- udp 8bytes
             |----- tcp 20bytes
```
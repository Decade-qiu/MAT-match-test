# -*- coding: utf-8 -*-
"""
cd ./match_test && sudo ip netns exec MAT python3 -u "./send_pkt.py" && cd ..
cd ./match_test && sudo python3 -u "./send_pkt.py" && cd ..
"""
from time import sleep
from scapy.all import *
from scapy.layers.inet import *
from scapy.contrib.igmp import IGMP
# 配置
conf.L3socket = L3RawSocket 

# debug
x = IP(src='58.249.190.113', dst='128.1.1.1', tos=255, id=222, proto=47)/TCP()
x.show()
send(x)
exit()

# 清空日志  
os.system("truncate -s 0 /var/log/kern.log")

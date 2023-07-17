# -*- coding: utf-8 -*-

"""
cd ./match_test && sudo python3 -u "./build_netspace.py"
"""
import os

cmd = [
    "ip netns add MAT",
    "ip link add veth0 type veth peer name veth1",
    "ip link set veth1 netns MAT",
    "ip netns exec MAT ip addr add 192.168.100.1/24 dev veth1",
    "ip netns exec MAT ip link set veth1 up",
    "ip netns exec MAT ip route add default via 192.168.100.1",
    "ip addr add 192.168.100.2/24 dev veth0",
    "ip link set veth0 up",
    "ip netns exec MAT ifconfig veth1 promisc"
]

for c in cmd:
    status = os.system(c)
    if (status != 0):
        print("Error: {}".format(c))
        break

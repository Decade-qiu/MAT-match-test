# -*- coding: utf-8 -*-
import argparse
import os

parser = argparse.ArgumentParser()
# 网络命名空间名称
parser.add_argument('--netspace', type=str, default="MAT", help='name of netspace')
name = parser.parse_args().netspace
os.system("ip netns del {}".format(name))
cmd = [
    "ip netns add {}".format(name),
    "ip link add veth0 type veth peer name veth1",
    "ip link set veth1 netns {}".format(name),
    "ip netns exec {} ip addr add 192.168.100.1/24 dev veth1".format(name),
    "ip netns exec {} ip link set veth1 up".format(name),
    "ip netns exec {} ip route add default via 192.168.100.1".format(name),
    "ip addr add 192.168.100.2/24 dev veth0",
    "ip link set veth0 up",
    "ip netns exec {} ifconfig veth1 promisc".format(name)
]
for c in cmd:
    status = os.system(c)
    if (status != 0):
        print("Error: {}".format(c))
        break
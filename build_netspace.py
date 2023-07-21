# -*- coding: utf-8 -*-
import argparse
import os

parser = argparse.ArgumentParser()
# 网络命名空间名称
parser.add_argument('--netspace', type=str, default="MAT", help='name of netspace')
name = parser.parse_args().netspace

ret = os.system("ip netns del {}".format(name))
if (ret == 0):
    print("Successfully del {}.".format(name))

cmd = [
    "ip netns add {}".format(name),
    "ip link add veth0_{} type veth peer name veth1_{}".format(name, name),
    "ip link set veth1_{} netns {}".format(name, name),
    "ip netns exec {} ip addr add 192.168.100.1/24 dev veth1_{}".format(name, name),
    "ip netns exec {} ip link set veth1_{} up".format(name, name),
    "ip netns exec {} ip route add default via 192.168.100.1".format(name),
    "ip addr add 192.168.100.2/24 dev veth0_{}".format(name),
    "ip link set veth0_{} up".format(name),
    "ip netns exec {} ifconfig veth1_{} promisc".format(name, name)
]
for idx, c in enumerate(cmd):
    status = os.system(c)
    if (status != 0):
        if (idx == 1):
            os.system("ip link del veth0_{} type veth peer name veth1_{}".format(name, name))
            os.system(c)
            continue
        print("Error: {}".format(c))
        exit()
print("Successfully create {}!".format(name))

# python -u "/home/qzj/src/classbench-ng/tuple_rule.py"
import os

res = []
for i in range(1, 2):
    command = "./classbench generate v4 ./vendor/parameter_files/fw{}_seed".format(i)
    output = os.popen(command).read()
    lines = output.split("\t\n")
    for line in lines:
        fd = line.split("\t")
        fd[0] = fd[0][1:]
        res.append(fd)

print(res[0], len(res))
# python -u "/home/qzj/src/classbench-ng/tuple_rule.py"
import os

res = []
for i in range(1, 2):
    command = "./classbench generate v4 ./vendor/parameter_files/fw{}_seed --count=20".format(i)
    output = os.popen(command).read()
    # output = os.system(command)
    # continue
    lines = output.split("\t\n")
    for line in lines:
        line = line.lstrip().rstrip()
        if (len(line)==0 or line[0] != '@'): continue
        fd = line.split("\t")
        fd[0] = fd[0][1:]
        res.append(fd)

with open("rule_set.txt", 'w') as f:
    for r in res:
        f.writelines(r)
        f.write('\n')

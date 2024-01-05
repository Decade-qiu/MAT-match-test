
# read rule files 
rule_set = []
with open('../output/rule_set', 'r') as file:
    lines = file.readlines()
    for line in lines:
        rule_set.append(line.strip())

src_dic = {}
for rule in rule_set:
    src = rule.split()[0]
    if src not in src_dic:
        src_dic[src] = 1
    else:
        src_dic[src] += 1

for i in src_dic.keys():
    print(i)
    break

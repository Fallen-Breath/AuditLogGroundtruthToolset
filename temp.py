counter = {}

with open('1.txt', 'r', encoding='utf8') as f:
    for line in f.readlines():
        if 'samples' in line:
            t = line.split('samples', 1)[0].split('.', 1)[1]
            amount = int(t.strip())
            func_name = line.split('@', 1)[1].strip()

            counter[func_name] = amount


for func_name in sorted(counter.keys(), key=lambda fn: counter[fn], reverse=True):
    print('{},{}'.format(func_name, counter[func_name]))


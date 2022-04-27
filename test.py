import random

a = 'fbduey'
s = ''
for i in range(45):
    op = random.choice('dyp')
    s += op
    if op != 'p':
        tt = random.choice('wlhwlh$')
        n = random.randint(1, 5 if tt == 'w' else 20)
        s += str(n) + tt
    # s += random.choice(a)

print(s)

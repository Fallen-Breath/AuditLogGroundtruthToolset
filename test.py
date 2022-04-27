import random
import string

chars = string.ascii_letters + string.digits
a = 'fbduey'
s = ''
for i in range(45):
    if random.random() < 0.34:
        op = random.randint(0, 5)
        if op == 0:
            ext = ''
        elif op == 1:
            ext = '+'
        else:
            ext = '+' + str(random.randint(0, 100))
        print('input :e!{} readme.txt[enter]'.format(ext))
    else:
        print('input :f dummy{}.txt[enter]'.format(random.randint(0, 10)))
        print('input i{}[esc]:w![enter]'.format(''.join([random.choice(chars) for i in range(random.randint(5, 20))])))


print(s)

import os.path
import random
import string
from argparse import ArgumentParser
from typing import IO, Callable, List

from common import touch_dir

chars = string.ascii_letters + string.digits
edit_input = list(chars)
edit_input.append(' ')
edit_input.append('[enter]')
edit_input.append('[backspace]')
edit_input.append('[delete]')


class ActionGenerator:
    def __init__(self, writer: IO[str]):
        self.rnd = random.Random()
        self.writer = writer

    def set_seed(self, seed):
        self.rnd.seed(seed)

    def get_file_name(self) -> str:
        return 'dummy{}.txt'.format(self.rnd.randint(0, 10))

    def write_header(self):
        self.writer.write('sleep 5\n')
        self.writer.write('set_key_delay 0.01\n')
        self.writer.write('set_seed {}\n'.format(self.rnd.randint(0, 1000000000)))
        self.writer.write('set_random_key_delay 0 0.05\n')
        self.writer.write('\n')
        self.writer.write('input :e readme.txt[enter]\n')
        self.writer.write('input :f {}[enter]\n'.format(self.get_file_name()))

    def write_footer(self):
        self.writer.write('\n')
        self.writer.write('input :q![enter]\n')

    def run(self, amount: int):
        # reference: https://zhuanlan.zhihu.com/p/51440836
        actions = [
            self.insert, self.insert, self.insert,
            self.save,
            self.move_cursor,
            self.navigate,
            self.scroll_page,
            self.clipboard,
            lambda: self.rnd.choice([self.save_as, self.set_file_name, self.switch_file])(),
            self.sleep
        ]

        self.write_header()
        for i in range(amount):
            action = self.rnd.choice(actions)
            action()
            self.writer.write('\n')
        self.write_footer()

    def _random_times(self, action: Callable[[List[str]], None]) -> str:
        p = min(self.rnd.random(), 0.95)
        seq = []
        while True:
            action(seq)
            if self.rnd.random() >= p:
                break
        return ''.join(seq)

    def insert(self):
        def action(seq: List[str]):
            seq.append(self.rnd.choice(edit_input))

        self.writer.write('# input texts under input mode\n')
        self.writer.write('input {}{}[esc]\n'.format(
            self.rnd.choice(['i', '[insert]']),
            self._random_times(action)
        ))

    def save(self):
        self.writer.write('# save file\n')
        self.writer.write('input :w[enter]\n')

    def set_file_name(self):
        self.writer.write('# set file name\n')
        self.writer.write('input :f {}[enter]\n'.format(self.get_file_name()))

    def save_as(self):
        self.writer.write('# save as another file\n')
        self.writer.write('input :saveas{} {}[enter]\n'.format(
            '!' if self.rnd.random() < 0.9 else '',
            self.get_file_name()
        ))

    def switch_file(self):
        self.writer.write('# switch to another file\n')
        op = random.randint(0, 5)
        ext = {0: '', 1: '+'}.get(op, '+' + str(self.rnd.randint(0, 100)))
        self.writer.write('input :e!{} {}[enter]\n'.format(ext, self.get_file_name()))

    def move_cursor(self):
        def action(seq: List[str]):
            move = random.choice('hljkwWeEbB(){}')
            step = self.rnd.randint(0, 30 if move in 'hljk' else 5)
            seq.append(str(step) if self.rnd.random() < 0.5 else '')
            seq.append(move)

        self.writer.write('# move cursor\n')
        self.writer.write('input {}\n'.format(self._random_times(action)))

    def navigate(self):
        def action(seq: List[str]):
            seq.append('{}%'.format(self.rnd.randint(0, 100)))

        self.writer.write('# navigate to n%\n')
        self.writer.write('input {}\n'.format(self._random_times(action)))

    def scroll_page(self):
        def action(seq: List[str]):
            seq.append(self.rnd.choice('bdfuye'))

        self.writer.write('# page scrolling\n')
        self.writer.write('press [ctrl_left]\n')
        self.writer.write('input {}\n'.format(self._random_times(action)))
        self.writer.write('release [ctrl_left]\n')

    def clipboard(self):
        def action(seq: List[str]):
            op = self.rnd.choice('dyp')
            if op == 'p':
                seq.append(op if self.rnd.random() < 0.5 else op.upper())
            else:
                mode = self.rnd.choice('wlh')
                amount = self.rnd.randint(1, 20 if mode != 'w' else 5)
                if amount == 1:
                    amount_str = ''
                else:
                    amount_str = str(amount)
                seq.append(op + amount_str + mode)

        self.writer.write('# using vim clipboard (copy / paste / cut)\n')
        self.writer.write('input {}\n'.format(self._random_times(action)))

    def sleep(self):
        self.writer.write('# sleep for a white\n')
        self.writer.write('sleep {}\n'.format(round(self.rnd.random() * 2, 3)))


def main():
    parser = ArgumentParser(prog='python action_gen.py')
    parser.add_argument('-o', '--output', default='action.act', help='The file name of the generated action file')
    parser.add_argument('-n', '--number', type=int, default=500, help='The amount of the actions')

    args = parser.parse_args()

    touch_dir(os.path.dirname(args.output))
    with open(args.output, 'w', encoding='utf8') as file:
        gen = ActionGenerator(file)
        gen.run(args.number)


if __name__ == '__main__':
    main()

import collections
import json
import os
from abc import ABC, abstractmethod
from argparse import ArgumentParser
from typing import Dict, Set, Tuple, Literal


class CountItem:
    def __init__(self):
        self.amount = 0
        self.func_name = ''
        self.file_path = ''
        self.call_chains: Set[Tuple[str]] = set()


class HotspotFinder(ABC):
    TEMP_DIR = '.tmp'

    def __init__(self, display_limit: int, csv_output: bool):
        self.display_limit = display_limit
        self.csv_output = csv_output

    @classmethod
    @abstractmethod
    def amount_type(cls) -> str:
        raise NotImplementedError()

    @abstractmethod
    def profile(self, cmd: str) -> bool:
        raise NotImplementedError()

    @abstractmethod
    def analyze(self):
        raise NotImplementedError()

    @staticmethod
    def create(tool_name: Literal['perf', 'callgrind'], display_limit: int, csv_output: bool) -> 'HotspotFinder':
        return {
            'perf': PerfHotspotFinder,
            'callgrind': CallgrindHotspotFinder,
        }[tool_name](display_limit, csv_output)

    @classmethod
    def _touch_temp_dir(cls):
        if not os.path.isdir(cls.TEMP_DIR):
            os.makedirs(cls.TEMP_DIR)

    @classmethod
    def _get_cmd(cls, cmd: str) -> str:
        if cmd:
            return cmd
        else:
            return input('command to profile: ')

    def _show_rank(self, counter: Dict[str, CountItem]):
        total = sum(map(lambda i: i.amount, counter.values()))
        if not self.csv_output:
            print()
            print('Total: {} {}'.format(total, self.amount_type()))
        for idx, func_name in enumerate(sorted(counter.keys(), key=lambda x: counter[x].amount, reverse=True)):
            item = counter[func_name]
            if self.csv_output:
                print('{},{},{}'.format(item.amount, item.amount / total * 100, func_name))
            else:
                print('{:2}. {} {}s ({:.2f}%) @ {}'.format(
                    idx + 1,
                    item.amount,
                    self.amount_type(),
                    item.amount / total * 100,
                    func_name
                ), end='')
                if len(item.call_chains) > 0 and False:
                    print(', (example callchain: {})'.format(' <- '.join(list(item.call_chains)[0])), end='')
                print()

            if idx + 1 == self.display_limit:
                break


class PerfHotspotFinder(HotspotFinder):
    FREQUENCY = 99999
    PERF_FILEPATH = os.path.join(HotspotFinder.TEMP_DIR, 'perf.data')
    JSON_FILEPATH = os.path.join(HotspotFinder.TEMP_DIR, 'perf.json')

    comm: str = ''

    @classmethod
    def amount_type(cls) -> str:
        return 'sample'

    def profile(self, cmd: str) -> bool:
        cmd = self._get_cmd(cmd)
        self.comm = cmd

        rv = os.system('perf record -a -g -e cpu-clock:pppH -F {freq} -o {output} -- {cmd}'.format(
            freq=self.FREQUENCY, output=self.PERF_FILEPATH, cmd=cmd
        ))
        if rv != 0:
            print('Failed to profile with perf, exit')
            return False

        self._touch_temp_dir()

        rv = os.system('perf data convert -i {} --to-json {} --force'.format(self.PERF_FILEPATH, self.JSON_FILEPATH))
        if rv != 0:
            print('Failed to export perf data, exit')
            return False

        return True

    @staticmethod
    def get_function_name(callchain_item: dict) -> str:
        try:
            return callchain_item.get('symbol', callchain_item['ip'])
        except KeyError:
            print('Except when getting function name from {}'.format(callchain_item))
            raise

    def analyze(self):
        counter: Dict[str, CountItem] = collections.defaultdict(CountItem)
        with open(self.JSON_FILEPATH, 'r') as file:
            data = json.load(file)
        comm = set()
        for sample in data['samples']:
            comm.add(sample['comm'])
            if sample['comm'] != self.comm:
                continue
            callchain = sample['callchain']
            if len(callchain) > 0:
                func_name = self.get_function_name(callchain[0])
                counter[func_name].amount += 1
                counter[func_name].func_name = func_name
                counter[func_name].call_chains.add(tuple(map(self.get_function_name, callchain)))
        # print(comm)
        self._show_rank(counter)


class CallgrindHotspotFinder(HotspotFinder):
    PROFILE_FILEPATH = os.path.join(HotspotFinder.TEMP_DIR, 'callgrind.out')
    RESULT_FILEPATH = os.path.join(HotspotFinder.TEMP_DIR, 'result.txt')

    @classmethod
    def amount_type(cls) -> str:
        return 'instruction'

    def profile(self, cmd: str) -> bool:
        cmd = self._get_cmd(cmd)
        self._touch_temp_dir()
        rv = os.system('valgrind --tool=callgrind -q --callgrind-out-file={output} {cmd}'.format(output=self.PROFILE_FILEPATH, cmd=cmd))
        if rv != 0:
            print('Failed to profile with valgrind, exit')
            return False

        rv = os.system('callgrind_annotate {} > {}'.format(self.PROFILE_FILEPATH, self.RESULT_FILEPATH))
        if rv != 0:
            print('Failed to export callgrind data, exit')
            return False

        return True

    def analyze(self):
        counter: Dict[str, CountItem] = {}

        with open(self.RESULT_FILEPATH, 'r', encoding='utf8') as file:
            lines = file.readlines()

        start_flag = False
        divider_line_counter = 0
        for line in lines:
            line = line.strip()
            try:
                if line.replace(' ', '') == 'Irfile:function':
                    start_flag = True
                    continue
                if start_flag and len(line) > 0:
                    if line.startswith('-'):
                        divider_line_counter += 1
                        if divider_line_counter == 2:
                            break
                        continue
                    # 6,543,492 (11.03%)  ???:0x000000000010c510 [/usr/bin/vim.basic]
                    amount, rest = line.split('(', 1)
                    ratio, info = rest.split(')', 1)

                    amount = int(amount.strip().replace(',', ''))
                    ratio = float(ratio.replace('%', ''))
                    info = info.strip()

                    item = CountItem()
                    item.amount = amount
                    t = info.split(':', 1)[1]
                    if ' ' in t:
                        item.func_name, item.file_path = t.split(' ', 1)
                    else:
                        item.func_name = t
                    counter[item.func_name] = item
            except:
                print('Failed to parse line {}'.format(repr(line)))
                raise

        self._show_rank(counter)


def main():
    parser = ArgumentParser(prog='python hotspot_finder.py')
    parser.add_argument('-t', '--tool', default='perf', help='Profile tool to be used. Available options: perf, callgrind. Default: perf')
    parser.add_argument('-l', '--limit', type=int, default=10, help='Maximum amount of hotspot functions to be displayed. Default: 10')
    # parser.add_argument('-p', '--pid', type=int, default=-1, help='Target process pid, optional. When specified, command of the program is not needed')
    parser.add_argument('-c', '--cmd', default='', help='The command of the program to be profiled')
    parser.add_argument('--csv', action='store_true', help='Use csv format to display result')
    result = parser.parse_args()

    finder = HotspotFinder.create(result.tool, result.limit, result.csv)
    if finder.profile(cmd=result.cmd):
        finder.analyze()


if __name__ == '__main__':
    main()

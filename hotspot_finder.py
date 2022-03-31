import collections
import json
import os
from abc import ABC, abstractmethod
from argparse import ArgumentParser
from typing import Dict, Literal, Optional, IO


class CountItem:
    def __init__(self):
        self.amount = 0
        self.func_name = ''
        self.file_path = ''


class HotspotFinder(ABC):
    TEMP_DIR = '.tmp'

    def __init__(self, display_limit: int, quiet: bool):
        self.display_limit: int = display_limit
        self.quiet: bool = quiet
        self.__file: Optional[IO[str]] = None

    def output(self, msg: str):
        if self.__file is not None:
            self.__file.write(msg)
            self.__file.write('\n')

    def set_output_file(self, output_file_name: str):
        self.__file = open(output_file_name, 'w', encoding='utf8')

    def stop(self):
        if self.__file is not None:
            self.__file.close()
            self.__file = None

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
    def create(tool_name: Literal['perf', 'callgrind', 'pin'], display_limit: int, quiet: bool) -> 'HotspotFinder':
        return {
            'perf': PerfHotspotFinder,
            'callgrind': CallgrindHotspotFinder,
            'pin': PinHotSpotFinder,
        }[tool_name](display_limit, quiet)

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

    @staticmethod
    def _get_total(counter: Dict[str, CountItem]) -> int:
        return sum(map(lambda i: i.amount, counter.values()))

    def _show_rank(self, counter: Dict[str, CountItem], *, total_overwrite: Optional[int] = None):
        total = self._get_total(counter) if total_overwrite is None else total_overwrite

        if not self.quiet and not total_overwrite:
            print('Total: {} {}'.format(total, self.amount_type()))

        for idx, func_name in enumerate(sorted(counter.keys(), key=lambda x: counter[x].amount, reverse=True)):
            item = counter[func_name]
            self.output('{},{},{}'.format(item.amount, item.amount / total * 100, func_name))
            if not self.quiet:
                print('{:2}. {} {}s ({:.2f}%) @ {}'.format(
                    idx + 1,
                    item.amount,
                    self.amount_type(),
                    item.amount / total * 100,
                    func_name
                ), end='')
                print()

            if idx + 1 == self.display_limit:
                break


class PerfHotspotFinder(HotspotFinder):
    FREQUENCY = 99999
    PERF_FILEPATH = os.path.join(HotspotFinder.TEMP_DIR, 'perf.data')
    JSON_FILEPATH = os.path.join(HotspotFinder.TEMP_DIR, 'perf.json')

    @classmethod
    def amount_type(cls) -> str:
        return 'sample'

    def profile(self, cmd: str) -> bool:
        cmd = self._get_cmd(cmd)
        self._touch_temp_dir()

        rv = os.system('perf record -g -e cpu-clock:pppH -F {freq} -o {output} -- {cmd}'.format(
            freq=self.FREQUENCY, output=self.PERF_FILEPATH, cmd=cmd
        ))
        if rv != 0:
            print('Failed to profile with perf, exit')
            return False

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
        with open(self.JSON_FILEPATH, 'r') as file:
            data = json.load(file)

        counter: Dict[int, Dict[str, CountItem]] = collections.defaultdict(lambda: collections.defaultdict(CountItem))
        for sample in data['samples']:
            callchain = sample['callchain']
            for depth, cc in enumerate(reversed(callchain)):
                func_name = self.get_function_name(cc)
                counter[depth][func_name].amount += 1
                counter[depth][func_name].func_name = func_name

        for depth in range(10):
            print('===== Depth {} ====='.format(depth))
            self._show_rank(counter[depth], total_overwrite=len(data['samples']))


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
                    info = info.strip()

                    item = CountItem()
                    item.amount = amount
                    t = info.split(':', 1)[1]
                    if ' ' in t:
                        item.func_name, item.file_path = t.split(' ', 1)
                    else:
                        item.func_name = t
                    counter[item.func_name] = item
            except (ValueError, KeyError):
                print('Failed to parse line {}'.format(repr(line)))
                raise

        self._show_rank(counter)


class PinHotSpotFinder(HotspotFinder):
    PINTOOL_OUTPUT_PATH = os.path.join(HotspotFinder.TEMP_DIR, 'pintool.json')

    @classmethod
    def amount_type(cls) -> str:
        return 'sample'

    def profile(self, cmd: str) -> bool:
        cmd = self._get_cmd(cmd)
        self._touch_temp_dir()

        rv = os.system('./pin/pin_root/pin -t ./pin/obj-intel64/SyscallTrace.so -o {output} -- {cmd}'.format(
            output=self.PINTOOL_OUTPUT_PATH, cmd=cmd
        ))
        if rv != 0:
            print('Failed to profile with pin tool SyscallTrace, exit')
            return False
        return True

    def analyze(self):
        with open(self.PINTOOL_OUTPUT_PATH, 'r') as file:
            data: list = json.load(file)

        counter: Dict[str, CountItem] = collections.defaultdict(CountItem)
        for sample in data:
            if sample['type'] != 'syscall':
                continue
            for depth, trace in enumerate(reversed(sample['trace'])):
                func_name = trace.split(' ', 1)[0]
                counter[trace].amount += 1
                counter[trace].func_name = func_name

        self._show_rank(counter)


def main():
    parser = ArgumentParser(prog='python hotspot_finder.py')
    parser.add_argument('-t', '--tool', default='perf', help='Profile tool to be used. Available options: perf, callgrind, pin. Default: perf')
    parser.add_argument('-l', '--limit', type=int, default=20, help='Maximum amount of hotspot functions to be displayed. Default: 10')
    parser.add_argument('-c', '--cmd', default='', help='The command of the program to be profiled. If not specified, you need to input it manually')
    parser.add_argument('-o', '--output', default='', help='The path of the output file in csv format, if specified')
    parser.add_argument('-q', '--quiet', action='store_true', help='Do not print any message unless exception occurs')
    args = parser.parse_args()

    finder = HotspotFinder.create(args.tool, args.limit, args.quiet)
    if args.output:
        finder.set_output_file(args.output)
    if finder.profile(args.cmd):
        finder.analyze()


if __name__ == '__main__':
    main()

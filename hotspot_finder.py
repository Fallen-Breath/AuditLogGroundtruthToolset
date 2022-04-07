import collections
import json
import os
from abc import ABC, abstractmethod
from argparse import ArgumentParser
from typing import Dict, Literal, Optional, IO, Any

from common import TEMP_DIR, SampleTreeNode, HOT_SPOT_BLACKLIST
from ground_truth_generator import ROOT_NODE_NAME

args: Any


class CountItem:
    def __init__(self):
        self.amount = 0
        self.func_name = ''
        self.file_path = ''


class HotspotFinder(ABC):
    def __init__(self, display_limit: int, quiet: bool):
        self.display_limit: int = display_limit
        self.quiet: bool = quiet
        self.__file: Optional[IO[str]] = None
        self.hot_spot_counter: Dict[str, CountItem] = collections.defaultdict(CountItem)
        self.total_overwrite: Optional[int] = None

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
        if not os.path.isdir(TEMP_DIR):
            os.makedirs(TEMP_DIR)

    @classmethod
    def _get_cmd(cls, cmd: str) -> str:
        if cmd:
            return cmd
        else:
            return input('command to profile: ')

    @staticmethod
    def _get_total(counter: Dict[str, CountItem]) -> int:
        return sum(map(lambda i: i.amount, counter.values()))

    def show_rank(self):
        counter = self.hot_spot_counter
        total = self._get_total(counter) if self.total_overwrite is None else self.total_overwrite

        if not self.quiet:
            print('Total: {} {}'.format(total, self.amount_type()))

        for idx, key in enumerate(sorted(counter.keys(), key=lambda x: counter[x].amount, reverse=True)):
            item = counter[key]
            if not self.quiet:
                print('{:2}. {} {}s ({:.2f}%) @ {}'.format(
                    idx + 1,
                    item.amount,
                    self.amount_type(),
                    item.amount / total * 100,
                    item.func_name
                ), end='')
                print()

            if idx + 1 == self.display_limit:
                break

    def print_to_file(self, *, percent: Optional[float] = None, maximum: Optional[int] = None):
        counter = self.hot_spot_counter
        for i, func_name in enumerate(sorted(counter.keys(), key=lambda k: counter[k].amount, reverse=True)):
            if percent is not None and i >= len(counter) * percent:
                break
            if maximum is not None and i >= maximum:
                break
            self.output(func_name)


class PerfHotspotFinder(HotspotFinder):
    FREQUENCY = 99999
    PERF_FILEPATH = os.path.join(TEMP_DIR, 'perf.data')
    JSON_FILEPATH = os.path.join(TEMP_DIR, 'perf.json')

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

        for sample in data['samples']:
            callchain = sample['callchain']
            func_names = set()
            for cc in callchain:
                func_names.add(self.get_function_name(cc))
            for func_name in func_names:
                self.hot_spot_counter[func_name].amount += 1
                self.hot_spot_counter[func_name].func_name = func_name

        self.total_overwrite = len(data['samples'])


class CallgrindHotspotFinder(HotspotFinder):
    PROFILE_FILEPATH = os.path.join(TEMP_DIR, 'callgrind.out')
    RESULT_FILEPATH = os.path.join(TEMP_DIR, 'result.txt')

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
                    self.hot_spot_counter[item.func_name] = item
            except (ValueError, KeyError):
                print('Failed to parse line {}'.format(repr(line)))
                raise


class PinHotSpotFinder(HotspotFinder):
    PINTOOL_OUTPUT_PATH = os.path.join(TEMP_DIR, 'pintool.json')

    @classmethod
    def amount_type(cls) -> str:
        return 'sample'

    def profile(self, cmd: str) -> bool:
        cmd = self._get_cmd(cmd)
        self._touch_temp_dir()

        rv = os.system('./pin/pin_root/pin -t ./pin/obj-intel64/SyscallSampler.so -o {output} -- {cmd}'.format(
            output=self.PINTOOL_OUTPUT_PATH, cmd=cmd
        ))
        if rv != 0:
            print('Failed to profile with pin tool SyscallTrace, exit')
            return False
        return True

    def analyze(self):
        with open(self.PINTOOL_OUTPUT_PATH, 'r') as file:
            samples: list = json.load(file)

        root = SampleTreeNode(ROOT_NODE_NAME)
        for sample in samples:
            if sample['type'] == 'syscall':
                traces = []
                for trace in sample['trace']:
                    if not trace.split(' at ', 1)[1].startswith('/lib/'):
                        traces.append(trace)
                root.add_traces(traces)

        if args.kfactor > 0:
            before = root.get_tree_size()
            root.trim(args.kfactor)
            after = root.get_tree_size()
            # print('trimming with k={}, {} -> {} ({:.2f}%)'.format(args.kfactor, before, after, after / before * 100))

        # print('========== Sampling Tree ==========')
        # root.dump()
        # print('===================================')

        def visitor(node: SampleTreeNode):
            name = node.to_str()
            if name not in HOT_SPOT_BLACKLIST:
                self.hot_spot_counter[name].amount += 1
                self.hot_spot_counter[name].func_name = name
        root.visit_tree(visitor)

        self.total_overwrite = len(samples)


def main():
    parser = ArgumentParser(prog='python hotspot_finder.py')
    parser.add_argument('-t', '--tool', default='perf', help='Profile tool to be used. Available options: perf, callgrind, pin. Default: perf')
    parser.add_argument('-l', '--limit', type=int, default=50, help='Maximum amount of hotspot functions to be displayed. Default: 50')
    parser.add_argument('-c', '--cmd', help='The command of the program to be profiled. If not specified, you need to input it manually')
    parser.add_argument('-o', '--output', default='hotspots.txt', help='The path of the output file, if specified')
    parser.add_argument('-r', '--report', action='store_true', help='Report a read-able result to console')
    parser.add_argument('-k', '--kfactor', type=int, default=1, help='The value k used in subtree trimming with tool pin, where nodes with <= k direct children will be trimmed. Default: 1')
    parser.add_argument('-q', '--quiet', action='store_true', help='Do not print any message unless exception occurs')

    global args
    args = parser.parse_args()

    finder = HotspotFinder.create(args.tool, args.limit, args.quiet)
    if args.output:
        finder.set_output_file(args.output)
    if finder.profile(args.cmd):
        finder.analyze()
        if args.report:
            finder.show_rank()
        finder.print_to_file(maximum=args.limit)


if __name__ == '__main__':
    main()

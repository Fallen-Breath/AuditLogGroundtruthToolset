import os
import sys
from argparse import ArgumentParser
from typing import Any

from action_sim import ActionSimulator
from common import TEMP_DIR, HERE

PIN_TOOL_NAME = 'SyscallTracer'
args: Any


def _touch_temp_dir():
    if not os.path.isdir(TEMP_DIR):
        os.makedirs(TEMP_DIR)


def pin_trace():
    pin_exe = os.path.join(HERE, 'pintool', 'pin_root', 'pin')
    pin_tool = os.path.join(HERE, 'pintool', 'obj-intel64', '{}.so'.format(PIN_TOOL_NAME))
    pin_args = {
        'i': os.path.join(HERE, args.input),
        'o': os.path.join(HERE, args.output),
    }

    command = '{pin_exe} -t {pin_tool}{args} -- {cmd}'.format(
        pin_exe=pin_exe,
        pin_tool=pin_tool,
        args=''.join(map(lambda k: ' -{k}{v}'.format(k=k, v=(' ' + pin_args[k]) if pin_args[k] is not None else ''), pin_args.keys())),
        cmd=args.cmd
    )

    sim = ActionSimulator(command, cwd=args.wd)
    if len(args.action) > 0:
        sim.read_file(args.action)
    rv = sim.run()
    if rv != 0:
        print('Pin tool execution failed! return value: {}'.format(rv))
        sys.exit(1)


def main():
    parser = ArgumentParser(prog='python ground_truth_generator.py')
    parser.add_argument('-c', '--cmd', help='The command of the program to be profiled')
    parser.add_argument('--wd', default='.', help='The path of the working directory. Default: current directory')
    parser.add_argument('-i', '--input', default='hotspots.txt', help='The path to the hotspot file. Default: hotspots.txt')
    parser.add_argument('-o', '--output', default='pintool_trace.json', help='The path of the output trace file. Default: pintool_trace.json')
    parser.add_argument('-a', '--action', default='', help='The action file for automatically executing the program')

    global args
    args = parser.parse_args()

    _touch_temp_dir()

    pin_trace()


if __name__ == '__main__':
    main()

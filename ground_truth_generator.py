import json
import os
import sys
from argparse import ArgumentParser
from enum import Enum, auto
from typing import List, Dict, Any, Collection

from common import TEMP_DIR, HOT_SPOT_FILE_PATH, AbstractTreeNode, ROOT_NODE_NAME

generator_args: Any
SYSCALL_SAMPLE_RESULT = os.path.join(TEMP_DIR, 'pintool_sample.json')
SYSCALL_TRACE_RESULT = os.path.join(TEMP_DIR, 'pintool_trace.json')


def _touch_temp_dir():
    if not os.path.isdir(TEMP_DIR):
        os.makedirs(TEMP_DIR)


class TracingTreeNode(AbstractTreeNode):
    class Type(Enum):
        root = auto()
        syscall = auto()
        function = auto()

    def __init__(self, type_: Type, value: str):
        super().__init__()
        self.type = type_
        self.value = value
        self.children_list: List['TracingTreeNode'] = []
        self.depth = 0
        self.max_child_distance = 0

    def add_child(self, child_node: 'TracingTreeNode'):
        super().add_child(child_node)
        self.children_list.append(child_node)

    def remove_child(self, child_node: 'TracingTreeNode'):
        try:
            self.children_list.remove(child_node)
        except ValueError:
            pass

    def clean_children(self):
        self.children_list.clear()

    def should_trim(self, k: int) -> bool:
        return super().should_trim(k) or (super().should_trim(k * 5) and all(map(lambda c: c.is_leaf(), self.children)))

    def __finalize(self, depth: int) -> int:
        self.depth = depth
        max_depth = depth
        for child in self.children:
            child_depth = child.__finalize(depth + 1)
            max_depth = max(max_depth, child_depth)
        self.max_child_distance = max_depth - self.depth
        return max_depth

    def finalize(self):
        self.__finalize(0)

    @property
    def children(self) -> Collection['TracingTreeNode']:
        return self.children_list

    def to_str(self) -> str:
        return '{}: {}'.format(self.type.name, self.value) if self.type != self.Type.root else ROOT_NODE_NAME

    def collect(self, node_list: list) -> dict:
        self_data_basic = {
            'type': self.type.name,
            'call_depth': self.depth,
            'max_child_distance': self.max_child_distance
        }

        if self.type == TracingTreeNode.Type.syscall:
            self_data_basic['syscall'] = self.value
        elif self.type == TracingTreeNode.Type.function:
            self_data_basic['function'] = self.value

        self_data_full = self_data_basic.copy()
        child_list = []
        for child in self.children:
            child_list.append(child.collect(node_list))
        self_data_full['children'] = child_list

        if not self.is_root() and not self.is_leaf():
            self_data_simple_children = self_data_basic.copy()
            self_data_simple_children['children'] = list(map(lambda c: '{}:{}'.format(c.type.name, c.value), self.children))
            node_list.append(self_data_simple_children)

        return self_data_full


def pin(tool_name: str, output_file: str, args: Dict[str, Any]) -> List[dict]:
    args['o'] = output_file
    command = './pin/pin_root/pin -t /pin/obj-intel64/{tool}.so{args} -- {cmd}'.format(
        tool=tool_name,
        args=''.join(map(lambda k: ' -{k}{v}'.format(k=k, v=(' ' + args[k]) if args[k] is not None else ''), args.keys())),
        cmd=generator_args.cmd
    )

    rv = os.system(command)
    if rv != 0:
        print('Pin tool execution failed! return value: {}'.format(rv))
        sys.exit(1)

    with open(output_file, 'r', encoding='utf8') as file:
        return json.load(file)


def do_trace():
    tracing = pin('SyscallTracer', SYSCALL_TRACE_RESULT, {'t': HOT_SPOT_FILE_PATH})
    root = TracingTreeNode(TracingTreeNode.Type.root, '')
    node = root
    for sample in tracing:
        if sample['type'] == 'syscall':
            node.add_child(TracingTreeNode(TracingTreeNode.Type.syscall, sample['syscallName']))
        elif sample['type'] == 'func_start':
            child = TracingTreeNode(TracingTreeNode.Type.function, sample['funcName'])
            node.add_child(child)
            node = child
        elif sample['type'] == 'func_end':
            node = node.father if node.father is not None else node
        else:
            print('Unknown type: {}'.format(sample['type']))

    root.trim(generator_args.kfactor)
    root.finalize()

    # print('========== Tracing Tree ==========')
    # root.dump()
    # print('===================================')

    lst = []
    dt = root.collect(lst)

    with open('ground_truth.nodes.json', 'w', encoding='utf8') as file:
        json.dump(lst, file, ensure_ascii=False, indent=2)

    with open('ground_truth.tree.json', 'w', encoding='utf8') as file:
        json.dump(dt, file, ensure_ascii=False, indent=2)

    with open('ground_truth.tree.txt', 'w', encoding='utf8') as file:
        root.visit_tree(lambda n: file.write('{}{}\n'.format('    ' * n.depth, n.to_str())))


def main():
    parser = ArgumentParser(prog='python ground_truth_generator.py')
    parser.add_argument('-c', '--cmd', help='The command of the program to be profiled')
    parser.add_argument('-i', '--input', default='hotspots.txt', help='The path to the hotspot file. Default: hotspots.txt')
    # parser.add_argument('-o', '--output', default='ground_truth.json', help='The path of the output file in csv format, if specified')
    parser.add_argument('-k', '--kfactor', type=int, default=1, help='The value k used in subtree trimming, where nodes with <= k direct children will be trimmed. Default: 1')
    parser.add_argument('-q', '--quiet', action='store_true', help='Do not print any message unless exception occurs')
    global generator_args
    generator_args = parser.parse_args()

    _touch_temp_dir()

    do_trace()


if __name__ == '__main__':
    main()

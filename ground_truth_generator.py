import collections
import json
import os
import sys
from argparse import ArgumentParser
from enum import Enum, auto
from typing import List, Dict, Any, Collection, Callable, Optional

from common import TEMP_DIR, AbstractTreeNode, ROOT_NODE_NAME

args: Any
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
        self.tree_data: Optional[dict] = None
        self.tree_data_simple: Optional[dict] = None

    @property
    def children(self) -> Collection['TracingTreeNode']:
        return self.children_list

    def to_str(self) -> str:
        return '{}: {}'.format(self.type.name, self.value) if self.type != self.Type.root else ROOT_NODE_NAME

    def add_child(self, child_node: 'TracingTreeNode'):
        super().add_child(child_node)
        self.children_list.append(child_node)

    def insert_children(self, child_nodes: Collection['TracingTreeNode'], idx: int):
        first_half = self.children_list[:idx]
        second_half = self.children_list[idx:]
        self.children_list.clear()
        for node in first_half:
            self.add_child(node)
        for child_node in child_nodes:
            self.add_child(child_node)
        for node in second_half:
            self.add_child(node)

    def remove_child(self, child_node: 'TracingTreeNode') -> Optional[int]:
        try:
            idx = self.children_list.index(child_node)
            self.children_list.pop(idx)
            return idx
        except ValueError:
            return None

    def clean_children(self):
        self.children_list.clear()

    def should_trim(self, k: int) -> bool:
        return super().should_trim(k) or (super().should_trim(args.kleaf) and all(map(lambda c: c.is_leaf(), self.children)))

    def finalize(self):
        self.__collect_depth(0)
        self.__collect_data()

    def __collect_depth(self, depth: int) -> int:
        self.depth = depth
        max_depth = depth
        for child in self.children:
            child_depth = child.__collect_depth(depth + 1)
            max_depth = max(max_depth, child_depth)
        self.max_child_distance = max_depth - self.depth
        return max_depth

    def __collect_data(self) -> dict:
        data_basic = {
            'type': self.type.name,
            'call_depth': self.depth,
            'max_child_distance': self.max_child_distance
        }

        if self.type == TracingTreeNode.Type.syscall:
            data_basic['syscall'] = self.value
        elif self.type == TracingTreeNode.Type.function:
            data_basic['function'] = self.value

        self.tree_data = data_basic.copy()
        child_list = []
        for child in self.children:
            child_list.append(child.__collect_data())
        self.tree_data['children'] = child_list

        if not self.is_root() and not self.is_leaf():
            self.tree_data_simple = data_basic.copy()
            self.tree_data_simple['children'] = list(map(lambda c: '{}:{}'.format(c.type.name, c.value), self.children))

        return self.tree_data


def pin(tool_name: str, output_file: str, pin_args: Dict[str, Any]):
    pin_args['o'] = output_file
    command = './pin/pin_root/pin -t /pin/obj-intel64/{tool}.so{args} -- {cmd}'.format(
        tool=tool_name,
        args=''.join(map(lambda k: ' -{k}{v}'.format(k=k, v=(' ' + pin_args[k]) if pin_args[k] is not None else ''), pin_args.keys())),
        cmd=args.cmd
    )

    rv = os.system(command)
    if rv != 0:
        print('Pin tool execution failed! return value: {}'.format(rv))
        sys.exit(1)


def aggregate_tree(root: TracingTreeNode) -> dict:
    def visitor(node: TracingTreeNode):
        if not node.is_root() and node.tree_data_simple is not None:
            result[node.max_child_distance].append(node.tree_data_simple)

    result: Dict[int, List[dict]] = collections.defaultdict(list)
    root.visit_tree(visitor)
    return dict(map(
        lambda k: (k, result[k]),
        sorted(result.keys())
    ))


def print_tree(root: AbstractTreeNode, writer: Callable[[str], Any]):
    root.visit_tree(lambda n: writer('{}{}\n'.format('    ' * n.depth, n.to_str())))


def do_trace():
    if not args.skip_pintool:
        pin('SyscallTracer', SYSCALL_TRACE_RESULT, {'i': args.input})
    with open(SYSCALL_TRACE_RESULT, 'r', encoding='utf8') as file:
        tracing: List[dict] = json.load(file)

    root = TracingTreeNode(TracingTreeNode.Type.root, '')
    node = root
    syscall_set = set()
    func_name_set = set()
    for sample in tracing:
        if sample['type'] == 'syscall':
            node.add_child(TracingTreeNode(TracingTreeNode.Type.syscall, sample['syscallName']))
            syscall_set.add(sample['syscallName'])
        elif sample['type'] == 'func_start':
            child = TracingTreeNode(TracingTreeNode.Type.function, sample['funcName'])
            node.add_child(child)
            node = child
            func_name_set.add(sample['funcName'])
        elif sample['type'] == 'func_end':
            node = node.father if node.father is not None else node
        else:
            print('Unknown type: {}'.format(sample['type']))

    tree_nonleaf_size_before_trim = root.get_tree_size(filter_=lambda n: not n.is_leaf())
    tree_size_before_trim = root.get_tree_size()

    root.finalize()
    with open('{}.raw_tree.txt'.format(args.output), 'w', encoding='utf8') as file:
        print_tree(root, file.write)

    root.trim(args.kfactor)
    root.finalize()

    trimmed_func_name_set = set()
    root.visit_tree(lambda n: (trimmed_func_name_set.add(n.value) if n.type == TracingTreeNode.Type.function else None))

    with open('{}.nodes.json'.format(args.output), 'w', encoding='utf8') as file:
        lst = list(filter(
            lambda data: data is not None,
            map(lambda n: n.tree_data_simple, root.get_all_nodes())
        ))
        json.dump(lst, file, ensure_ascii=False, indent=2)

    with open('{}.tree.json'.format(args.output), 'w', encoding='utf8') as file:
        json.dump(root.tree_data, file, ensure_ascii=False, indent=2)

    with open('{}.trimmed_tree.txt'.format(args.output), 'w', encoding='utf8') as file:
        print_tree(root, file.write)

    with open('{}.summary.txt'.format(args.output), 'w', encoding='utf8') as file:
        file.write('k = {}\n'.format(args.kfactor))
        file.write('k_leaf = {}\n'.format(args.kleaf))
        file.write('Pintool tracer result line count: {}\n'.format(len(tracing)))
        file.write('Tree node amount: {}\n'.format(tree_size_before_trim))
        file.write('Tree node amount (non-leaf): {}\n'.format(tree_nonleaf_size_before_trim))
        file.write('Tree node amount (trimmed): {}\n'.format(root.get_tree_size()))
        file.write('Tree node amount (trimmed, non-leaf): {}\n'.format(root.get_tree_size(filter_=lambda n: not n.is_leaf())))
        file.write('Different syscall amount: {}\n'.format(len(syscall_set)))
        file.write('Different function amount: {}\n'.format(len(func_name_set)))
        file.write('Different function amount (trimmed): {}\n'.format(len(trimmed_func_name_set)))

    aggregation_data = aggregate_tree(root)
    with open('{}.aggregation.json'.format(args.output), 'w', encoding='utf8') as file:
        json.dump(aggregation_data, file, ensure_ascii=False, indent=2)


def main():
    parser = ArgumentParser(prog='python ground_truth_generator.py')
    parser.add_argument('-c', '--cmd', help='The command of the program to be profiled')
    parser.add_argument('-i', '--input', default='hotspots.txt', help='The path to the hotspot file. Default: hotspots.txt')
    parser.add_argument('-o', '--output', default='ground_truth', help='The basic name of output files')
    parser.add_argument('-k', '--kfactor', type=int, default=1, help='The factor k used in subtree trimming, where nodes with <= k direct children will be trimmed. Default: 1')
    parser.add_argument('--kl', '--kleaf', type=int, default=-1, help='The factor k, but used for a node who has its all children be leaf. Default: -1, resulting using the same value as kfactor')
    parser.add_argument('--skip-pintool', action='store_true', help='Do not run pin tool. Useful when you want to reuse the previous generated data')
    parser.add_argument('-q', '--quiet', action='store_true', help='Do not print any message unless exception occurs')
    global args
    args = parser.parse_args()
    args.kleaf = args.kl
    if args.kleaf < 0:
        args.kleaf = args.kfactor

    _touch_temp_dir()

    do_trace()


if __name__ == '__main__':
    main()

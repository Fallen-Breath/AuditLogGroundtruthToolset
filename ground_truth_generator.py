import collections
import json
import os
import time
from argparse import ArgumentParser
from enum import Enum, auto
from typing import List, Dict, Any, Collection, Callable, Optional

from common import TEMP_DIR, AbstractTreeNode, ROOT_NODE_NAME

args: Any


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
        return '{}:{}'.format(self.type.name, self.value) if self.type != self.Type.root else ROOT_NODE_NAME

    def add_child(self, child_node: 'TracingTreeNode'):
        super().add_child(child_node)
        self.children_list.append(child_node)

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


def aggregate_tree(root: TracingTreeNode) -> dict:
    """
    The tree structure will be modified
    Use as the last step
    """
    def has_compound_child(node: AbstractTreeNode):
        return any(map(lambda n: not n.is_leaf(), node.children))

    result: Dict[int, list] = collections.defaultdict(list)
    level: int = 0
    while has_compound_child(root):
        def visit(node: TracingTreeNode):
            if node.is_leaf():
                log_this_level.append(node.to_str())
                return
            if has_compound_child(node):
                for child in node.children:
                    visit(child)
            else:
                # aggregate this node
                log_this_level.append({
                    node.to_str(): list(map(lambda n: n.to_str(), node.children))
                })
                node.clean_children()

        log_this_level = []
        visit(root)
        result[level] = log_this_level
        level += 1

    return result


def print_tree(root: AbstractTreeNode, writer: Callable[[str], Any]):
    root.visit_tree(lambda n: writer('{}{}\n'.format('    ' * n.depth, n.to_str())))


def do_trace():
    with open(args.input, 'r', encoding='utf8') as file:
        tracing: List[dict] = json.load(file)

    output_dir = os.path.dirname(args.output)
    if len(output_dir) > 0 and not os.path.isdir(output_dir):
        os.makedirs(output_dir)

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
        file.write('Ground truth generated at {}\n'.format(time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())))
        file.write('k = {}\n'.format(args.kfactor))
        file.write('k_leaf = {}\n'.format(args.kleaf))
        file.write('PinTool tracer result line count: {}\n'.format(len(tracing)))
        file.write('Tree node amount: {}\n'.format(tree_size_before_trim))
        file.write('Tree node amount (leaf): {}\n'.format(tree_size_before_trim - tree_nonleaf_size_before_trim))
        file.write('Tree node amount (non-leaf): {}\n'.format(tree_nonleaf_size_before_trim))
        file.write('Tree node amount (trimmed): {}\n'.format(root.get_tree_size()))
        file.write('Tree node amount (trimmed, non-leaf): {}\n'.format(root.get_tree_size(filter_=lambda n: not n.is_leaf())))
        file.write('Maximum node depth (trimmed): {}\n'.format(root.max_child_distance))
        file.write('Different syscall amount: {}\n'.format(len(syscall_set)))
        file.write('Different function amount: {}\n'.format(len(func_name_set)))
        file.write('Different function amount (trimmed): {}\n'.format(len(trimmed_func_name_set)))

    aggregation_data = aggregate_tree(root)
    with open('{}.aggregation.json'.format(args.output), 'w', encoding='utf8') as file:
        json.dump(aggregation_data, file, ensure_ascii=False, indent=2)


def main():
    parser = ArgumentParser(prog='python ground_truth_generator.py')
    parser.add_argument('-i', '--input', default='pintool_trace.json', help='The path to the trace file. Default: pintool_trace.json')
    parser.add_argument('-o', '--output', default='ground_truth', help='The basic name of output files. Default: ground_truth, with which output files will be like ground_truth.tree.json')
    parser.add_argument('-k', '--kfactor', type=int, default=2, help='The factor k used in subtree trimming, where nodes with <= k direct children will be trimmed. Default: 2')
    parser.add_argument('--kl', '--kleaf', type=int, default=4, help='The factor k, but used for a node who has its all children be leaf. Default: 4')
    global args
    args = parser.parse_args()
    args.kleaf = args.kl
    if args.kleaf < 0:
        args.kleaf = args.kfactor

    _touch_temp_dir()

    do_trace()


if __name__ == '__main__':
    main()

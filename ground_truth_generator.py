import json
import os
import sys
from abc import ABC
from argparse import ArgumentParser
from typing import Optional, List, Dict, Any, Callable, Set

generator_args: Any
TEMP_DIR = '.tmp'
SYSCALL_SAMPLE_RESULT = os.path.join(TEMP_DIR, 'pintool_1.json')
EXECUTION_RESULT = os.path.join(TEMP_DIR, 'pintool_2.json')
HOT_SPOT_FUNC_NAMES = os.path.join(TEMP_DIR, 'hotspots.txt')


def _touch_temp_dir():
    if not os.path.isdir(TEMP_DIR):
        os.makedirs(TEMP_DIR)


class AbstractTreeNode(ABC):
    def __init__(self, key: str):
        self.key: str = key
        self.father: Optional['AbstractTreeNode'] = None
        self.children: Dict[str, 'AbstractTreeNode'] = {}

    ########################
    # Tree functionalities #
    ########################

    def set_father(self, father_node: Optional['AbstractTreeNode']):
        self.father = father_node

    def add_child(self, child_node: 'AbstractTreeNode'):
        self.children[child_node.key] = child_node
        child_node.set_father(self)

    def visit_tree(self, consumer: Callable[['AbstractTreeNode'], Any]):
        consumer(self)
        for child in self.children.values():
            child.visit_tree(consumer)

    ########################
    #      Properties      #
    ########################

    @property
    def children_size(self) -> int:
        return len(self.children)

    def is_root(self) -> bool:
        return self.father is None

    def is_leaf(self) -> bool:
        return self.children_size == 0

    ########################
    #    Info Displaying   #
    ########################

    def to_str(self) -> str:
        return self.key

    def _dump(self, writer: Callable[[str, int], Any], depth: int):
        writer(self.to_str(), depth)
        for child in self.children.values():
            child._dump(writer, depth + 1)

    def dump(self, writer: Optional[Callable[[str], Any]] = None):
        if writer is None:
            def writer(s: str, depth: int):
                print('{}{}'.format(' ' * (depth * 2), s))
        self._dump(writer, 0)


class SampleTree(AbstractTreeNode):
    children: Dict[str, 'SampleTree'] = {}

    def __init__(self, trace_entry: str):
        super().__init__(trace_entry)

    def __add_traces(self, traces: List[str], idx: int):
        if idx >= len(traces):
            return
        trace = traces[idx].split('+', 1)[0]
        if trace in self.children:
            node = self.children[trace]
        else:
            node = SampleTree(trace)
            self.add_child(node)
        node.__add_traces(traces, idx + 1)

    def add_traces(self, traces: List[str]):
        self.__add_traces(traces, 0)

    def trim(self, k: int):
        for child in self.children.values():
            child.trim(k)
        if self.children_size <= k:
            children = list(self.children.values())
            self.children.clear()
            for child in children:
                for grandchild in child.children.values():
                    self.add_child(grandchild)


class ExecutionTree(AbstractTreeNode):
    pass


def pin(output_file: str, args: Dict[str, Any]) -> List[dict]:
    args['o'] = output_file
    command = './pin/pin_root/pin -t /pin/obj-intel64/SyscallTrace.so{args} -- {cmd}'.format(
        args=''.join(map(lambda k: ' -{k}{v}'.format(k=k, v=(' ' + args[k]) if args[k] is not None else ''), args.keys())),
        cmd=generator_args.cmd
    )

    rv = os.system(command)
    if rv != 0:
        print('Pin tool execution failed! return value: {}'.format(rv))
        sys.exit(1)

    with open(output_file, 'r', encoding='utf8') as file:
        return json.load(file)


def generate():
    samples = pin(SYSCALL_SAMPLE_RESULT, {'s': None})
    root = SampleTree('#ROOT')
    for sample in samples:
        if sample['type'] == 'syscall':
            root.add_traces(sample['trace'])
    root.trim(generator_args.kfactor)
    root.dump()

    func_names: Set[str] = set()
    root.visit_tree(lambda node: func_names.add(node.to_str()))
    func_names.remove(root.to_str())

    with open(HOT_SPOT_FUNC_NAMES, 'w', encoding='utf8') as file:
        for func_name in func_names:
            file.write(func_name)
            file.write('\n')

    executions = pin(EXECUTION_RESULT, {'t': HOT_SPOT_FUNC_NAMES})


def main():
    parser = ArgumentParser(prog='python ground_truth_generator.py')
    parser.add_argument('-c', '--cmd', help='The command of the program to be profiled')
    parser.add_argument('-o', '--output', default='ground_truth.json', help='The path of the output file in csv format, if specified')
    parser.add_argument('-k', '--kfactor', type=int, default=1, help='Mww. Default: 1')
    parser.add_argument('-q', '--quiet', action='store_true', help='Do not print any message unless exception occurs')
    global generator_args
    generator_args = parser.parse_args()

    _touch_temp_dir()

    generate()


if __name__ == '__main__':
    main()

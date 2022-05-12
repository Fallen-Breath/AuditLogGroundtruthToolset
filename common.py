import os
from abc import ABC, abstractmethod
from typing import Optional, Any, Callable, Collection, List, Dict

HERE = os.path.abspath(os.path.dirname(__file__))
TEMP_DIR = os.path.join(HERE, '.tmp')
HOT_SPOT_FILE_PATH = os.path.join(TEMP_DIR, 'hotspots.txt')
ROOT_NODE_NAME = '#ROOT'
HOT_SPOT_BLACKLIST = {ROOT_NODE_NAME, '.text'}


def touch_dir(dir_path: str):
    if dir_path == '':
        dir_path = '.'
    if not os.path.isdir(dir_path):
        os.makedirs(dir_path)


class AbstractTreeNode(ABC):
    def __init__(self):
        self.father: Optional['AbstractTreeNode'] = None

    @property
    @abstractmethod
    def children(self) -> Collection['AbstractTreeNode']:
        raise NotImplementedError()

    ########################
    # Tree functionalities #
    ########################

    def __set_father(self, father_node: Optional['AbstractTreeNode']):
        self.father = father_node

    @abstractmethod
    def add_child(self, child_node: 'AbstractTreeNode'):
        child_node.__set_father(self)

    @abstractmethod
    def clean_children(self):
        raise NotImplementedError()

    def get_tree_size(self, filter_: Optional[Callable] = None) -> int:
        def visitor(node):
            nonlocal counter
            if filter_ is None or filter_(node):
                counter += 1

        counter = 0
        self.visit_tree(visitor)
        return counter

    def visit_tree(self, visitor: Callable):
        visitor(self)
        for child in self.children:
            child.visit_tree(visitor)

    def get_all_nodes(self):
        nodes = []
        self.visit_tree(lambda node: nodes.append(node))
        return nodes

    def should_trim(self, k: int) -> bool:
        return self.children_size <= k

    def trim(self, k: int):
        children_list = list(self.children)
        self.clean_children()
        for child in children_list:
            child.trim(k)
            if not child.is_leaf() and child.should_trim(k):
                for grand_child in child.children:
                    self.add_child(grand_child)
            else:
                self.add_child(child)

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

    @abstractmethod
    def to_str(self) -> str:
        raise NotImplementedError()

    def _dump(self, writer: Callable[[str, int], Any], depth: int):
        writer(self.to_str(), depth)
        for child in self.children:
            child._dump(writer, depth + 1)

    def dump(self, writer: Optional[Callable[[str], Any]] = None):
        if writer is None:
            def writer(s: str, depth: int):
                print('{}{}'.format(' ' * (depth * 2), s))
        self._dump(writer, 0)


class SampleTreeNode(AbstractTreeNode):
    def __init__(self, trace_entry: str):
        super().__init__()
        self.trace_entry = trace_entry
        self.sample_count = 0
        self.children_map: Dict[str, 'SampleTreeNode'] = {}

    @property
    def children(self) -> Collection['SampleTreeNode']:
        return self.children_map.values()

    def add_child(self, child_node: 'SampleTreeNode'):
        super().add_child(child_node)
        self.children_map[child_node.trace_entry] = child_node

    def clean_children(self):
        self.children_map.clear()

    def to_str(self) -> str:
        return self.trace_entry

    def __add_traces(self, traces: List[str], idx: int):
        self.sample_count += 1
        if idx >= len(traces):
            return
        trace = traces[idx].split('+', 1)[0]
        if trace in self.children_map:
            node = self.children_map[trace]
        else:
            node = SampleTreeNode(trace)
            self.add_child(node)
        node.__add_traces(traces, idx + 1)

    def add_traces(self, traces: List[str]):
        self.__add_traces(traces, 0)

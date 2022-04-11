import os
from abc import ABC, abstractmethod
from typing import Optional, Any, Callable, Collection, List, Dict

TEMP_DIR = '.tmp'
HOT_SPOT_FILE_PATH = os.path.join(TEMP_DIR, 'hotspots.txt')
ROOT_NODE_NAME = '#ROOT'
HOT_SPOT_BLACKLIST = {ROOT_NODE_NAME, '.text'}


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
    def insert_children(self, child_nodes: Collection['AbstractTreeNode'], idx: int):
        raise NotImplementedError()

    @abstractmethod
    def remove_child(self, child_node: 'AbstractTreeNode') -> Optional[int]:
        raise NotImplementedError()

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
        for child in list(self.children):
            child.trim(k)
        if not self.is_root() and not self.is_leaf() and self.should_trim(k):
            idx = self.father.remove_child(self)
            self.father.insert_children(self.children, idx)

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
        self.children_map: Dict[str, 'SampleTreeNode'] = {}

    @property
    def children(self) -> Collection['SampleTreeNode']:
        return self.children_map.values()

    def add_child(self, child_node: 'SampleTreeNode'):
        super().add_child(child_node)
        self.children_map[child_node.trace_entry] = child_node

    def insert_children(self, child_nodes: Collection['SampleTreeNode'], idx: Optional[int] = None):
        first_half = []
        second_half = []
        for i, node in enumerate(self.children_map.values()):
            if i < idx:
                first_half.append(node)
            else:
                second_half.append(node)
        self.children_map.clear()
        for node in first_half:
            self.add_child(node)
        for child_node in child_nodes:
            self.add_child(child_node)
        for node in second_half:
            self.add_child(node)

    def remove_child(self, child_node: 'SampleTreeNode') -> Optional[int]:
        try:
            rv = list(self.children_map.keys()).index(child_node.trace_entry)
        except ValueError:
            rv = None
        self.children_map.pop(child_node.trace_entry, None)
        return rv

    def clean_children(self):
        self.children_map.clear()

    def to_str(self) -> str:
        return self.trace_entry

    def __add_traces(self, traces: List[str], idx: int):
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

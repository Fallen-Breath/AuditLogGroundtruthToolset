import json
import os

from common import ROOT_NODE_NAME
from hotspot_finder import HotspotFinder, SampleTreeNode, HOT_SPOT_BLACKLIST


class Arg:
	kfactor = 1


args = Arg()


class MultiPinHotSpotFinder(HotspotFinder):
	def __init__(self, display_limit: int, quiet: bool):
		super().__init__(display_limit, quiet)
		self.root = SampleTreeNode(ROOT_NODE_NAME)
		self.sample_amount = 0

	@classmethod
	def amount_type(cls) -> str:
		return 'sample'

	def profile(self, cmd: str) -> bool:
		pass

	def accept_sample(self, sample: dict):
		if sample['type'] == 'syscall':
			traces = []
			for trace in sample['trace']:
				if not trace.split(' at ', 1)[1].startswith('/lib/'):
					traces.append(trace)
			self.root.add_traces(traces)
		self.sample_amount += 1

	def analyze(self):
		root = self.root

		if args.kfactor > 0:
			before = root.get_tree_size()
			root.trim(args.kfactor)
			after = root.get_tree_size()

		# print('========== Sampling Tree ==========')
		# root.dump()
		# print('===================================')

		def visitor(node: SampleTreeNode):
			name = node.to_str()
			if name not in HOT_SPOT_BLACKLIST:
				self.hot_spot_counter[name].amount += node.counter
				self.hot_spot_counter[name].func_name = name
		root.visit_tree(visitor)

		self.total_overwrite = self.sample_amount


def main():
	dir_path = 'vimtest'
	finder = MultiPinHotSpotFinder(10000, False)
	finder.set_output_file('vimtest_all.txt')
	for file_name in os.listdir(dir_path):
		if file_name.endswith('.json'):
			print(file_name)
			file_path = os.path.join(dir_path, file_name)
			try:
				with open(file_path, 'r') as f:
					s = f.read()
				s = s.replace('\n]\n[\n', ',')
				js = json.loads(s)

				for sample in js:
					finder.accept_sample(sample)
			except Exception as e:
				print(file_name, e)
			# break

	finder.analyze()
	finder.print_to_file()

	print('samples: ' + str(finder.sample_amount))
	with open('vimtest_all.csv', 'w', encoding='utf8') as f:
		counter = finder.hot_spot_counter
		for idx, key in enumerate(sorted(counter.keys(), key=lambda x: counter[x].amount, reverse=True)):
			f.write(','.join(map(str, [key, counter[key].amount])))
			f.write('\n')


if __name__ == '__main__':
	main()

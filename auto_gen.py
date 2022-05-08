import os.path
import time
from argparse import ArgumentParser

from common import touch_dir


def main():
    parser = ArgumentParser(prog='python auto_gen.py')
    parser.add_argument('-o', '--output', default='output', help='The directory name of the generated ground truths')
    parser.add_argument('-n', '--number', type=int, default=20, help='The amount of the data')
    parser.add_argument('--an', type=int, help='The amount of the actions per data')
    parser.add_argument('--start-index', type=int, default=1, help='The start index of the data, set it to the previous number +1 to generate more data')

    args = parser.parse_args()
    data_count = args.number
    lower = args.start_index
    upper = lower + data_count
    time_start = time.time()
    for i in range(lower, upper):
        dir_name = os.path.join(args.output, 'data{}'.format(i))
        print('Generating ground truth #{} in {}'.format(i, dir_name))
        touch_dir(dir_name)
        action_file = os.path.join(dir_name, 'action.act')
        trace_file = os.path.join(dir_name, 'pintool_trace.json')
        gt_file_base = os.path.join(dir_name, 'ground_truth')
        os.system('python3 action_gen.py -o {}'.format(action_file) + (' -n {}'.format(args.an) if args.an is not None else ''))
        os.system('python3 syscall_tracer.py -c "vim" -i hotspots.txt -o {} -a {} --wd ./vimworkspace'.format(trace_file, action_file))
        os.system('python3 ground_truth_generator.py -i {} -o {}'.format(trace_file, gt_file_base))

    time_cost = time.time() - time_start
    print('Total time cost: {}s'.format(round(time_cost, 2)))
    print('Average time cost per ground truth: {}s'.format(round(time_cost / max(1, data_count), 2)))


if __name__ == '__main__':
    main()

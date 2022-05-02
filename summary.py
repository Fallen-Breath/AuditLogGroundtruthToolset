def main():
    header = [
        'k',
        'k_leaf',
        'PinTool tracer result line count',
        'Tree node amount',
        'Tree node amount (leaf)',
        'Tree node amount (non-leaf)',
        'Tree node amount (trimmed)',
        'Tree node amount (trimmed & non-leaf)',
        'Maximum node depth (trimmed)',
        'Different syscall amount',
        'Different function amount',
        'Different function amount (trimmed)',
    ]
    with open('output/summary.csv', 'w') as f:
        f.write('groundtruth,')
        f.write(','.join(map(str, header)))
        f.write('\n')
        for i in range(1, 41):
            lines = open('output/data{}/ground_truth.summary.txt'.format(i)).readlines()
            lines.pop(0)
            nums = ['data{}'.format(i)]
            for j in range(len(header)):
                num = int(lines[j].replace(':', '=').split('=', 1)[1].strip())
                nums.append(num)
            f.write(','.join(map(str, nums)))
            f.write('\n')


if __name__ == '__main__':
    main()
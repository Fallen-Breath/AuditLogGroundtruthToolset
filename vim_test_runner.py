import os.path

VIM_DIR = '/home/nellaf/valgrind/vim-master'
VIM_EXE = os.path.join(VIM_DIR, 'src', 'vim')
VIM_TEST_DIR = os.path.join(VIM_DIR, 'src', 'testdir')


def main():
    file_names = []
    for file_name in os.listdir(VIM_TEST_DIR):
        if file_name.startswith('test_') and file_name.endswith('.vim'):
            file_names.append(file_name)

    file_names.sort()
    file_names.remove('test_terminal.vim')
    print(len(file_names))

    for file_name in file_names:
        test_name = file_name[:-4]
        print(test_name)

        cmd = '../vim -u NONE -S runtest.vim {}'.format(file_name)
        os.system('rm ./.tmp/pintool_sample.json')
        os.system('python3 hotspot_finder.py -c "{cmd}" --wd {wd} -t pin -k 1 -l 200 -o output/vimtest/{tn}.txt'.format(
            cmd=cmd, wd=VIM_TEST_DIR, tn=test_name
        ))
        os.system('cp ./.tmp/pintool_sample.json output/vimtest/{tn}.json'.format(tn=test_name))


if __name__ == '__main__':
    main()

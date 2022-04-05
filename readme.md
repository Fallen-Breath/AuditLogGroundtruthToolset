Use `-h` option to see help for all toos

`pipeline.sh`: A simple bash script to generate the ground truth

`hotspot_finder.py`: Use perf / callgrind / pin to find hotspot functions. Outputs hotspots into a txt file

`ground_truth_generator.py`: Use given hotspot function list and pin to create a base ground truth data. Outputs data into `ground_truth.nodes.json`, `ground_truth.tree.json` and `ground_truth.tree.txt`

`pin/SyscallSampler.cpp`, `pin/obj-intel64/SyscallSampler.so`: Sample stack traces on syscalls

`pin/SyscallTracer.cpp`, `pin/obj-intel64/SyscallTracer.so`: Sample syscalls, and function start / end for given functions. Requires the hotspots file

`pin/make.sh`: Build pin tools (SyscallSampler, SyscallTracer). Intel Pin files should be put in `/pin/pin_root/`


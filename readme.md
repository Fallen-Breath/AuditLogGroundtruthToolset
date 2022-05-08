# Ground truth 生成相关工具集

## 概述

python3

### 基本使用流程

1. 使用 `hotspot_finder.py` 运行目标程序，生成热点函数列表 hotspots.txt
2. 使用 `syscall_tracer.py` 基于热点函数列表插桩并运行目标程序，生成系统调用追踪数据 pintool_trace.json
3. 使用 `ground_truth_generator.py` 解析追踪数据，构造并裁切运行追踪树，生成 ground truth 数据


## 文件用途

可以在运行时使用 `-h` 参数来查看帮助，如 `python3 ground_truth_generator.py -h`

根目录

- `action_gen.py`

  自动生成随机用户操作脚本
  
  111
  
- `action_sim.py`：用户操作脚本的解析与应用的实现
- `auto_gen.py`：自动的 ground truth 批量生成工具
- `common.py`：复用工具库
- `gen.sh`：
- `hotspot_finder.py`：运行目标程序，生成热点函数
- `syscall_tracer.py`：基于热点函数列表插桩并运行目标程序，生成系统调用追踪数据
- `ground_truth_generator.py`：解析追踪数据，构造并裁切运行追踪树，生成 ground truth 数据

pintool 目录

- `pintool/common.cpp`, `pintool/common.h`：复用工具库
- `pintool/make.sh`：pintool 的构造脚本
- `pintool/makefile`, `pintool/makefile.rules`
- `pintool/SyscallSampler.cpp`
- `pintool/SyscallTracer.cpp`




# Ground truth 生成相关工具集

## 概述

依赖 python3，需要安装 virtkey 库

需要将 intel pin 的文件夹复制为 `./pintool/pin_root/`，即让 `./pintool/pin_root/pin` 为可执行文件 pin 的路径

### 基本使用流程

1. 使用 `hotspot_finder.py` 运行目标程序，生成热点函数列表 hotspots.txt
2. 使用 `syscall_tracer.py` 基于热点函数列表插桩并运行目标程序，生成系统调用追踪数据 pintool_trace.json
3. 使用 `ground_truth_generator.py` 解析追踪数据，构造并裁切运行追踪树，生成 ground truth 数据


## 文件用途

可以在运行时使用 `-h` 参数来查看帮助，如 `python3 ground_truth_generator.py -h`

根目录

- `action_gen.py`

  自动生成随机用户动作脚本。用户动作脚本的定义见下方 `action_sim.py` 说明
  
  **参数**：
  
  - `-h`：输出帮助信息
  - `-o`：指定 .act 用户动作脚本的输出文件路径
  - `-n`：指定动作的数量

  **用法示例**:
  
  ```bash
  python3 action_gen.py -o my_action.act -n 100
  ```
  
- `action_sim.py`：

  用户动作脚本的解析与应用的实现
  
  动作脚本为一个文本文件，主要用于 vim 的用户操作模拟，通常以 .act 为后缀
  
  脚本描述了一个按键模拟操作序列，每一个非空行代表一个动作，格式为 `<动作名> <参数>`。以 `#` 开头的行将被视为注释而被忽略
  
  **可用的动作列表**：
  
  - `press`：按下给定按键。参数为一个按键描述串
  - `release`：松开给定按键。参数为一个按键描述串
  - `input`：逐个按下并松开给定按键。参数为一个按键描述串
  - `multikey`：逐个按下所有给定按键后，逐个松开所有给定按键。参数为一个按键描述串
  - `sleep`：延迟给定时间。参数为一个浮点数，代表 sleep 的秒数
  - `set_key_delay`：设置按下/松开每个按键后会执行的**固定**时间延迟。参数为 1 个浮点数，代表延迟的秒数
  - `set_seed`：设置随机数种子。参数为一个整数
  - `set_random_key_delay`：设置按下/松开每个按键后会执行的**随机**时间延迟。参数为 2 个浮点数，代表延迟的秒数的下界以及上界
  
  **按键描述串**：
  
  一个包含任意字符的字符串。其中可显示的字符，如 abc123，代表着对应的键盘按键
  
  对于特殊按键，使用 `[按键名]` 的方法来表示，如 `[enter]`。当需要表示 `[` 或 `]` 时，可以使用 `\` 来进行转义，当然 `\` 也可以转义 `\`。例子：`abc\[\]\\123[enter]`，表示输入了 `abc[]\123` 再带一个回车键
  
  可用的特殊按键列表见 `action_sim.py` 中的 `AbstractKeyAction.SPECIAL_KEYS`。直接运行 `action_sim.py` 也可以得到所有的动作列表以及特殊按键名
  
  **例子**：
  
  ```
  # startup wait
  sleep 4
  set_key_delay 0.02
  set_key_delay 0 0.04

  # insert and input 2 line
  input i
  sleep 0.2
  input abc[enter]
  sleep 0.2
  input new line here[enter]
  
  # page scrolling
  press [ctrl_left]
  input du
  release [ctrl_left]

  # quit
  input [esc]
  sleep 0.3
  input :wq! 1.txt[enter]
  ```
  
- `auto_gen.py`：

  自动化的批量 ground truth 生成工具，用于批量生成目标程序为 vim 的 ground truth
  
  **流程**：
  
  1. 使用 `action_gen.py` 生成一份新的随机的动作脚本
  2. 使用 `syscall_tracer.py` 运行 vim 并生成插桩追踪数据
  3. 使用 `ground_truth_generator.py` 生成 ground truth
  
  **运行需求**：
  
  需要已有 hotspots.txt 热点函数文件
  
  **参数**：
  
  - `-h`：输出帮助信息
  - `-i`：指定热点函数文件的路径。默认值：`hotspots.txt`
  - `-o`：指定存放 ground truth 的文件夹。默认值：`output`
  - `-n`：指定 ground truth 生成的数量。默认值：20
  - `-an`：指定对于每次运行时生成的动作脚本中动作的数量。将作为 `-n` 参数传递给 `action_gen.py`。可选
  - `--start-index`：在为每个 ground truth 存放文件夹编号时的开始下标。默认值：1
  
  在默认参数下，生成的 ground truth 将被存放于 `./output/data1/` ... `./output/data20/` 中

  **用法示例**:
  
  ```bash
  python3 auto_gen.py -n 10
  python3 auto_gen.py --start-index 20 -an 100 -i myhotspots.txt
  ```
  
  
- `common.py`

  一些常用的代码，单独放在这以便于复用
  
- `gen.sh`

  一个简单的从 0 开始生成基于 vim 的 ground truth 的脚本

- `hotspot_finder.py`

  运行目标程序，生成热点函数列表
  
  有 3 种采集热点函数的工具可选：perf，callgrind 以及 pin。默认值为 perf
  
  当使用 pin 作为采集工具时，将使用 SyscallSampler 这一 pintool 进行插桩。它将在发生系统调用的时刻对程序运行堆栈进行采样，可以看作是一个针对系统调用的采样性能分析器
  
  **参数**：
  
  - `-h`：输出帮助信息
  - `-t`：选择采集热点函数的工具，可选值为 perf，callgrind 以及 pin。默认值：perf
  - `-l`：输入的热点函数的最大上限数量。默认值：100
  - `-c`：运行目标程序的指令。若未给出此参数，则程序将在控制台中请求用户输入
  - `-o`：输出的热点函数文件的路径。默认值：hotspots.txt
  - `-r`：当包含此参数时，程序将在控制台输出一些易于阅读的热点函数分析报告
  - `-k`：在使用 pin 采集热点函数时，对函数调用树进行裁切时所使用的参数 k。调用树中子节点数不超过 k 的节点将被裁切掉。默认值：1，意味将会把成链的节点裁掉
  - `-a`：用户操作脚本的路径。当给定时，将在运行目标程序时执行用户操作脚本模拟用户输入。可选参数
  - `-q`：保持安静，不要在控制台输出信息。虽然这条参数实际上好像并没有什么用，有些地方的输出没能成功隐藏

  **用法示例**:
  
  ```bash
  python3 hotspot_finder.py -c vim
  python3 hotspot_finder.py -c vim -t pin -k 1 -o my_hotspots.txt -r
  python3 hotspot_finder.py -c vim -t callgrind -l 200 -a action.act -o my_hotspots.txt
  ```
  
- `syscall_tracer.py`

  基于热点函数列表插桩并运行目标程序，生成系统调用追踪数据
  
  将使用 SyscallTracer 这一 pintool，对给定函数的进出以及系统调用的发生进行插桩
  
  **参数**：
  
  - `-h`：输出帮助信息
  - `-c`：运行目标程序的指令。必须的参数
  - `--wd`：运行目标程序的工作路径。可选参数
  - `-i`：将被插桩的函数列表文件路径。默认值：hotspots.txt
  - `-o`：生成的系统调用追踪数据文件路径。默认值：pintool_trace.json
  - `-a`：用户操作脚本的路径。当给定时，将在运行目标程序时执行用户操作脚本模拟用户输入。可选参数
  
- `ground_truth_generator.py`

  解析追踪数据，构造并裁切运行追踪树，生成 ground truth 数据
  
  默认参数下将生成以下的 ground truth 文件：
  
  - `ground_truth.aggregation.json`：模拟逐层聚类的数据，可用于下游程序使用
  - `ground_truth.nodes.json`：一个列表，储存每个节点的信息
  - `ground_truth.raw_tree.txt`：裁剪前的追踪树概览
  - `ground_truth.trimmed_tree.txt`：裁剪后的追踪树概览
  - `ground_truth.summary.txt`：对这一组 ground truth 数据的小结
  - `ground_truth.tree.json`：以树的形态嵌套输出的追踪树，完整地描述了整个追踪树
  
  **树裁切**：
  
  追踪树中所有的叶节点均为系统调用，所有的非叶节点均为函数调用
  
  为了增加聚合的效率，我们将对分支较少的节点进行裁切：将其所有的子结点并入其父节点中，并删除该节点
  
  判断一个节点是否分支过少是通过参数 k 来判断的，子节点数（不包括孙节点等）不超过 k 的节点将被裁切
  
  我们将次叶节点定义为其所有子结点均为叶子的节点。由于次叶节点的所有子结点均为叶节点，也即均为系统调用，因此我们希望它的 k 值能相对较大，因此这就是参数 kl 的作用：仅适用于次叶节点的参数“k”
  
  树裁切将自底向上地进行，从而保证成链的函数节点集合被裁剪后能保留最上层的语义性更强的函数节点
  
  **参数**：
  
  - `-h`：输出帮助信息
  - `-i`：生成的系统调用追踪数据文件路径。默认值：pintool_trace.json
  - `-o`：生成的 ground truth 文件的文件名前缀。默认值：ground_truth
  - `-k`：指定裁剪追踪树时对非次叶节点的参数。默认值：2
  - `--kl`：指定裁剪追踪树时对次叶节点的参数。默认值：4
  - 
  **用法示例**:
  
  ```bash
  python3 ground_truth_generator.py -k 2 --kl 4 -o output/my_ground_truth
  ```

-------

pintool 目录

- `pintool/common.cpp`, `pintool/common.h`

  一些常用的代码，单独拎出来以便于复用
  
- `pintool/make.sh`

  配置好的，用于一键编译 pintool 的脚本

  pintool 的构造脚本
  
- `pintool/makefile`, `pintool/makefile.rules`

  与编译 pintool 相关的文件

- `pintool/SyscallSampler.cpp`

  采样在系统调用发生时目标程序的调用栈
  
  **用法示例**（需编译好 pintool）：
  
  ```bash
  cd ./pintool
  ./pin_root/pin -t obj-intel64/SyscallSampler.so -o my_sampling_result.json -- ls
  ```

  **参数**：
  
  - `-h`：输出帮助信息
  - `-o`：设置输出的系统调用堆栈采样数据文件的路径。默认值：sampler.json


- `pintool/SyscallTracer.cpp`

  基于热点函数列表插桩并运行目标程序
  
  **用法示例**（需编译好 pintool）：
  
  ```bash
  cd ./pintool
  ./pin_root/pin -t obj-intel64/SyscallSampler.so -o my_tracing_result.json -- pwd
  ```

  **参数**：
  
  - `-h`：输出帮助信息
  - `-i`：设置储存着被插桩的函数名的文本文件，一行代表一个函数名，通常也即热点函数文件。需给定，否则将不会插桩任何函数
  - `-o`：设置输出的系统调用追踪数据文件的路径。默认值：tracer.json
  - `-r`：在控制台中输出易读的追踪树



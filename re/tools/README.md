# re/tools · 一键再生脚本

依赖：`pip install pefile capstone`（Python 3.9+）

| 脚本 | 作用 |
|---|---|
| `dump_all.py` | 再生 `re/out/pe_meta.json`（11 个 PE 的段表/导出表/导入计数/PDB 路径）+ 解密两份内核日志 |
| `extract_strings.py` | 全量 ASCII 字符串抽取（`.txt` 全量、`.plain.txt` 去虚表修饰名） |
| `kb.py` | 核心工具库：RVA↔文件偏移、字符串交叉引用、函数起点恢复（`find_proc`，用 int3 填充 + 线性反汇编校验）、Capstone 反汇编 |
| `funcstr.py` | 打印某函数内引用的所有字符串（定位日志/配置键最有效） |
| `pagestr.py` | 按 4KB 页聚合字符串引用（用于给"孤儿"字符串找归属函数，见下） |
| `rtti2.py` | 手工 MSVC RTTI 解析（TypeDescriptor / ClassHierarchyDescriptor / vtable） |
| `xref.py`  | 早期版本的交叉引用脚本（保留作对照） |

## 用法示例

```bash
# 1) 元数据 + 日志解密
python3 re/tools/dump_all.py

# 2) 找某个配置键/日志文案被谁引用
python3 -c "
import sys; sys.path.insert(0,'re/tools')
from kb import Bin
b=Bin('bin/kernel.dll')
b.who_logs('cdn_speed_limit_dispatch')"

# 3) 打印某函数引用到的全部字符串
python3 re/tools/funcstr.py bin/kernel.dll 2eeccb 2dc910

# 4) 反汇编某函数（自动按 int3/序言切边界）
python3 -c "
import sys; sys.path.insert(0,'re/tools')
from kb import Bin
b=Bin('bin/kernel.dll')
for i in b.dis_func(0x2dc910): print(f'{i.address:08x} {i.mnemonic} {i.op_str}')"
```

## 遇到的两个坑（记录一下，省得重复踩）

1. **kernel.dll 没有 `.pdata`**（只有 `.voltbl`），所以无法靠异常表切函数边界；
   而 `find_proc` 依赖 `cc` 填充，在某些函数上会失败（函数体里没有 int3 前缀）。
   对这类地址改用"页聚合"思路：同一 4KB 页内的字符串引用大多属于同一模块的同一批日志函数。
2. **字符串常量池被合并**：多个 `.cpp` 的日志格式串挨着存放，
   所以 `who_logs()` 命中的函数不一定是"定义该行日志"的函数，
   需要结合该函数里其它字符串与相邻调用一起判断（报告里对每一条结论都注明了依据）。

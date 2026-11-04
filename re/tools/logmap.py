#!/usr/bin/env python3
"""按地址区间扫描 push/mov imm32 引用到的字符串, 输出 "代码地址 -> 文案" 映射.
用于给无符号的大函数区做快速语义测绘。
用法: python3 re/tools/logmap.py bin/kernel.dll 0x2da000 0x300000 [--calls]
"""
import sys, os, re
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from kb import Bin

def str_at(b, va):
    o = b.rva2off(va - b.base)
    if o is None: return None
    raw = b.data[o:o + 160].split(b'\0')[0]
    if len(raw) < 3: return None
    if not all(32 <= c < 127 or c in (9, 10, 13) for c in raw[:60]): return None
    return raw.decode('latin1')

def main():
    b = Bin(sys.argv[1])
    lo, hi = int(sys.argv[2], 16), int(sys.argv[3], 16)
    want_calls = '--calls' in sys.argv
    for insn in b.dis(lo, hi - lo):
        if insn.mnemonic not in ('push', 'mov', 'cmp', 'lea'):
            continue
        m = re.search(r'0x(10[0-9a-f]{6}|11[0-9a-f]{6})\b', insn.op_str)
        if not m: continue
        s = str_at(b, int(m.group(1), 16))
        if not s: continue
        f = b.find_proc(insn.address - b.base)
        print(f"{insn.address:08x} (func {f and hex(f)}) {insn.mnemonic} {insn.op_str:<20} ; {s!r}")

if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""孤儿字符串归属定位: 某字符串没有直接 xref 时, 用同页其它字符串的 xref 反推代码函数.
用法: python3 re/tools/pagestr.py bin/kernel.dll 0x12499c3 0x1249a60
"""
import sys, os, collections
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from kb import Bin

MAX_PROBE = 40

def main():
    b = Bin(sys.argv[1])
    for a in sys.argv[2:]:
        rva = int(a, 16)
        o = b.rva2off(rva)
        s = b.data[o:o+80].split(b'\0')[0].decode('latin1')
        print(f"== {a} {s!r}  page={rva & ~0xfff:#x}")
        direct = b.xrefs(rva)
        print("   直接 xref:", [hex(x) for x in direct] or "无（字符串被内联/合并，或被 xor 加密常量访问）")
        if direct:
            print("   所属函数:", sorted({hex(b.find_proc(x) or 0) for x in direct}))
            continue
        page = rva & ~0xfff
        cands = collections.Counter()
        probes = 0
        p = page
        while p < page + 0x1000 and probes < MAX_PROBE:
            oo = b.rva2off(p)
            p += 4
            if oo is None:
                continue
            raw = b.data[oo:oo+80].split(b'\0')[0]
            if len(raw) < 8 or not all(32 <= c < 127 for c in raw[:40]):
                continue
            probes += 1
            for x in b.xrefs(p - 4):
                f = b.find_proc(x)
                if f:
                    cands[f] += 1
        for f, c in cands.most_common(5):
            print(f"   候选函数 {f:#x}  (同页字符串被引用 {c} 次)")

if __name__ == '__main__':
    main()

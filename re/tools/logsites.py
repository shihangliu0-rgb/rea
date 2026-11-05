#!/usr/bin/env python3
"""从 MSVC 日志宏的帧构造代码里批量恢复 (函数名, 源码行号) —— 相当于还原符号表.

日志帧结构:  { int type=9/0x3b; const char* file; const char* func; int line; }
典型代码:
    mov dword ptr [eax], 9
    mov dword ptr [eax+0x1c], 0x11259ef8   ; "calculate_target_speed"
    mov dword ptr [eax+0x20], 0x7e         ; 126  <- 源码行号
所以扫描 "写 [reg+0x1c] 的 imm32 指向可打印字符串" + 紧随其后的 "[reg+0x20]=小整数" 即可.

用法: python3 re/tools/logsites.py bin/kernel.dll [-o re/out]
"""
import sys, os, json, bisect
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from kb import Bin

def main():
    path = sys.argv[1]
    outdir = 're/out'
    if '-o' in sys.argv:
        outdir = sys.argv[sys.argv.index('-o') + 1]
    os.makedirs(outdir, exist_ok=True)
    b = Bin(path)
    prologues = b.call_targets()
    def func_of(a):
        i = bisect.bisect_right(prologues, a) - 1
        return prologues[i] if i >= 0 else a

    def printable(va):
        o = b.rva2off(va - b.base)
        if o is None: return None
        raw = b.data[o:o + 96].split(b'\0')[0]
        if len(raw) < 3: return None
        if not all(32 <= c < 127 or c in (9,) for c in raw[:60]): return None
        return raw.decode('latin1')

    lo, hi = b.textva, b.textva + b.textvsz
    funcs = b.call_targets() + [hi]
    sites = {}
    for i in range(len(funcs) - 1):
        fs, fe = funcs[i], funcs[i + 1]
        if fe <= fs: continue
        if fe - fs > 0x40000: continue
        try:
            insns = list(b.md.disasm(b.data[b.rva2off(fs):b.rva2off(fs) + (fe - fs)], b.base + fs))
        except TypeError:
            continue
        pend = None
        for insn in insns:
            if insn.mnemonic == 'mov' and pend is None:
                op = insn.op_str
                if '0x1c]' in op and ', 0x' in op:
                    va = int(op.rsplit(', ', 1)[1], 16)
                    if va > b.base:
                        s2 = printable(va)
                        if s2: pend = (s2, insn.address)
                        continue
            if pend and insn.mnemonic == 'mov' and '0x20]' in insn.op_str and ', 0x' in insn.op_str:
                line = int(insn.op_str.rsplit(', ', 1)[1], 16)
                if 0 < line < 200000:
                    rec = sites.setdefault(fs, {'name': pend[0], 'sites': []})
                    rec['sites'].append((line, pend[1]))
                pend = None
            elif pend and insn.address - pend[1] > 0x40:
                pend = None

    # 汇总
    out = []
    for f, rec in sorted(sites.items()):
        lines = sorted({l for l, _ in rec['sites']})
        out.append({'func': f'0x{f:08x}', 'name': rec['name'],
                    'lines': lines[:40], 'n_sites': len(rec['sites'])})
    json.dump(out, open(f'{outdir}/logsites_{os.path.basename(path)}.json', 'w'), indent=1, ensure_ascii=False)
    with open(f'{outdir}/funcnames_{os.path.basename(path)}.txt', 'w') as fh:
        for r in out:
            fh.write(f"{r['func']}  {r['name']:<44} lines={r['lines'][:6]}\n")
    print(f"{len(out)} 个函数恢复出名字 -> {outdir}/funcnames_{os.path.basename(path)}.txt")

if __name__ == '__main__':
    main()

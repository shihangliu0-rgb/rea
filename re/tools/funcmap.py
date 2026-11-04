#!/usr/bin/env python3
"""把 "0xRVA 函数名 行号" 映射成 PE 里的真实函数起点 (VA 形式, 便于对照 IDA/x64dbg).
原理: 日志宏里的行号/函数名写在函数体内, 所以记录地址落在函数内部;
     用逆向的 call/jmp 目标 + 常见序言做函数起点候选, 取 "≤记录地址且最接近" 的那个.
输出: re/out/funcmap_<dll>.csv  (func_rva, func_va, name, src_lines)
"""
import sys, os, json, bisect, csv
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from kb import Bin

def main():
    path = sys.argv[1]
    name = os.path.basename(path)
    b = Bin(path)
    starts = sorted(set(b.call_targets()))
    recs = json.load(open(f're/out/logsites_{name}.json'))
    rows = []
    for r in recs:
        a = int(r['func'], 16)
        i = bisect.bisect_right(starts, a) - 1
        f = starts[i] if i >= 0 else a
        rows.append((f, b.base + f, r['name'], ';'.join(map(str, r['lines']))))
    # 合并同一函数的多条记录
    merged = {}
    for f, va, nm, ln in rows:
        if f in merged:
            merged[f][2].append(nm)
            merged[f][3].extend(ln.split(';'))
        else:
            merged[f] = [f, va, [nm], ln.split(';')]
    with open(f're/out/funcmap_{name}.csv', 'w', newline='') as fh:
        w = csv.writer(fh)
        w.writerow(['func_rva', 'func_va', 'names', 'src_lines'])
        for f, v in sorted(merged.items()):
            w.writerow([f'0x{f:08x}', f'0x{v[1]:08x}',
                        '|'.join(sorted(set(v[2]))),
                        ','.join(sorted(set(v[3]), key=lambda x: int(x)))])
    print(f'{len(merged)} funcs -> re/out/funcmap_{name}.csv')

if __name__ == '__main__':
    main()

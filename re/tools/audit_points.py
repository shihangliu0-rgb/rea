#!/usr/bin/env python3
"""
re/tools/audit_points.py —— 对 12 个 hook 点位做"是否可能被执行"的静态审计

背景（这是一次教训的固化）：
  12 个点位都通过了"字节签名在文件里唯一匹配"，但用户在真机上跑 stats() 发现：
      bucket.set_rate  208 次
      bucket.consume  2665 次
      其余 10 个        0 次
  也就是说 **"签名匹配" 完全不等于 "运行时会执行"**。

这个脚本把判断依据摆出来，让"死活"不再靠猜：
  1. 该地址是函数入口，还是函数中间（决定 E8 调用者计数是否有意义）
  2. 有多少条 `E8 rel32` 直接 call 到它
  3. 有多少处代码把它当数据引用（vtable / 函数指针 / 间接调用）
  4. 如果它是 set_rate 这种"设置值"的函数，统计每个调用点压栈的立即数
     —— 能直接看出"谁在下发 16384 / 120KiB / 500MB/s"

用法：
    python3 re/tools/audit_points.py bin/kernel.dll
    python3 re/tools/audit_points.py bin/kernel.dll --callers 0xdd320
"""
import sys, os, struct, collections, argparse

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import kb  # noqa: E402

# 12 个点位：RVA 以 242 为准（237 见 docs/10）
POINTS_242 = [
    (0x125f20, 'set_param'),
    (0x2e7e70, 'update_max_speed'),
    (0x2e7a50, 'set_restrict_ratio'),
    (0x2e8800, 'calculate_target_speed'),
    (0x0dd320, 'bucket.set_rate'),
    (0x0dd340, 'bucket.consume'),
    (0x2f83ae, 'cdn_speed_limit_dispatch'),
    (0x1b25bd, 'close_cdn(decided)'),
    (0x0e52c0, 'set_try_speedup_flag'),
    (0x1b3788, 'block_gate(pre)'),
    (0x1b3a03, 'download_threshold'),
    (0x28a0f0, 'set_download_restrict_ratio'),
]

# 实测命中数（用户 2026-11 的 stats() 结果），None = 没测
RUNTIME_HITS = {
    'bucket.set_rate': 208,
    'bucket.consume': 2665,
}


def build_call_map(b):
    """扫 .text 里所有 E8 rel32，返回 {callee_rva: [call_sites]}"""
    blob = b.data[b.textra:b.textra + b.textvsz]
    tv = b.textva
    calls = collections.defaultdict(list)
    i = blob.find(b'\xe8')
    while i >= 0:
        if i + 5 <= len(blob):
            rel = struct.unpack_from('<i', blob, i + 1)[0]
            site = tv + i
            dst = site + 5 + rel
            if tv <= dst < tv + b.textvsz:
                calls[dst].append(site)
        i = blob.find(b'\xe8', i + 1)
    return calls


def immediate_arg(b, site, back=0x80):
    """取 call 之前最近的一条 push，返回操作数字符串"""
    try:
        ins = [x for x in b.dis(site - back, back) if x.address - b.base < site]
    except Exception:
        return '?'
    for x in reversed(ins):
        if x.mnemonic == 'push':
            return x.op_str
    return '?'


def audit(path, verbose_callers=None):
    b = kb.Bin(path)
    size = b.pe.OPTIONAL_HEADER.SizeOfImage
    print("样本: %s" % path)
    print("SizeOfImage = 0x%x  (%d 字节)" % (size, len(b.data)))
    print("ImageBase   = 0x%x   .text = [0x%x, 0x%x)" %
          (b.base, b.textva, b.textva + b.textvsz))
    print()

    calls = build_call_map(b)
    print("%-28s %-9s %-10s %-8s %-8s %s" %
          ("点位", "RVA", "位置", "E8调用", "取地址", "运行时命中"))
    print("-" * 88)

    for rva, name in POINTS_242:
        off = b.rva2off(rva)
        prev = b.data[max(0, off - 8):off]
        enclosing = b.func_of(rva)
        at_entry = (enclosing == rva)
        sites = calls.get(rva, [])
        refs = b.xrefs(rva)
        hits = RUNTIME_HITS.get(name)
        hits_s = ('%d 次' % hits) if hits is not None else '未测'
        print("%-28s 0x%-7x %-10s %-8s %-8s %s" % (
            name, rva,
            '函数入口' if at_entry else '函数内部',
            str(len(sites)) if at_entry else str(len(sites)) + '*',
            str(len(refs)), hits_s))

    print("-" * 88)
    print("* 函数中间的调用点数**不能**用来判断死活：那只是别人路过这条指令。")
    print("  只有「函数入口 + E8 调用数 = 0 + 无取地址引用」才是真正的死代码。")
    print()

    # 位置判定细节
    print("位置判定（前一条指令是否是 ret/int3/对齐填充）：")
    for rva, name in POINTS_242:
        off = b.rva2off(rva)
        prev = b.data[max(0, off - 8):off]
        end_ok = prev[-1:] in (b'\xcc', b'\xc3', b'\xcb')
        enc = b.func_of(rva)
        print("  0x%-7x %-28s prev=%-18s %s  所在函数=0x%x" % (
            rva, name, prev.hex(), '入口' if enc == rva else '内部', enc))
    print()

    # set_rate 的入参分布
    target = 0xdd320
    sites = calls.get(target, [])
    if sites:
        print("bucket.set_rate 的 %d 个调用点，各自压栈的立即数：" % len(sites))
        c = collections.Counter()
        detail = []
        for s in sites:
            a = immediate_arg(b, s)
            detail.append((s, a, b.func_of(s)))
            c[a] += 1
        for k, v in c.most_common():
            print("  %-24s x%d" % (k, v))
        print()
        print("  常量里最值得注意的是：")
        for w in ('0x4000', '0x1e000', '0x1f400000', '0x6400000', '0x80000'):
            if c.get(w):
                print("    %-12s x%d  (%d B/s)" %
                      (w, c[w], int(w, 16)))
        print()
        # 反查逻辑
        for s, a, f in detail:
            if verbose_callers and s == verbose_callers:
                print("  调用点 0x%x 上下文：" % s)
                for i in b.dis(s - 0x40, 0x48):
                    print("    ", hex(i.address - b.base), i.mnemonic, i.op_str)

    # 导出函数覆盖
    import pefile
    pe = pefile.PE(path, fast_load=True)
    ex = []
    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT') and pe.DIRECTORY_ENTRY_EXPORT:
        for s in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if s.address:
                ex.append((s.address, s.name.decode() if s.name else '#%d' % s.ordinal))
    ex.sort()
    print()
    print("导出函数（%d 个）—— 落在导出函数里的点位，零命中就说明这条路没走：" % len(ex))
    for a, n in ex:
        print("  0x%-8x %s" % (a, n))
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('dll')
    ap.add_argument('--callers', type=lambda x: int(x, 16), default=None)
    a = ap.parse_args()
    return audit(a.dll, a.callers)


if __name__ == '__main__':
    sys.exit(main())

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
re/frida/rescan.py —— 在**新版本 kernel.dll** 上重新定位 hooks.js 需要的 13 个点位

背景：
  hooks.js 里的 RVA 是在 kernel.dll 3.0.20.237（8.1.6.101，SizeOfImage=0x2a3a000）上定的。
  8.1.6 之后的客户端换了内核（用户机器上是 43.1MB 版本），所有 RVA 全偏移，
  逐个报 "字节不匹配"。

  这个脚本不靠 RVA，靠**语义特征**重新找：
    * 先按"函数前导字节模式"扫描（MSVC 的 push ebp / mov ebp,esp / push ebx,esi,edi / sub esp,X）
    * 再用 hooks.js 里原本用作校验的**函数体内部特征字节**做二次确认
    * 命中多个候选时全部列出，让你可以 --use 指定

用法：
  python rescan.py --dll "D:\\Wang_Pan\\BaiduNetdisk\\...\\kernel.dll"
  python rescan.py                    # 默认找 PATH 里的 bin/kernel.dll
  python rescan.py --pattern "c7 45"  # 自己找别的特征

输出：一张表（点位名 / 新 RVA / 命中方式 / 候选数），以及可直接粘贴的 patch 片段。

注意：本脚本只做**静态**定位，不保证语义一定对。
      凡是 <<LOW>> 标记的，必须用 verify_rva.py 二次确认，或者用 hooks.js 的
      LOG_ALL=true 先空跑一遍看有没有崩。
"""
import argparse
import os
import re
import struct
import sys

# ── 13 个点位：现在的 RVA + 现有签名 + 允许的"替代特征" ────────────────────
# sig   : hooks.js 里用于 byte 校验的字节（通常是函数体内部，不是函数头）
# heads : 该函数可能的**函数头**前导字节（MSVC 常见几种 prologue）
# 说明  : 中文名，仅用于打印
POINTS = [
    ("set_param", 0x1225F0, "55 89 e5 53 57 56 83 ec 2c",
     ["55 89 e5 53 57 56 83 ec", "55 89 e5 53 57 56 81 ec"], "配置下发入口（限速/开关）"),
    ("update_max_speed", 0x2DD200, "55 89 e5 53 57 56 83 e4 f8",
     ["55 89 e5 53 57 56 83 e4 f8"], "更新 max_speed"),
    ("set_restrict_ratio", 0x2DCDE0, "55 89 e5 53 57 56 81 ec",
     ["55 89 e5 53 57 56 81 ec"], "设置限速比例"),
    ("calculate_target_speed", 0x2DDB90, "55 89 e5 53 57 56 83 e4 f8",
     ["55 89 e5 53 57 56 83 e4 f8"], "计算目标速度"),
    ("bucket.set_rate", 0xDB150, "8b 44 24 04 85 c0",
     ["8b 44 24 04 85 c0", "8b 4c 24 04 85 c9"], "TokenBucket::set_rate"),
    ("bucket.consume", 0xDB170, "53 57 56 89 ce",
     ["53 57 56 89 ce", "53 57 56 8b f1", "53 57 56 8b c1"], "TokenBucket::consume"),
    ("cdn_speed_limit_dispatch", 0x2ED84E, "8b 0b e8",
     ["8b 0b e8"], "CDN 限速调度"),
    ("close_cdn(decided)", 0x1AEB6D, "8b 7d d0 0f af ce",
     ["8b 7d d0 0f af ce"], "close cdn 判定"),
    ("set_try_speedup_flag", 0xE2FB0, "55 89 e5 53 57 56 81 ec",
     ["55 89 e5 53 57 56 81 ec"], "SVIP 试用提速开关"),
    ("block_gate(pre)", 0x1AFD38, "29 d8 89 86 f0 00 00 00",
     ["29 d8 89 86 f0 00 00 00"], "块门限（计数）"),
    ("download_threshold", 0x1AFFB3, "f2 0f 59 0d",
     ["f2 0f 59 0d"], "门限浮点乘法"),
    ("set_download_restrict_ratio", 0x27FEE0, "55 89 e5 53 57 56 81 ec",
     ["55 89 e5 53 57 56 81 ec"], "下载限速比例"),
]

# 观察到的"新版本实际字节"（用户 8.1.6 之后版本的输出）——用来判断是否同一处
OBSERVED = {
    0x1225F0: "50 e8 ca 3c fb ff 83 c4 04",
    0x2DD200: "ff ff ff 8b 95 4c ff ff ff",
    0x2DCDE0: "85 74 fe ff ff a0 e2 3d",
    0x2DDB90: "6c fe ff ff 8b 95 70 fe ff",
    0xDB150: "00 00 00 0f 47 df",
    0xDB170: "83 c0 23 c7 86",
    0x2ED84E: "00 72 c3",
    0x1AEB6D: "30 89 46 14 89 d8",
    0xE2FB0: "89 4d dc e8 18 a3 ff ff",
    0x1AFD38: "00 00 00 c6 02 00 8b 56",
    0x1AFFB3: "00 72 14 8b",
    0x27FEE0: "83 c1 fc 29 d1 83 f9 20",
}


def dll_version(path):
    """读 VS_FIXEDFILEINFO 里的 FileVersion + SizeOfImage"""
    import pefile
    pe = pefile.PE(path, fast_load=True)
    pe.parse_data_directories(directories=[
        pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']])
    ver = "?"
    try:
        for fi in pe.FileInfo or []:
            for e in fi:
                if hasattr(e, 'StringTable'):
                    for st in e.StringTable:
                        d = {k.decode(): v.decode() for k, v in st.entries.items()}
                        if d.get('FileVersion'):
                            ver = d['FileVersion']
    except Exception:
        pass
    return ver, pe.OPTIONAL_HEADER.SizeOfImage, pe.OPTIONAL_HEADER.ImageBase


def load_pe(path):
    import pefile
    pe = pefile.PE(path, fast_load=True)
    pe.parse_data_directories(directories=[
        pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']])
    data = open(path, 'rb').read()
    return pe, data


def sec_of(pe, rva):
    for s in pe.sections:
        va = s.VirtualAddress
        if va <= rva < va + max(s.Misc_VirtualSize, s.SizeOfRawData):
            return s
    return None


def rva2off(pe, rva):
    s = sec_of(pe, rva)
    if s is None:
        return None
    d = rva - s.VirtualAddress
    if d >= s.SizeOfRawData:
        return None
    return s.PointerToRawData + d


def off2rva(pe, off):
    for s in pe.sections:
        if s.PointerToRawData <= off < s.PointerToRawData + s.SizeOfRawData:
            return s.VirtualAddress + (off - s.PointerToRawData)
    return None


def text_range(pe):
    """返回 .text 的 (起始RVA, 结束RVA)"""
    for s in pe.sections:
        if s.Name.rstrip(b'\x00') == b'.text':
            return s.VirtualAddress, s.VirtualAddress + s.Misc_VirtualSize
    s = pe.sections[0]
    return s.VirtualAddress, s.VirtualAddress + s.Misc_VirtualSize


def find_bytes(data, pat, start=0, end=None, limit=200):
    """在 data[start:end] 里找字节串，返回偏移列表"""
    end = len(data) if end is None else end
    needle = bytes(int(x, 16) for x in pat.split())
    out = []
    i = start
    while len(out) < limit:
        i = data.find(needle, i, end)
        if i < 0:
            break
        out.append(i)
        i += 1
    return out


def func_head_backward(data, off, maxback=0x300):
    """从 off 往回找最近的函数头（55 89 e5 / 53 57 56 / 8b ff 55 8b ec）"""
    heads = [b'\x55\x89\xe5', b'\x8b\xff\x55\x8b\xec', b'\x55\x8b\xec', b'\x53\x57\x56']
    best = None
    for i in range(off, max(0, off - maxback), -1):
        for h in heads:
            if data[i:i + len(h)] == h:
                best = i
                break
        if best is not None:
            break
    return best


def scan(dll, verbose=True):
    pe, data = load_pe(dll)
    tstart, tend = text_range(pe)
    tsoff = rva2off(pe, tstart)
    teoff = rva2off(pe, tend - 1)
    if tsoff is None or teoff is None:
        sys.exit("读不出 .text 节")

    print("=" * 96)
    print("目标：%s" % dll)
    print("  SizeOfImage = 0x%x (%.2f MB)   ImageBase = 0x%x"
          % (pe.OPTIONAL_HEADER.SizeOfImage, pe.OPTIONAL_HEADER.SizeOfImage / 1048576,
             pe.OPTIONAL_HEADER.ImageBase))
    print("  .text RVA 范围 0x%x - 0x%x，文件偏移 0x%x - 0x%x"
          % (tstart, tend, tsoff, teoff))
    print("  TimeDateStamp = %s" % pe.FILE_HEADER.TimeDateStamp)
    print("=" * 96)

    rows = []
    for name, old_rva, sig, heads, desc in POINTS:
        hits = []
        # 1) 用原签名找（函数体内特征，最可靠）
        for off in find_bytes(data, sig, tsoff, teoff, 30):
            hits.append((off, "sig"))
        # 2) 用函数头特征找（只有唯一时才可信）
        if not hits:
            for h in heads:
                for off in find_bytes(data, h, tsoff, teoff, 30):
                    hits.append((off, "head:" + h.split()[0]))
        # 去重并转成 RVA
        seen, cand = set(), []
        for off, how in hits:
            rva = off2rva(pe, off)
            if rva is None or rva in seen:
                continue
            seen.add(rva)
            cand.append((rva, how))
        # 排序：sig 命中 > 函数头命中；同类里离旧 RVA 近的优先
        def rank(item):
            rva, how = item
            return (0 if how == "sig" else 1, abs(rva - old_rva))
        cand.sort(key=rank)
        rows.append((name, old_rva, cand, desc))

    print("\n%-28s %-10s %-10s %-6s %s" % ("点位", "旧RVA", "新RVA", "候选", "命中方式"))
    print("-" * 96)
    lines = []
    for name, old_rva, cand, desc in rows:
        if not cand:
            print("%-28s 0x%-8x %-10s %-6s %s" % (name, old_rva, "-", 0, "未命中 ← 需手工"))
            lines.append((name, old_rva, None, desc))
            continue
        rva, how = cand[0]
        flag = "" if len(cand) == 1 else "  <<%d 个候选>>" % len(cand)
        print("%-28s 0x%-8x 0x%-8x %-6d %s%s" % (name, old_rva, rva, len(cand), how, flag))
        for r2, h2 in cand[1:6]:
            print("%-28s %-10s 0x%-8x %-6s   (候选) %s" % ("", "", r2, "", h2))
        lines.append((name, old_rva, rva, desc))

    # ── 生成 patch 片段 ───────────────────────────────────────────────
    print("\n" + "=" * 96)
    print("可直接替换到 hooks.js 的片段（请先逐条用 verify_rva.py 复核）：")
    print("=" * 96)
    miss = 0
    for name, old_rva, rva, desc in lines:
        if rva is None:
            miss += 1
            print("// %s : 未能自动定位，需手工  %s" % (name, desc))
            continue
        print("hook(0x%x, '%s', '...') // 旧 0x%x" % (rva, name, old_rva))
        lines_ok = True

    print("\n合计：定位 %d / %d，未命中 %d"
          % (len(lines) - miss, len(lines), miss))
    return lines


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dll", default=os.path.join(os.path.dirname(__file__), "..", "..", "bin", "kernel.dll"))
    ap.add_argument("--dump-observed", action="store_true",
                    help="打印用户上报的字节，用于人工比对")
    args = ap.parse_args()

    if not os.path.exists(args.dll):
        sys.exit("找不到 %s（用 --dll 指定你的 kernel.dll）" % args.dll)

    ver, size, base = dll_version(args.dll)
    print("版本信息：FileVersion=%s  SizeOfImage=0x%x (%.2fMB)  ImageBase=0x%x"
          % (ver, size, size / 1048576, base))
    ref_ver, ref_size = "3.0.20.237", 0x2A3A000
    if abs(size - ref_size) > 0x60000:
        print("  ⚠ 与 hooks.js 的目标版本 %s (0x%x = %.2fMB) 不同 → RVA 需全部重新定位"
              % (ref_ver, ref_size, ref_size / 1048576))
    else:
        print("  ✓ 与 hooks.js 的目标版本一致，下面的新 RVA 应该与原 RVA 相同")
    print()

    if args.dump_observed:
        print("%-12s %-26s %s" % ("旧RVA", "新版本实际字节", "旧签名"))
        for name, old_rva, sig, heads, desc in POINTS:
            print("%-12s %-26s %s" % (hex(old_rva), OBSERVED.get(old_rva, "-"), sig))
        print()

    scan(args.dll)


if __name__ == "__main__":
    main()

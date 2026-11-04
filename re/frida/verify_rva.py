#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
re/frida/verify_rva.py —— 离线校验 hooks.js 里的 RVA 和字节签名

作用：**不启动客户端、不需要 Frida**，直接拿 bin/kernel.dll 对一遍
`hooks.js` 里每个 hook 点的「RVA + 期望字节」，回答一个问题：
我的客户端版本还对不对得上这些地址？

用法：
    python re/frida/verify_rva.py
    python re/frida/verify_rva.py --dll "D:\\Wang_Pan\\BaiduNetdisk\\kernel.dll"
    python re/frida/verify_rva.py --dll ... --add 0x1afd38:29d88986f0000000

输出里 SIG 一列：
    OK    = 期望字节与实际完全一致 → 这个 hook 点可以直接用
    BAD   = 地址还在但字节变了   → 版本不同，需要重新定位（脚本会自动跳过它，不会崩）
    MISS  = 地址不在任何节内    → DLL 结构完全不同
"""
import argparse
import binascii
import os
import re
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))


def load_pe_image(path):
    """极简 PE 解析：只需要 section 表，把 RVA 映射到文件偏移。返回 (data, sections)"""
    data = open(path, "rb").read()
    if data[:2] != b"MZ":
        raise SystemExit("不是 PE 文件：" + path)
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if data[e_lfanew:e_lfanew + 4] != b"PE\0\0":
        raise SystemExit("PE 头异常：" + path)
    coff = e_lfanew + 4
    nsec = struct.unpack_from("<H", data, coff + 2)[0]
    opt_size = struct.unpack_from("<H", data, coff + 16)[0]
    opt = coff + 20
    magic = struct.unpack_from("<H", data, opt)[0]
    image_base = (struct.unpack_from("<I", data, opt + 28)[0] if magic == 0x10B
                  else struct.unpack_from("<Q", data, opt + 24)[0])
    secs = []
    so = opt + opt_size
    for i in range(nsec):
        off = so + i * 40
        name = data[off:off + 8].rstrip(b"\0").decode("latin-1")
        vsize, vaddr, rawsize, rawptr = struct.unpack_from("<IIII", data, off + 8)
        secs.append((name, vaddr, max(vsize, rawsize), rawptr))
    return data, secs, image_base


def rva2off(secs, rva):
    for name, vaddr, vsz, rawptr in secs:
        if vaddr <= rva < vaddr + vsz:
            delta = rva - vaddr
            if delta < vsz:
                return rawptr + delta
    return None


def parse_hooks(js_path):
    """从 hooks.js 里抓 hook(0xRVA, 'label', 'sig', ...)"""
    src = open(js_path, encoding="utf-8").read()
    pat = re.compile(r"""hook\(\s*(0x[0-9a-fA-F]+)\s*,\s*'([^']+)'\s*,\s*(?:'([^']*)'|null)""")
    out = []
    for m in pat.finditer(src):
        rva = int(m.group(1), 16)
        label = m.group(2)
        sig = m.group(3)
        out.append((rva, label, sig))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dll", default=os.path.join(REPO, "bin", "kernel.dll"))
    ap.add_argument("--js", default=os.path.join(HERE, "hooks.js"))
    ap.add_argument("--add", action="append", default=[],
                    metavar="RVA:HEXBYTES", help="额外校验一个点，如 0x1afd38:29d88986")
    args = ap.parse_args()

    if not os.path.exists(args.dll):
        raise SystemExit("找不到 kernel.dll：%s\n用 --dll 指定路径" % args.dll)

    data, secs, image_base = load_pe_image(args.dll)
    print("目标 DLL : %s" % args.dll)
    print("ImageBase: 0x%08x   大小: %.1f MB" % (image_base, len(data) / 1048576.0))
    print("节区     : %s" % ", ".join("%s(0x%x)" % (n, v) for n, v, _, _ in secs))
    print("-" * 78)

    hooks = parse_hooks(args.js)
    for extra in args.add:
        rva_s, hex_s = extra.split(":")
        hooks.append((int(rva_s, 16), "(命令行附加)", " ".join(
            hex_s[i:i + 2] for i in range(0, len(hex_s), 2))))

    ok = bad = miss = 0
    for rva, label, sig in hooks:
        off = rva2off(secs, rva)
        if off is None or off >= len(data):
            print("  %-9s %-30s MISS  地址不在任何节内" % ("0x%x" % rva, label))
            miss += 1
            continue
        if not sig:
            print("  %-9s %-30s ----  未校验（无签名）" % ("0x%x" % rva, label))
            continue
        nbytes = len(sig.split())
        actual = data[off:off + nbytes]
        want = binascii.unhexlify(sig.replace(" ", ""))
        if actual == want:
            print("  %-9s %-30s OK" % ("0x%x" % rva, label))
            ok += 1
        else:
            print("  %-9s %-30s BAD   期望=%s 实际=%s"
                  % ("0x%x" % rva, label, want.hex(" "), actual.hex(" ")))
            bad += 1

    print("-" * 78)
    print("合计：OK=%d  BAD=%d  MISS=%d" % (ok, bad, miss))
    if bad or miss:
        print()
        print("BAD/MISS 说明这个 kernel.dll 不是 8.1.6.101 的那一份。")
        print("hooks.js 会在 attach 前自动跳过这些点（不会崩），但你需要重新定位。")
        print("定位方法见 docs/05-完整逆向报告.md §3「反推符号表」。")
        return 1
    print("全部匹配 —— hooks.js 的 RVA 可以直接用。")
    return 0


if __name__ == "__main__":
    sys.exit(main())

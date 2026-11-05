#!/usr/bin/env python3
"""解析 PE 的 .rsrc, 把 RCDATA 里以 MZ 开头的内嵌 PE 导出.
用法: python3 re/tools/extract_rsrc.py bin/kernel.dll [outdir]
"""
import sys, os, struct

def main():
    path = sys.argv[1]
    outdir = sys.argv[2] if len(sys.argv) > 2 else 're/out/embedded'
    os.makedirs(outdir, exist_ok=True)
    d = open(path, 'rb').read()
    import pefile
    pe = pefile.PE(path, fast_load=True)
    rs = [s for s in pe.sections if s.Name.rstrip(b'\0') == b'.rsrc'][0]
    seg = d[rs.PointerToRawData: rs.PointerToRawData + rs.Misc_VirtualSize]
    base_rva, base_off = rs.VirtualAddress, rs.PointerToRawData

    def walk(off, depth, path_ids):
        _, _, _, _, nname, nid = struct.unpack_from('<IIHHHH', seg, off)
        for i in range(nname + nid):
            name, offv = struct.unpack_from('<II', seg, off + 16 + 8 * i)
            sub = offv & 0x7fffffff
            if offv & 0x80000000 and depth < 2:
                walk(sub, depth + 1, path_ids + (name,))
            else:
                rva, size, _, _ = struct.unpack_from('<IIII', seg, sub)
                fo = base_off + (rva - base_rva)
                blob = d[fo:fo + size]
                tag = 'PE' if blob[:2] == b'MZ' else 'raw'
                if tag == 'PE':
                    fn = os.path.join(outdir, f'rsrc_0x{rva:08x}.bin')
                    open(fn, 'wb').write(blob)
                    print(f'{path_ids+(name,)} size={size} -> {fn}')
                else:
                    print(f'{path_ids+(name,)} size={size} (非 PE, 前 32 字节: {blob[:32].hex()})')

    walk(0, 0, ())

if __name__ == '__main__':
    main()

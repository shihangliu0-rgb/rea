#!/usr/bin/env python3
"""一键再生本仓库的所有取证产物: 字符串 / 导出表 / 日志明文 / 模块清单 / 关键函数反汇编"""
import os, sys, json, struct, subprocess
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pefile
from kb import Bin
from rtti2 import classes

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # re/tools/ -> repo root
OUT = os.path.join(ROOT, 're', 'out')
os.makedirs(OUT, exist_ok=True)

BINS = sorted(os.path.join(ROOT, 'bin', f) for f in os.listdir(os.path.join(ROOT, 'bin')))

def exports(path):
    pe = pefile.PE(path, fast_load=True)
    pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']])
    rows = []
    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        for s in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            rows.append({'ordinal': s.ordinal,
                         'name': s.name.decode() if s.name else None,
                         'rva': hex(s.address) if s.address else None})
    return rows

def imports(path):
    pe = pefile.PE(path, fast_load=True)
    pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']])
    return {m.dll.decode(): [i.name.decode() for i in m.imports if i.name]
            for m in getattr(pe, 'DIRECTORY_ENTRY_IMPORT', [])}

def main():
    meta = {}
    for p in BINS:
        name = os.path.basename(p)
        pe = pefile.PE(p, fast_load=True)
        meta[name] = {
            'size': os.path.getsize(p),
            'machine': hex(pe.FILE_HEADER.Machine),
            'timestamp': pe.FILE_HEADER.TimeDateStamp,
            'image_base': hex(pe.OPTIONAL_HEADER.ImageBase),
            'sections': [{'name': s.Name.rstrip(b'\0').decode('latin1'),
                          'va': hex(s.VirtualAddress), 'vsize': s.Misc_VirtualSize,
                          'raw': hex(s.PointerToRawData), 'rawsize': s.SizeOfRawData}
                         for s in pe.sections],
            'has_pdb_pe': any(getattr(d, 'PdbFileName', None) for d in getattr(pe, 'DIRECTORY_ENTRY_DEBUG', [])),
            'exports': exports(p),
            'import_count': {k: len(v) for k, v in imports(p).items()},
        }
    json.dump(meta, open(os.path.join(OUT, 'pe_meta.json'), 'w'), indent=1, ensure_ascii=False)
    print('pe_meta.json ok:', len(meta), 'binaries')

    # 日志
    for f in ('BaiduKernel_20261028040309_641_1.log', 'BaiduKernel_20261119200054_937_1.log'):
        raw = open(os.path.join(ROOT, 'logs', f), 'rb').read()
        open(os.path.join(OUT, f + '.decoded'), 'wb').write(bytes(b ^ 0x8A for b in raw))
    print('logs decoded (XOR 0x8A)')

    # 日志模块分布
    import collections, re
    mods = collections.Counter()
    for f in ('BaiduKernel_20261028040309_641_1.log', 'BaiduKernel_20261119200054_937_1.log'):
        for line in open(os.path.join(OUT, f + '.decoded'), 'r', errors='replace'):
            m = re.search(r'\{(\w+)\}', line)
            if m:
                mods[m.group(1)] += 1
    with open(os.path.join(OUT, 'log_modules.txt'), 'w') as fh:
        fh.write('# 模块\t行数（两份日志合计）\n')
        for k, v in mods.most_common():
            fh.write(f'{k}\t{v}\n')
    print('log_modules.txt ok:', len(mods), 'modules')

if __name__ == '__main__':
    main()

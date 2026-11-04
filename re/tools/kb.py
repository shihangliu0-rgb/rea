#!/usr/bin/env python3
"""kernel.dll 逆向工具箱: RVA/文件偏移映射、字符串定位、交叉引用、函数识别、反汇编"""
import pefile, struct, re, bisect, json
from capstone import *

class Bin:
    def __init__(self, path):
        self.path = path
        self.data = open(path, 'rb').read()
        self.pe = pefile.PE(path, fast_load=True)
        self.base = self.pe.OPTIONAL_HEADER.ImageBase
        self.secs = [(s.Name.rstrip(b'\0').decode('latin1'), s.VirtualAddress,
                      s.Misc_VirtualSize, s.PointerToRawData, s.SizeOfRawData,
                      s.Characteristics) for s in self.pe.sections]
        t = [s for s in self.secs if s[5] & 0x20000000][0]
        self.textva, self.textvsz, self.textra = t[1], t[2], t[3]
        self.md = Cs(CS_ARCH_X86, CS_MODE_32); self.md.detail = True
        self._funcs = None

    # --- 地址换算 ---
    def rva2off(self, rva):
        for n, va, vsz, ra, rs, ch in self.secs:
            if va <= rva < va + max(vsz, rs): return ra + (rva - va)
    def off2rva(self, off):
        for n, va, vsz, ra, rs, ch in self.secs:
            if ra <= off < ra + rs: return va + (off - ra)

    # --- 字符串 ---
    def find_str_rva(self, s):
        out = []
        for enc in ('ascii', 'utf-16-le'):
            try: pat = s.encode(enc)
            except Exception: continue
            i = self.data.find(pat)
            while i >= 0:
                r = self.off2rva(i)
                if r: out.append((r, enc))
                i = self.data.find(pat, i + 1)
        return out

    # --- 交叉引用: 立即数(VA)引用 / 重定位指向 ---
    def imm_refs(self, rva, va=False):
        pat = struct.pack('<I', (self.base + rva) if va else rva)
        res = []; i = self.data.find(pat)
        while i >= 0:
            r = self.off2rva(i)
            if r and self.textva <= r < self.textva + self.textvsz:
                res.append(r)
            i = self.data.find(pat, i + 1)
        return res

    def xrefs(self, rva):
        return self.imm_refs(rva) + self.imm_refs(rva, va=True)

    # --- 函数识别: 收集 call 目标 + 序言模式 ---
    def call_targets(self):
        if self._funcs is not None: return self._funcs
        blob = self.data[self.textra:self.textra + self.textvsz]
        base = self.textva
        tg = set()
        # E8 rel32 / E9 rel32
        for m in re.finditer(rb'[\xe8\xe9]', blob):
            i = m.start()
            if i + 5 > len(blob): break
            rel = struct.unpack_from('<i', blob, i + 1)[0]
            t = base + i + 5 + rel
            if base <= t < base + self.textvsz: tg.add(t)
        # 典型序言 push ebp; mov ebp,esp  (55 8b ec / 55 89 e5)
        for m in re.finditer(rb'\x55[\x8b\x89][\xec\xe5]', blob):
            tg.add(base + m.start())
        # 热补丁空位 / 常见对齐
        self._funcs = sorted(tg)
        return self._funcs

    def func_of(self, rva):
        f = self.call_targets(); i = bisect.bisect_right(f, rva) - 1
        return f[i] if i >= 0 else None

    def func_end(self, rva, maxlen=0x8000):
        f = self.call_targets(); i = bisect.bisect_right(f, rva)
        nxt = f[i] if i < len(f) else rva + maxlen
        return min(nxt, rva + maxlen)

    def find_proc(self, addr):
        """从 addr 往前找函数起点: 优先 int3/cc 填充之后, 并用线性反汇编校验"""
        if addr >= self.base:       # 兼容传入 VA
            addr -= self.base
        o = self.rva2off(addr)
        if o is None:
            return None
        win = 0x6000
        start = max(0, o - win)
        blob = self.data[start:o + 1]
        cands = []
        # cc 填充后
        for m in re.finditer(rb'\xcc{1,16}', blob):
            cands.append(m.end())
        # 55 8b ec (push ebp; mov ebp,esp)
        for m in re.finditer(rb'\x55[\x8b\x89][\xec\xe5]', blob):
            cands.append(m.start())
        rel_target = o - start
        ok = []
        for c in sorted(set(cands), reverse=True):
            if c > rel_target: continue
            base_rva = self.textva + (start + c - self.textra)
            insns = list(self.md.disasm(blob[c:rel_target + 1], self.base + base_rva))
            if not insns: continue
            # 覆盖到 addr 且指令数合理
            last = insns[-1]
            if last.address + len(last.bytes) - self.base == base_rva + (rel_target - c):
                ok.append((base_rva, len(insns)))
                break
        return ok[0][0] if ok else None

    # --- 反汇编 ---
    def dis(self, rva, n=0x400):
        o = self.rva2off(rva)
        if o is None:
            raise ValueError(f"rva {rva:#x} 不在任何节内（检查是否传入了 VA）")
        return list(self.md.disasm(self.data[o:o + n], self.base + rva))

    def dis_func(self, rva):
        end = self.func_end(rva)
        return self.dis(rva, end - rva)

    def dump(self, rva, n=0x300):
        for i in self.dis(rva, n):
            line = f"{i.address:08x}  {i.bytes.hex():<20} {i.mnemonic} {i.op_str}"
            print(line)

    def str_at_ref(self, code_rva):
        """若该指令附近有 push imm32 指向字符串, 返回字符串"""
        insns = self.dis(code_rva, 0x20)
        for i in insns[:6]:
            if i.mnemonic in ('push', 'mov') and i.op_str.startswith('0x'):
                try: v = int(i.op_str, 16)
                except: continue
                r = v - self.base if v >= self.base else v
                o = self.rva2off(r)
                if o:
                    raw = self.data[o:o + 200].split(b'\0')[0]
                    if raw and all(32 <= c < 127 or c in (9, 10, 13) for c in raw[:60]):
                        return raw.decode('latin1')
        return None

    # --- 包一层: 字符串 -> 引用函数 ---
    def who_logs(self, s):
        res = []
        for rva, enc in self.find_str_rva(s):
            for x in self.xrefs(rva):
                f = self.func_of(x)
                res.append((s[:50], hex(rva), hex(x), hex(f) if f else None))
        for r in res: print("   ", r)
        return res
    # --- 调用者 / 被调用者 ---
    def callers(self, rva):
        """返回所有 call rva 的指令地址列表（RVA）"""
        out = []
        for name, va, vsz, ra, rs, ch in self.secs:
            if not (ch & 0x20000000):
                continue
            blob = self.data[ra:ra + rs]
            i = blob.find(b'\xe8')
            while i >= 0 and i + 5 <= len(blob):
                rel = struct.unpack_from('<i', blob, i + 1)[0]
                if va + i + 5 + rel == rva:
                    out.append(va + i)
                i = blob.find(b'\xe8', i + 1)
        return out

    def jmp_slots(self, rva):
        """虚表/函数指针表里指向 rva 的槽位（VA 或 RVA 形式）"""
        res = []
        for pat in (struct.pack('<I', self.base + rva), struct.pack('<I', rva)):
            i = self.data.find(pat)
            while i >= 0:
                r = self.off2rva(i)
                if r:
                    res.append(r)
                i = self.data.find(pat, i + 1)
        return res

def func_report(b, rva, maxn=4000):
    """打印函数: 大小 / 引用的字符串 / 调用的子函数"""
    insns = b.dis_func(rva)[:maxn]
    if not insns: return
    lo, hi = insns[0].address, insns[-1].address
    strs, callees = [], []
    for i in insns:
        if i.mnemonic in ('push', 'mov', 'cmp', 'lea') and ', ' in i.op_str and i.op_str.split(', ')[-1].startswith('0x'):
            try: v = int(i.op_str.split(', ')[-1], 16)
            except: v = 0
            if v:
                r = v - b.base if v >= b.base else v
                o = b.rva2off(r)
                if o:
                    raw = b.data[o:o + 240].split(b'\0')[0]
                    if len(raw) >= 4 and all(32 <= c < 127 or c in (9, 10, 13) for c in raw[:80]):
                        strs.append((hex(i.address), raw.decode('latin1')))
        if i.mnemonic in ('call', 'jmp') and i.op_str.startswith('0x'):
            t = int(i.op_str, 16) - b.base
            callees.append((hex(i.address), hex(t)))
    print(f"--- func {rva:#x} .. {hi:#x} ({hi-lo+len(insns[-1].bytes)} bytes, {len(insns)} insns)")
    seen = set()
    for a, s in strs:
        if s not in seen: print(f"   str {a}: {s!r}"); seen.add(s)
    print("   callees:", sorted(set(c[1] for c in callees)))
    return insns

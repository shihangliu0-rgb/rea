#!/usr/bin/env python3
"""PE xref helper: find string refs, recover function starts from call targets, disassemble."""
import pefile, struct, sys, re, json, bisect

class Bin:
    def __init__(self,path):
        self.path=path
        self.pe=pefile.PE(path,fast_load=True)
        self.data=open(path,'rb').read()
        self.base=self.pe.OPTIONAL_HEADER.ImageBase
        self.secs=[(s.Name.rstrip(b'\0').decode('latin1'),s.VirtualAddress,s.Misc_VirtualSize,s.PointerToRawData,s.SizeOfRawData,s.Characteristics) for s in self.pe.sections]
        self.text=[s for s in self.secs if s[5]&0x20000000][0]
        self.calls=self._calls()
    def rva2off(self,rva):
        for n,va,vsz,ra,rs,ch in self.secs:
            if va<=rva<va+max(vsz,rs): return ra+(rva-va)
        return None
    def off2rva(self,off):
        for n,va,vsz,ra,rs,ch in self.secs:
            if ra<=off<ra+rs: return va+(off-ra)
        return None
    def bytes_at(self,rva,n):
        o=self.rva2off(rva)
        return self.data[o:o+n]
    def _calls(self):
        t=self.text; start=t[3]; end=t[3]+t[4]
        blob=self.data[start:end]; base=t[1]
        out=[]
        i=0
        # find E8 (call rel32) and E9 (jmp rel32) - oversample, filtered later by capstone
        for m in re.finditer(rb'[\xe8\xe9]', blob):
            i=m.start()
            if i+5>len(blob): break
            rel=struct.unpack_from('<i',blob,i+1)[0]
            tgt=base+i+5+rel
            out.append((base+i,tgt,blob[i]))
        return out
    def call_targets_sorted(self):
        return sorted(set(t for _,t,_ in self.calls))
    def func_start(self,rva):
        tg=self.call_targets_sorted()
        i=bisect.bisect_right(tg,rva)-1
        # closest call target <= rva, plus heuristic: also look for int3/ret padding
        cand=tg[i] if i>=0 else self.text[1]
        return cand
    def xrefs(self,rva):
        """find push imm32 / mov reg,imm32 references to rva"""
        t=self.text; start=t[3]; end=t[3]+t[4]
        blob=self.data[start:end]; base=t[1]
        pat=struct.pack('<I',rva)
        res=[]
        i=blob.find(pat)
        while i>=0:
            if i>0:
                op=blob[i-1]
                if op in (0x68,0xb8,0xb9,0xba,0xbb,0xbc,0xbd,0xbe,0xbf,0xc7):  # push/mov imm
                    res.append(base+i-1)
            i=blob.find(pat,i+1)
        # lea reg,[imm32]
        for m in re.finditer(rb'\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]'+re.escape(pat), blob):
            res.append(base+m.start())
        return sorted(res)

def find_str(b, s, encoding='ascii'):
    tgt=s.encode(encoding)
    i=b.data.find(tgt)
    rv=[]
    while i>=0:
        r=b.off2rva(i)
        if r: rv.append(r)
        i=b.data.find(tgt,i+1)
    return rv

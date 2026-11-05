import sys; sys.path.insert(0,'/home/user/rea/re')
from kb import Bin

def read_str(b, rva, n=300):
    o=b.rva2off(rva)
    if o is None: return None
    raw=b.data[o:o+n].split(b'\0')[0]
    if not raw: return None
    if all(32<=c<127 or c in (9,10,13) for c in raw[:80]):
        return raw.decode('latin1')
    return None

def func_strings(b, rva, maxn=20000):
    res=[]
    for i in b.dis_func(rva)[:maxn]:
        vals=[]
        for part in i.op_str.replace('[',' ').replace(']',' ').replace('+',' ').replace('-',' ').replace('*',' ').replace(',',' ').split():
            if part.startswith('0x'):
                try: vals.append(int(part,16))
                except: pass
        for v in vals:
            r = v-b.base if v>=b.base else v
            s=read_str(b,r)
            if s: res.append((hex(i.address), s))
    return res

if __name__=='__main__':
    b=Bin(sys.argv[1])
    for a in sys.argv[2:]:
        rva=int(a,16)
        print(f"=== func {a}")
        seen=set()
        for x,s in func_strings(b,rva):
            if s in seen: continue
            print(f"   {x}: {s!r}"); seen.add(s)

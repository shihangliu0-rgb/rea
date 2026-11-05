import re,sys,os,pefile
def sec_data(pe):
    return [(s.Name.rstrip(b'\0').decode('latin1'), s.get_PointerToRawData_adj(), s.SizeOfRawData, s.VirtualAddress) for s in pe.sections]
def strings(path, minlen=5):
    d=open(path,'rb').read()
    out=[]
    for m in re.finditer(rb'[\x20-\x7e]{%d,}'%minlen, d):
        out.append(m.group().decode('latin1'))
    return out
for p in sys.argv[1:]:
    base=os.path.basename(p)
    ss=strings(p)
    # plain-ish: no '?' mangled, printable words
    keep=[s for s in ss if '?' not in s[:3] or True]
    with open(f'/home/user/rea/re/strings/{base}.txt','w') as f:
        for s in ss: f.write(s+'\n')
    plain=[s for s in ss if not s.startswith('.?') and '?' not in s]
    with open(f'/home/user/rea/re/strings/{base}.plain.txt','w') as f:
        for s in plain: f.write(s+'\n')
    print(base, len(ss), len(plain))

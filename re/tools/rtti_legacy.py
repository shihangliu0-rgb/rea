import pefile,struct,sys,json,os,re
out={}
for path in sys.argv[1:]:
    pe=pefile.PE(path,fast_load=True)
    base=pe.OPTIONAL_HEADER.ImageBase
    data=open(path,'rb').read()
    secs=[(s.Name.rstrip(b'\0').decode('latin1'),s.VirtualAddress,s.Misc_VirtualSize,s.PointerToRawData,s.SizeOfRawData) for s in pe.sections]
    def off2rva(off):
        for n,va,vsz,ra,rs in secs:
            if ra<=off<ra+rs: return va+(off-ra)
        return None
    def rva2off(rva):
        for n,va,vsz,ra,rs in secs:
            if va<=rva<va+max(vsz,rs): return ra+(rva-va)
        return None
    names={}
    for m in re.finditer(rb'\.\?A[VU][^\x00]{1,400}', data):
        rva=off2rva(m.start())
        if rva is None: continue
        names[rva-16]=m.group().decode('latin1')  # TD rva -> name
    # find COLs
    vtabs={}
    for td,rva_name in names.items():
        pat=struct.pack('<I',td)
        start=0
        while True:
            i=data.find(pat,start)
            if i<0: break
            start=i+1
            col_rva=off2rva(i-12)
            if col_rva is None: continue
            sig,off,cd=struct.unpack('<III',data[i-12:i])
            if sig!=0 or off!=0: continue
            # find vtable pointing to col
            vpat=struct.pack('<I',col_rva)
            j=0
            while True:
                k=data.find(vpat,j)
                if k<0: break
                j=k+1
                vt_rva=off2rva(k+4)
                if vt_rva is None: continue
                funcs=[]
                o=k+4
                while o+4<=len(data):
                    f=struct.unpack('<I',data[o:o+4])[0]
                    if f==0: break
                    # must be inside .text
                    if not (secs[0][1]<=f<secs[0][1]+secs[0][2]): break
                    funcs.append(f); o+=4
                if funcs:
                    vtabs.setdefault(rva_name,set()).add((vt_rva,tuple(funcs)))
    out[os.path.basename(path)]={k:[(a,list(b)) for a,b in v] for k,v in vtabs.items()}
    print(os.path.basename(path),"classes",len(names),"with vtables",len(vtabs))
json.dump(out,open('re/rtti_vtables.json','w'),indent=0)

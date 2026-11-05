import struct, sys
sys.path.insert(0,'/home/user/rea/re')
from kb import Bin

def classes(b):
    """返回 {修饰名: {'td':rva,'col':rva,'vtables':[rva,...]}}"""
    out={}
    data=b.data
    # 找 .?AV... 类型描述符名字
    i=0
    names=[]
    while True:
        i=data.find(b'.?AV',i)
        if i<0: break
        end=data.find(b'\0',i)
        names.append((i,end))
        i=end
    for s,e in names:
        nm=data[s:e].decode('latin1')
        name_rva=b.off2rva(s)
        if name_rva is None: continue
        td=name_rva-8                      # TypeDescriptor 起点
        pat=struct.pack('<II',0,0)+struct.pack('<I',td)
        j=data.find(pat)
        cols=[]
        while j>=0:
            cols.append(b.off2rva(j))
            j=data.find(pat,j+1)
        vtabs=[]
        for col in cols:
            if col is None: continue
            vp=struct.pack('<I',col); k=data.find(vp)
            while k>=0:
                # vtable = k+4 (col 指针放在 vtable-4)
                vt=b.off2rva(k+4)
                if vt is not None:
                    funcs=[]
                    p=k+4
                    while p+4<=len(data):
                        f=struct.unpack_from('<I',data,p)[0]
                        if not (b.textva<=f<b.textva+b.textvsz): break
                        funcs.append(f); p+=4
                    if funcs: vtabs.append((vt,funcs))
                k=data.find(vp,k+1)
        out[nm]={'td':td,'col':cols,'vtables':vtabs}
    return out

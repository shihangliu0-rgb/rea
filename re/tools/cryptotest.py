import base64, hashlib, struct, zlib, itertools, sys
def rc4(key, data):
    S=list(range(256)); j=0
    for i in range(256):
        j=(j+S[i]+key[i%len(key)])&0xff
        S[i],S[j]=S[j],S[i]
    out=bytearray(); i=j=0
    for b in data:
        i=(i+1)&0xff; j=(j+S[i])&0xff
        S[i],S[j]=S[j],S[i]
        out.append(b^S[(S[i]+S[j])&0xff])
    return bytes(out)
def score(b):
    if not b: return 0
    return sum(1 for c in b[:256] if 32<=c<127 or c in (9,10,13,0))/min(len(b),256)
cands=[b"987F0A62535468615A9F4F7560454219", b"B8ec24caf34ef7227c66767d29ffd3fb",
       b"987f0a62535468615a9f4f7560454219"]
files={
 'VersionInfo':open('config/VersionInfo','rb').read(),
 'kernel_pop':open('config/kernel_pop','rb').read(),
 'kernel_kernelb.cfg':open('config/kernel_kernelb.cfg','rb').read(),
 'PersonalSetting':base64.b64decode(''.join(open('config/users/3392342571c1267308ff27d7ee5e212d/PersonalSetting.xml','rb').read().decode('utf-16le').split())+'=='),
 'AppSettingApp':base64.b64decode(''.join(open('config/AppSettingApp.dat','rb').read().decode('utf-16le').split())+'=='),
}
for name,d in files.items():
    print("==",name,len(d))
    for k in cands:
        x=rc4(k,d); print("   rc4", k[:8], f"{score(x):.2f}", x[:40])

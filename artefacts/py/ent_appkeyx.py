import struct, math, hashlib

APPC = r"/mnt/c/Program Files (x86)/Compac/Contabilidad/AppKeyX.dll"
APPS = r"/mnt/c/Program Files (x86)/Compac/Servidor/AppKeyX.dll"

def sections(data):
    e = struct.unpack_from("<I", data, 0x3C)[0]
    ns = struct.unpack_from("<H", data, e+6)[0]
    osz = struct.unpack_from("<H", data, e+20)[0]
    opt = e+24
    sec = opt+osz
    out=[]
    for i in range(ns):
        nm = data[sec+i*40:sec+i*40+8].rstrip(b"\0").decode("latin1")
        vsz, vaddr, rsz, rptr = struct.unpack_from("<IIII", data, sec+i*40+8)
        out.append((nm, vaddr, vsz, rptr, rsz))
    return out

def ent(chunk):
    if not chunk: return 0.0
    freqs=[0]*256
    for b in chunk: freqs[b]+=1
    n=len(chunk)
    return -sum((f/n)*math.log2(f/n) for f in freqs if f)

for p in (APPC, APPS):
    d = open(p,"rb").read()
    secs = sections(d)
    print("=== %s (%d B) sha256 %s" % (p, len(d), hashlib.sha256(d).hexdigest()[:16]))
    for nm, vaddr, vsz, rptr, rsz in secs:
        print("  %-8s vaddr 0x%X vsz 0x%X rptr 0x%X rsz 0x%X" % (nm, vaddr, vsz, rptr, rsz))
    # entropia global por seccion y mapa fino de alta entropia en .data/.rdata
    for nm, vaddr, vsz, rptr, rsz in secs:
        if rsz == 0: continue
        chunk = d[rptr:rptr+rsz]
        e = ent(chunk)
        print("  %s entropia global = %.3f" % (nm, e))
        # ventanas 128B > 7.5 en secciones de datos
        if nm in (".data",".rdata",".jidata",".jedata",".appkey"):
            runs=[]; cur=None
            for i in range(0, max(0,len(chunk)-128), 32):
                if ent(chunk[i:i+128])>7.5:
                    if cur is None: cur=[i,i]
                    else: cur[1]=i
                else:
                    if cur: runs.append((cur[0],cur[1]+32)); cur=None
            if cur: runs.append((cur[0],cur[1]+32))
            merged=[]
            for a,b in runs:
                if merged and a-merged[-1][1]<=96: merged[-1]=(merged[-1][0],b)
                else: merged.append((a,b))
            if merged:
                print("    ventanas e>7.5: %d rangos:" % len(merged))
                for a,b in merged[:10]:
                    print("      rptr 0x%X-0x%X (RVA 0x%X, %d B)" % (a+rptr, b+rptr, a+vaddr, b-a))

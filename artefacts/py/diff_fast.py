import struct, math

C = r"/mnt/c/Program Files (x86)/Compac/Contabilidad/contabilidad_i.exe"
B = r"/mnt/c/Program Files (x86)/Compac/Bancos/bancos_i.exe"

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
    fr=[0]*256
    for b in chunk: fr[b]+=1
    n=len(chunk)
    return -sum((f/n)*math.log2(f/n) for f in fr if f)

dc=open(C,"rb").read(); db=open(B,"rb").read()
sc=sections(dc)
n=min(len(dc),len(db))
# 1) bloques de 4096 que difieren (comparacion C-veloz)
BS=4096
diffblocks=[i for i in range(0,n,BS) if dc[i:i+BS]!=db[i:i+BS]]
print("bloques 4K diferentes:", len(diffblocks), "de", n//BS)
# 2) localizar rangos finos dentro de cada bloque diferente (union con vecinos)
ranges=[]
for blk in diffblocks:
    a,b=blk,min(blk+BS,n)
    # expandir al bloque entero y afinar
    lo,hi=a,b
    # afinar: primer/ultimo byte distinto dentro de [lo,hi)
    k=lo
    while k<hi and dc[k]==db[k]: k+=1
    lo=k
    k=hi-1
    while k>=lo and dc[k]==db[k]: k-=1
    hi=k+1
    # afinar bordes contra bloques vecinos iguales
    ranges.append((lo,hi))
# 3) fusionar rangos adyacentes
ranges.sort()
merged=[]
for a,b in ranges:
    if merged and a<=merged[-1][1]+16: merged[-1]=(merged[-1][0],max(merged[-1][1],b))
    else: merged.append((a,b))
print("rangos de diferencia fusionados:", len(merged))

def secname(off):
    for nm,vaddr,vsz,rptr,rsz in sc:
        if rptr<=off<rptr+max(rsz,1): return nm
    return "?"

import collections
bysec=collections.defaultdict(list)
for a,b in merged:
    bysec[secname(a)].append((a,b))
total=0
for sn in sorted(bysec):
    tot=sum(b-a for a,b in bysec[sn])
    total+=tot
    print("\n== %s: %d rangos, %d B total" % (sn,len(bysec[sn]),tot))
    for a,b in bysec[sn][:40]:
        seg=dc[a:b]
        e=ent(seg) if len(seg)>=32 else 0.0
        print("   0x%X-0x%X (%d B) e=%.2f  ini:%s" % (a,b,b-a,e,seg[:16].hex()))
    if len(bysec[sn])>40: print("   ... +%d rangos" % (len(bysec[sn])-40))
print("\nTOTAL bytes diferentes: %d de %d (%.2f%%)" % (total,n,100.0*total/n))

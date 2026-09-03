import struct, math, os

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
sc=sections(dc); sb=sections(db)
n=min(len(dc),len(db))
# diff lineal con salto por bloques (rapido: compara 64KB a la vez)
out=[]; cur=None; i=0
blk=65536
while i<n:
    j=i
    while j<n and j-i<blk and dc[j]==db[j]:
        j+=1
    if j<n and j-i<blk:
        # hay diferencia dentro del bloque -> localizar fino
        k=i
        while k<min(i+blk,n):
            if dc[k]!=db[k]:
                if cur is None: cur=[k,k]
                else: cur[1]=k
            else:
                if cur:
                    if cur[1]-cur[0]>=4: out.append(tuple(cur))
                    cur=None
            k+=1
        if cur:
            if cur[1]-cur[0]>=4: out.append(tuple(cur))
            cur=None
        i=j+1  # sigue tras el bloque con dif
        while i<n and dc[i]==db[i]: i+=1
    else:
        i=i+blk
if cur and cur[1]-cur[0]>=4: out.append(tuple(cur))

def secname(secs,off):
    for nm,vaddr,vsz,rptr,rsz in secs:
        if rptr<=off<rptr+max(rsz,1): return nm
    return "?"

# filtrar: fuera de .jedata/.jidata/.appkey, tam 8..400
cand=[r for r in out if r[1]-r[0]+1<=400 and secname(sc,r[0]) not in (".jedata",".jidata",".appkey")]
print("dif C vs B totales>=4B:", len(out), "| candidatos (8-400B, fuera jedata/jidata/appkey):", len(cand))
bysec={}
for a,b2 in cand:
    sn=secname(sc,a)
    bysec.setdefault(sn,[]).append((a,b2))
for sn,rs in sorted(bysec.items()):
    print("\n-- %s: %d rangos" % (sn,len(rs)))
    for a,b2 in rs[:30]:
        seg=dc[a:b2+1]
        e=ent(seg) if len(seg)>=32 else 0
        print("   0x%X-0x%X (%d B) e=%.2f  ini:%s" % (a,b2,b2-a+1,e,seg[:12].hex()))
    if len(rs)>30: print("   ... +%d" % (len(rs)-30))

# entropia rapida de ficheros pequenos
small=[
 r"/mnt/c/Program Files (x86)/Compac/Contabilidad/contabilidad_i.dat",
 r"/mnt/c/Program Files (x86)/Compac/Contabilidad/cti.exe",
 r"/mnt/c/Program Files (x86)/Compac/Servidor/servidor_servicio.exe",
 r"/mnt/c/Program Files (x86)/Compac/Servidor/CONTPAQ_I_SERVIDOR.exe",
]
for p in small:
    d=open(p,"rb").read(); sz=len(d)
    best=(0,0)
    for i in range(0,max(0,sz-256),128):
        e=ent(d[i:i+256])
        if e>best[0]: best=(e,i)
    print("== %s (%d B) mejor ventana e=%.3f en 0x%X" % (os.path.basename(p),sz,best[0],best[1]))

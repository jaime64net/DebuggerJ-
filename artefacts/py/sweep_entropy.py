import struct, math, os

FILES = [
 r"/mnt/c/Program Files (x86)/Compac/Contabilidad/contabilidad_i.exe",
 r"/mnt/c/Program Files (x86)/Compac/Bancos/bancos_i.exe",
 r"/mnt/c/Program Files (x86)/Compac/Contabilidad/contabilidad_i.dat",
 r"/mnt/c/Program Files (x86)/Compac/Contabilidad/cti.exe",
 r"/mnt/c/Program Files (x86)/Compac/Servidor/servidor_servicio.exe",
 r"/mnt/c/Program Files (x86)/Compac/Servidor/CONTPAQ_I_SERVIDOR.exe",
]
EXTRA = []  # dtz del servidor de licencias se anaden si existen
base = r"/mnt/c/Program Files (x86)/Compac"
for root, dirs, fs in os.walk(base):
    for f in fs:
        if f.lower().endswith((".dtz",".dat",".dll")) and "servidor" in root.lower():
            EXTRA.append(os.path.join(root,f))
    if len(EXTRA) > 6: break
FILES += EXTRA[:6]

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

def secname_of(secs, off):
    for nm,vaddr,vsz,rptr,rsz in secs:
        if rptr <= off < rptr+max(rsz,1): return nm
    return "?"

for p in FILES:
    if not os.path.exists(p):
        print("skip", p); continue
    d = open(p,"rb").read()
    sz = len(d)
    secs = sections(d) if d[:2]==b"MZ" else []
    # 1) ventanas 256B e>7.6 por TODA la imagen (paso 64) — blob cripto real
    runs=[]; cur=None
    step = 256
    for i in range(0, max(0,sz-256), 64):
        if ent(d[i:i+256])>7.6:
            if cur is None: cur=[i,i]
            else: cur[1]=i
        else:
            if cur: runs.append((cur[0],cur[1]+256)); cur=None
    if cur: runs.append((cur[0],cur[1]+256))
    merged=[]
    for a,b in runs:
        if merged and a-merged[-1][1]<=192: merged[-1]=(merged[-1][0],b)
        else: merged.append((a,b))
    print("== %s (%d B) ventanas e>7.6: %d rangos" % (os.path.basename(p), sz, len(merged)))
    for a,b in merged[:10]:
        print("   0x%X-0x%X (%d B) [%s] e=%.3f" % (a,b,b-a,secname_of(secs,a) if secs else "?", ent(d[a:a+256])))

# caracterizar .jedata de contabilidad: prologos? codigo? strings?
d = open(r"/mnt/c/Program Files (x86)/Compac/Contabilidad/contabilidad_i.exe","rb").read()
secs = sections(d)
for nm in (".jedata",):
    s = [x for x in secs if x[0]==nm][0]
    chunk = d[s[3]:s[3]+min(s[4], 0x4000)]
    print("\n.jedata rptr 0x%X primeros 0x100:" % s[3])
    for i in range(0,0x100,16):
        hexs=" ".join("%02x"%b for b in chunk[i:i+16])
        asc="".join(chr(b) if 32<=b<127 else "." for b in chunk[i:i+16])
        print("   %08X  %-47s %s" % (s[3]+i, hexs, asc))
    # contar prologos 55 8b ec en primeros 1MB
    pro = chunk.count(bytes.fromhex("558bec"))
    print("prologos 55 8B EC en primeros 0x4000: %d" % pro)
    nulls = chunk[:0x4000].count(0)
    print("bytes 0x00 en 0x4000: %d (%.1f%%)" % (nulls, 100.0*nulls/0x4000))

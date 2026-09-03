import struct, math, os

C = r"/mnt/c/Program Files (x86)/Compac/Contabilidad/contabilidad_i.exe"
B = r"/mnt/c/Program Files (x86)/Compac/Bancos/bancos_i.exe"

def sections(data):
    e = struct.unpack_from("<I", data, 0x3C)[0]
    ns = struct.unpack_from("<H", data, e+6)[0]
    osz = struct.unpack_from("<H", data, e+20)[0]
    opt = e+24
    ib = struct.unpack_from("<I", data, opt+28)[0]
    sec = opt+osz
    out = []
    for i in range(ns):
        nm = data[sec+i*40:sec+i*40+8].rstrip(b"\0").decode("latin1")
        vsz, vaddr, rsz, rptr = struct.unpack_from("<IIII", data, sec+i*40+8)
        out.append((nm, vaddr, vsz, rptr, rsz))
    return ib, out

def v2o(data, va, secs, ib):
    for nm, vaddr, vsz, rptr, rsz in secs:
        if vaddr <= va < vaddr + max(vsz, rsz):
            off = va - vaddr
            if off < rsz: return rptr + off
    return None

def ent(chunk):
    if not chunk: return 0.0
    freqs = [0]*256
    for b in chunk: freqs[b] += 1
    n = len(chunk)
    return -sum((f/n)*math.log2(f/n) for f in freqs if f)

def entmap(data, sec, winsz=256, thr=7.4, cap=25):
    nm, vaddr, vsz, rptr, rsz = sec
    chunk = data[rptr:rptr+rsz]
    res = []
    for i in range(0, len(chunk)-winsz, 64):
        e = ent(chunk[i:i+winsz])
        if e > thr: res.append((i, e))
    return res

dc = open(C,"rb").read()
db = open(B,"rb").read()
ibc, secsc = sections(dc)
ibb, secsb = sections(db)
print("sections contabilidad:", [(n, hex(v), hex(r), hex(rs)) for n,v,_,r,rs in secsc])
for nm in (".appkey", ".jidata", ".jedata", ".config"):
    for ib, secs, tag in ((ibc,secsc,"C"),(ibb,secsb,"B")):
        s = [x for x in secs if x[0]==nm]
        if s: print("  %s %s: vaddr 0x%X vsz 0x%X rptr 0x%X rsz 0x%X" % (tag, nm, s[0][1], s[0][2], s[0][3], s[0][4]))

# --- 1) .appkey head annotated (contabilidad) ---
s_ak = [x for x in secsc if x[0]==".appkey"][0]
ak = dc[s_ak[3]:s_ak[3]+s_ak[4]]
print("\n.appkey head dwords (fileoff base 0x%X):" % s_ak[3])
for i in range(0, 0x90, 4):
    d = struct.unpack_from("<I", ak, i)[0]
    print("  +0x%02X  %08X  %s" % (i, d, "(RVA .appkey+%X)" % (d-s_ak[1]) if s_ak[1] <= d < s_ak[1]+s_ak[2] else ("(VA)" if 0x400000 <= d < 0x60000000 else "")))

# --- 2) structs referenced (.jidata around 0x4FEA000) ---
s_jd = [x for x in secsc if x[0]==".jidata"][0]
jd = dc[s_jd[3]:s_jd[3]+s_jd[4]]
base = 0x4FEA000 - s_jd[1]
print("\n.jidata 0x4FEA000..0x4FEA220 (rptr 0x%X):" % s_jd[3])
for i in range(base, base+0x220, 16):
    chunk = jd[i:i+16]
    hexs = " ".join("%02x"%b for b in chunk)
    asc = "".join(chr(b) if 32<=b<127 else "." for b in chunk)
    dw = [struct.unpack_from("<I", jd, i+k)[0] for k in (0,4,8,12)]
    print("  %08X  %-47s %-16s %s" % (0x4FEA000+i-base, hexs, " ".join("%08X"%d for d in dw), asc))

# --- 3) entropy map .appkey y .jidata (ambos exes) ---
for nm in (".appkey", ".jidata"):
    print("\nentropia>7.4 en %s (w256):" % nm)
    for ib, secs, data, tag in ((ibc,secsc,dc,"C"),(ibb,secsb,db,"B")):
        s = [x for x in secs if x[0]==nm][0]
        res = entmap(data, s)
        if res:
            # agrupar en rangos
            ranges = []
            for off,e in res:
                if ranges and off - ranges[-1][1] <= 128: ranges[-1]=(ranges[-1][0], off)
                else: ranges.append((off,off))
            rng = ", ".join("%X-%X" % (a+ s[3], b+64+s[3]) for a,b in ranges[:12])
            print("  %s: %d ventanas -> %s" % (tag, len(res), rng))
        else:
            print("  %s: ninguna ventana" % tag)

# --- 4) diff .appkey/.jidata C vs B (rangos contiguos de diferencia) ---
print("\ndiff C vs B:")
for nm in (".appkey", ".jidata"):
    sc = [x for x in secsc if x[0]==nm][0]; sb = [x for x in secsb if x[0]==nm][0]
    a = dc[sc[3]:sc[3]+sc[4]]; bb = db[sb[3]:sb[3]+sb[4]]
    n = min(len(a), len(bb))
    ranges = []; cur=None
    for i in range(n):
        if a[i]!=bb[i]:
            if cur is None: cur=[i,i]
            else: cur[1]=i
        else:
            if cur: ranges.append(tuple(cur)); cur=None
    if cur: ranges.append(tuple(cur))
    big = [r for r in ranges if r[1]-r[0]>=8]
    print("  %s: %d rangos dif >=8B (%d total)" % (nm, len(big), len(ranges)))
    for a_,b_ in big[:16]:
        print("    0x%X-0x%X (%d B)" % (a_+sc[3], b_+sc[3], b_-a_+1))
    if len(big)>16: print("    ... +%d mas" % (len(big)-16))

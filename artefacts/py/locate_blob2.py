import struct, math

C = r"/mnt/c/Program Files (x86)/Compac/Contabilidad/contabilidad_i.exe"
B = r"/mnt/c/Program Files (x86)/Compac/Bancos/bancos_i.exe"

def sections(data):
    e = struct.unpack_from("<I", data, 0x3C)[0]
    ns = struct.unpack_from("<H", data, e+6)[0]
    osz = struct.unpack_from("<H", data, e+20)[0]
    opt = e+24
    sec = opt+osz
    out = []
    for i in range(ns):
        nm = data[sec+i*40:sec+i*40+8].rstrip(b"\0").decode("latin1")
        vsz, vaddr, rsz, rptr = struct.unpack_from("<IIII", data, sec+i*40+8)
        out.append((nm, vaddr, vsz, rptr, rsz))
    return out

def ent(chunk):
    if not chunk: return 0.0
    freqs = [0]*256
    for b in chunk: freqs[b] += 1
    n = len(chunk)
    return -sum((f/n)*math.log2(f/n) for f in freqs if f)

dc = open(C,"rb").read(); db = open(B,"rb").read()
sc = sections(dc); sb = sections(db)
def sec(secs, nm): return [x for x in secs if x[0]==nm][0]

# --- .idata dump 0x4FEA000..0x4FEA200 (fileoff base rptr) ---
sid = sec(sc, ".idata")
print(".idata vaddr 0x%X rptr 0x%X rsz 0x%X" % (sid[1], sid[3], sid[4]))
raw = dc[sid[3]:sid[3]+sid[4]]
for i in range(0, 0x220, 16):
    if i+16 > len(raw): break
    chunk = raw[i:i+16]
    hexs = " ".join("%02x"%b for b in chunk)
    asc = "".join(chr(b) if 32<=b<127 else "." for b in chunk)
    dw = [struct.unpack_from("<I", raw, i+k)[0] for k in (0,4,8,12)]
    ann = []
    for d in dw:
        if 0x4FA0000 <= d <= 0x5F00000: ann.append("RVA:%X" % d)
        elif d==0: ann.append("")
        else: ann.append("")
    print("  RVA %08X  %-47s  %-44s %s" % (sid[1]+i, hexs, " ".join("%08X"%d for d in dw), asc))

# --- entropia + diff sobre .appkey/.jidata/.jedata (C y B) ---
print("\n=== mapa entropia >7.4 ===")
for nm in (".appkey", ".jidata", ".jedata"):
    print("-- %s" % nm)
    for tag, secs, data in (("C",sc,dc),("B",sb,db)):
        s = sec(secs, nm)
        raw2 = data[s[3]:s[3]+s[4]]
        runs=[]; cur=None
        for i in range(0, max(0,len(raw2)-256), 64):
            if ent(raw2[i:i+256]) > 7.4:
                if cur is None: cur=[i,i]
                else: cur[1]=i
            else:
                if cur: runs.append((cur[0],cur[1]+64)); cur=None
        if cur: runs.append((cur[0],cur[1]+64))
        merged=[]
        for a,b2 in runs:
            if merged and a - merged[-1][1] <= 192: merged[-1]=(merged[-1][0],b2)
            else: merged.append((a,b2))
        tot = sum(b2-a for a,b2 in merged)
        print("  %s: %d ventanas alta-entropia, %d rangos, %d B total" % (tag, len(runs), len(merged), tot))
        for a,b2 in merged[:8]:
            print("     fileoff 0x%X-0x%X (RVA 0x%X-0x%X, %d B) e=%.3f" % (a+s[3], b2+s[3], a+s[1], b2+s[1], b2-a, ent(raw2[a:a+256])))

print("\n=== diff C vs B ===")
for nm in (".appkey", ".jidata", ".jedata"):
    sa = sec(sc, nm); sbb = sec(sb, nm)
    a = dc[sa[3]:sa[3]+sa[4]]; b = db[sbb[3]:sbb[3]+sbb[4]]
    n = min(len(a), len(b))
    ranges=[]; cur=None
    for i in range(n):
        if a[i]!=b[i]:
            if cur is None: cur=[i,i]
            else: cur[1]=i
        else:
            if cur: ranges.append(tuple(cur)); cur=None
    if cur: ranges.append(tuple(cur))
    big=[r for r in ranges if r[1]-r[0]>=8]
    print("-- %s (C rptr 0x%X, B rptr 0x%X): %d rangos dif>=8B" % (nm, sa[3], sbb[3], len(big)))
    for a_,b2_ in big[:14]:
        print("     C fileoff 0x%X-0x%X (RVA 0x%X, %dB)" % (a_+sa[3], b2_+sa[3], a_+sa[1], b2_-a_+1))
    if len(big)>14: print("     ... +%d mas" % (len(big)-14))

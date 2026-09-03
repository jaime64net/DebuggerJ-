import os, struct

BLOB = open(r"/mnt/c/902B2E65508C6.EE7","rb").read()
SIG16 = BLOB[:16]
ROOT = "/mnt/c/Program Files (x86)/Compac"

def scan(p):
    try:
        data = open(p,"rb").read()
    except Exception as e:
        print("  ERR", p, e); return None
    r = {}
    r["size"] = len(data)
    reg = data[0x3270:0x3270+99]
    r["cc99"] = reg.count(0xCC)
    # longest CC run
    best=(0,0); cur=None
    for i,b in enumerate(data):
        if b==0xCC:
            if cur is None: cur=i
        else:
            if cur is not None:
                if i-cur>best[1]-best[0]: best=(cur,i)
                cur=None
    if cur is not None and len(data)-cur>best[1]-best[0]: best=(cur,len(data))
    r["ccrun"]=(best[0],best[1]-best[0])
    hits=[]; s=0
    while True:
        j=data.find(SIG16,s)
        if j<0: break
        hits.append(j); s=j+1
    r["blobhits"]=hits
    return r

print("### A) scan extendido de ficheros clave del stack")
extra = [
 r"/mnt/c/Program Files (x86)/Compac/Contabilidad/librerias.dll",
 r"/mnt/c/Program Files (x86)/Compac/Contabilidad/contpaqi_rt.dll",
 r"/mnt/c/Program Files (x86)/Compac/Contabilidad/contabilidad_i.mgr",
 r"/mnt/c/Program Files (x86)/Compac/Contabilidad/contabilidad_i.dtx",
 r"/mnt/c/Program Files (x86)/Compac/Contabilidad/contabilidad_i.dat",
 r"/mnt/c/Program Files (x86)/Compac/Contabilidad/CommonRA.dat",
 r"/mnt/c/Program Files (x86)/Compac/Servidor/CONTPAQ_I_SERVIDOR.mgr",
 r"/mnt/c/Program Files (x86)/Compac/Servidor/CONTPAQ_I_SERVIDOR.dtx",
 r"/mnt/c/Program Files (x86)/Compac/Servidor/servidor_servicio.mgr",
 r"/mnt/c/Program Files (x86)/Compac/Servidor/servidor_servicio.dtx",
 r"/mnt/c/Program Files (x86)/Compac/Servidor de Licencias/AppKey/AppKeyLicenseServer.exe",
 r"/mnt/c/Program Files (x86)/Compac/Servidor de Licencias/AppKey/CrypKeyDLL.dll",
]
for p in extra:
    r = scan(p)
    if r: print(" %-70s size=%-10d cc99@0x3270=%-3d ccrun=0x%X/%d blobhits=%s" % (
        os.path.basename(p), r["size"], r["cc99"], r["ccrun"][0], r["ccrun"][1], [hex(h) for h in r["blobhits"]]))

print("\n### B) inventario: exes bajo Compac con 99 CC en 0x3270 (parcheados)")
for dirpath, dirnames, filenames in os.walk(ROOT):
    for fn in sorted(filenames):
        if fn.lower().endswith(".exe"):
            p = os.path.join(dirpath, fn)
            try:
                sz = os.path.getsize(p)
            except Exception:
                continue
            if sz < 50000:  # solo exes con PE relevante
                continue
            r = scan(p)
            if r and r["cc99"] == 99:
                print("  PATCHED: %s  (%d B)" % (p.replace("/mnt/c/","C:\\").replace("/","\\"), sz))
            elif r and r["cc99"] > 0:
                print("  parcial : %s  cc=%d" % (p.replace("/mnt/c/","C:\\").replace("/","\\"), r["cc99"]))
print("\n### C) PE parse contabilidad_i.exe (mapeo fileoff 0x3270 -> RVA)")
for name in [r"/mnt/c/Program Files (x86)/Compac/Contabilidad/contabilidad_i.exe",
             r"/mnt/c/Program Files (x86)/Compac/Contabilidad/contabilidad_i.bin",
             r"/mnt/c/Program Files (x86)/Compac/Servidor/CONTPAQ_I_SERVIDOR.exe"]:
    data = open(name,"rb").read()
    e = struct.unpack_from("<I", data, 0x3C)[0]
    ns = struct.unpack_from("<H", data, e+6)[0]
    osz = struct.unpack_from("<H", data, e+20)[0]
    opt = e+24
    ep = struct.unpack_from("<I", data, opt+16)[0]
    ib = struct.unpack_from("<I", data, opt+28)[0]
    print("  %s" % os.path.basename(name))
    print("    PE=0x%X nsect=%d entryRVA=0x%X imageBase=0x%X" % (e, ns, ep, ib))
    sec = opt+osz
    for i in range(ns):
        nm = data[sec+i*40:sec+i*40+8].rstrip(b"\0").decode("latin1")
        vsz, vaddr, rsz, rptr = struct.unpack_from("<IIII", data, sec+i*40+8)
        print("      %-8s vaddr=0x%X vsize=0x%X rptr=0x%X rsize=0x%X" % (nm, vaddr, vsz, rptr, rsz))
    # fileoff 0x3270 -> RVA
    for i in range(ns):
        vsz, vaddr, rsz, rptr = struct.unpack_from("<IIII", data, sec+i*40+8)
        if rptr <= 0x3270 < rptr+max(rsz,1):
            rva = 0x3270 - rptr + vaddr
            print("    fileoff 0x3270 -> section %s RVA 0x%X (VA 0x%X)" % (nm, rva, ib+rva))
            print("    fileoff 0x32D3 -> RVA 0x%X (VA 0x%X)" % (0x32D3-rptr+vaddr, ib+0x32D3-rptr+vaddr))
            break

import sys, os

BLOB = open(r"/mnt/c/902B2E65508C6.EE7","rb").read()
print("blob len:", len(BLOB), "head:", BLOB[:16].hex())

SIG16 = BLOB[:16]

cands = [
 r"C:\Program Files (x86)\Compac\Contabilidad\contabilidad_i.exe",
 r"C:\Program Files (x86)\Compac\Contabilidad\contabilidad_i.bin",
 r"C:\Program Files (x86)\Compac\Contabilidad\cti.exe",
 r"C:\Program Files (x86)\Compac\Contabilidad\AppKeyX.dll",
 r"C:\Program Files (x86)\Compac\Servidor\CONTPAQ_I_SERVIDOR.exe",
 r"C:\Program Files (x86)\Compac\Servidor\CONTPAQ_I_SERVIDOR.bin",
 r"C:\Program Files (x86)\Compac\Servidor\servidor_servicio.exe",
 r"C:\Program Files (x86)\Compac\Servidor\servidor_servicio.bin",
 r"C:\Program Files (x86)\Compac\Servidor de Licencias\AppKey\AppKeyAuthServer.exe",
]

for c in cands:
    p = "/mnt/" + c.replace("\\","/").replace("Program Files (x86)","Program Files (x86)").lstrip("/")
    p = "/mnt/c/" + c[2:].replace("\\","/")
    if not os.path.exists(p):
        print("MISSING:", c); continue
    data = open(p,"rb").read()
    print("\n== ", c, " size=", len(data))
    # longest CC run
    best = (0,0); cur = None
    for i,b in enumerate(data):
        if b == 0xCC:
            if cur is None: cur = i
        else:
            if cur is not None:
                if i-cur > best[1]-best[0]: best = (cur,i)
                cur = None
    if cur is not None and len(data)-cur > best[1]-best[0]: best = (cur,len(data))
    print("   longest CC run: off=0x%X len=%d" % (best[0], best[1]-best[0]))
    # occurrences of blob head (16) and full blob
    hits = []
    start = 0
    while True:
        j = data.find(SIG16, start)
        if j < 0: break
        hits.append(j); start = j+1
    print("   hits of blob[0:16]:", [hex(h) for h in hits[:10]], "count=", len(hits))
    fh = data.find(BLOB)
    if fh >= 0:
        print("   FULL 88-byte blob found at 0x%X" % fh)
    # CC run check around 0x3270..0x32D3 and dump that region
    reg = data[0x3270:0x32D3]
    print("   [0x3270..0x32D3] CC count:", reg.count(0xCC), "head:", reg[:16].hex())

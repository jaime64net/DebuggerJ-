import os

pairs = [
 (r"/mnt/c/Program Files (x86)/Compac/Contabilidad/contabilidad_i.bin",
  r"/mnt/c/Program Files (x86)/Compac/Contabilidad/contabilidad_i.exe"),
 (r"/mnt/c/Program Files (x86)/Compac/Contabilidad/cti.exe",
  r"/mnt/c/Program Files (x86)/Compac/Contabilidad/contabilidad_i.exe"),
 (r"/mnt/c/Program Files (x86)/Compac/Servidor/CONTPAQ_I_SERVIDOR.bin",
  r"/mnt/c/Program Files (x86)/Compac/Servidor/CONTPAQ_I_SERVIDOR.exe"),
 (r"/mnt/c/Program Files (x86)/Compac/Servidor/servidor_servicio.bin",
  r"/mnt/c/Program Files (x86)/Compac/Servidor/servidor_servicio.exe"),
 (r"/mnt/c/Program Files (x86)/Compac/Contabilidad/contabilidad_i.bin",
  r"/mnt/c/Program Files (x86)/Compac/Bancos/bancos_i.exe"),
]

def find_all(data, pat, limit=20):
    out=[]; s=0
    while True:
        j=data.find(pat,s)
        if j<0: break
        out.append(j); s=j+1
        if len(out)>=limit: break
    return out

for binp, exp in pairs:
    if not (os.path.exists(binp) and os.path.exists(exp)):
        print("MISSING", binp, exp); continue
    b = open(binp,"rb").read()
    x = open(exp,"rb").read()
    blob99 = b[0x3270:0x3270+99]
    print("\n== %s -> %s" % (os.path.basename(binp), os.path.basename(exp)))
    print("   bin99[0:16]:", blob99[:16].hex())
    hits = find_all(x, blob99[:16])
    if hits:
        print("   hits de bin99[:16] en exe:", [hex(h) for h in hits[:10]])
        for h in hits[:3]:
            print("     contexto exe 0x%X: %s" % (h, x[h:h+99].hex()))
    else:
        print("   sin hits de bin99[:16] en el exe")
    full = find_all(x, blob99)
    print("   hits del bin99 COMPLETO en exe:", [hex(h) for h in full[:5]] if full else "ninguno")

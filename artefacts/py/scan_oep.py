import os, struct

EXES = [
 (r"/mnt/c/Program Files (x86)/Compac/Contabilidad/contabilidad_i.exe", 0x50EC080),
 (r"/mnt/c/Program Files (x86)/Compac/Bancos/bancos_i.exe", None),
 (r"/mnt/c/Program Files (x86)/Compac/Servidor/CONTPAQ_I_SERVIDOR.exe", None),
 (r"/mnt/c/Program Files (x86)/Compac/Servidor/servidor_servicio.exe", None),
]

def sections(data):
    e = struct.unpack_from("<I", data, 0x3C)[0]
    ns = struct.unpack_from("<H", data, e+6)[0]
    osz = struct.unpack_from("<H", data, e+20)[0]
    opt = e+24
    ep = struct.unpack_from("<I", data, opt+16)[0]
    ib = struct.unpack_from("<I", data, opt+28)[0]
    sec = opt+osz
    out = []
    for i in range(ns):
        nm = data[sec+i*40:sec+i*40+8].rstrip(b"\0").decode("latin1")
        vsz, vaddr, rsz, rptr = struct.unpack_from("<IIII", data, sec+i*40+8)
        out.append((nm, vaddr, vsz, rptr, rsz))
    return ib, ep, out

def sec_of(off, secs):
    for nm, vaddr, vsz, rptr, rsz in secs:
        if rptr <= off < rptr + max(rsz,1):
            return "%s (RVA 0x%X)" % (nm, off - rptr + vaddr)
    return "?"

def find_all(data, pat):
    out = []; s = 0
    while True:
        j = data.find(pat, s)
        if j < 0: break
        out.append(j); s = j+1
    return out

for path, known_ep in EXES:
    data = open(path,"rb").read()
    ib, ep, secs = sections(data)
    print("\n=== %s (%d B)  imageBase=0x%X entryRVA=0x%X" % (os.path.basename(path), len(data), ib, ep))
    # refs to the hole VAs (little-endian literals) and neighbor OEP addrs
    for va in (0x403E70, 0x403ED3, 0x403E71, 0x403E72):
        pat = struct.pack("<I", va)
        hits = find_all(data, pat)
        if hits:
            for h in hits[:8]:
                print("   lit 0x%X -> fileoff 0x%X [%s]" % (va, h, sec_of(h, secs)))
            if len(hits) > 8: print("     ... +%d mas" % (len(hits)-8))
    # imports: VirtualProtect / WriteProcessMemory / VirtualAlloc names present?
    for name in (b"VirtualProtect\0", b"WriteProcessMemory\0", b"VirtualAlloc\0", b"VirtualProtectEx\0"):
        if name in data:
            print("   importa:", name.rstrip(b"\0").decode())
    # dump .appkey head (first 0x180 bytes of its raw) when present
    for nm, vaddr, vsz, rptr, rsz in secs:
        if nm == ".appkey":
            chunk = data[rptr:rptr+min(0x180, rsz)]
            print("   .appkey rptr=0x%X rsize=0x%X; cabecera:" % (rptr, rsz))
            for i in range(0, len(chunk), 16):
                hexs = " ".join("%02x" % b for b in chunk[i:i+16])
                asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk[i:i+16])
                print("     %08x  %-47s  %s" % (rptr+i, hexs, asc))

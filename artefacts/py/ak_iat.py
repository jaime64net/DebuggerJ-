#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ak_iat.py — mapea slots IAT de AppKeyX.dll y busca call-sites en CODE.
Uso: ak_iat.py [func1 func2 ...]
Si se dan funciones, imprime el slot (RVA/VA runtime) y todos los FF15/FF25 que lo referencian en CODE."""
import sys, struct

PATH = "/mnt/c/Program Files (x86)/Compac/Contabilidad/AppKeyX.dll"
BASE_RT = 0x5DF0000
d = open(PATH, "rb").read()
pe = struct.unpack_from("<I", d, 0x3C)[0]
opt = pe + 24
magic = struct.unpack_from("<H", d, opt)[0]
optsz = 224 if magic == 0x10B else 240
imagebase = struct.unpack_from("<I", d, opt + 28)[0]
nsec = struct.unpack_from("<H", d, pe + 6)[0]
secs = []
off = opt + optsz
for s in range(nsec):
    name = d[off + s*40: off + s*40 + 8].rstrip(b"\0").decode("latin1")
    vsize = struct.unpack_from("<I", d, off + s*40 + 8)[0]
    vaddr = struct.unpack_from("<I", d, off + s*40 + 12)[0]
    roff = struct.unpack_from("<I", d, off + s*40 + 20)[0]
    rsize = struct.unpack_from("<I", d, off + s*40 + 16)[0]
    secs.append((name, vaddr, vsize, roff, rsize))

def r2o(rva):
    for n, va, vs, ro, rs in secs:
        if va <= rva < va + max(vs, rs):
            return ro + (rva - va)
    return None

def dd(idx):
    return struct.unpack_from("<I", d, opt + 96 + idx*8)[0]

# imports -> (dll, func, slot_rva)
imports = []
imp_rva = dd(1)
off = r2o(imp_rva)
while True:
    ilt = struct.unpack_from("<I", d, off)[0]
    name_rva = struct.unpack_from("<I", d, off + 12)[0]
    ft = struct.unpack_from("<I", d, off + 16)[0]
    if name_rva == 0:
        break
    noff = r2o(name_rva)
    end = d.index(b"\0", noff)
    dll = d[noff:end].decode("latin1")
    iat_rva = ilt if r2o(ilt) is not None else ft
    io = r2o(iat_rva)
    idx = 0
    while io is not None:
        v = struct.unpack_from("<I", d, io)[0]
        if v == 0:
            break
        if v & 0x80000000:
            fname = "ord#%d" % (v & 0xFFFF)
        else:
            hn = r2o(v & 0x7FFFFFFF)
            e2 = d.index(b"\0", hn + 2)
            fname = d[hn+2:e2].decode("latin1")
        imports.append((dll, fname, ft + idx*4))
        io += 4
        idx += 1
    off += 20

code = [(n, va, vs, ro, rs) for n, va, vs, ro, rs in secs if n == "CODE"][0]
cname, cva, cvs, cro, crs = code
code_blob = d[cro:cro + cvs]

def find_callsites(slot_rva):
    pat = struct.pack("<I", slot_rva)
    hits = []
    for op in (b"\xff\x15", b"\xff\x25"):
        p = op + pat
        i = 0
        while True:
            j = code_blob.find(p, i)
            if j < 0:
                break
            hits.append((cva + j, op))
            i = j + 1
    return hits

want = sys.argv[1:]
print("=== imports AppKeyX.dll (slot RVA / VA runtime) ===")
seen = set()
for dll, fname, slot in imports:
    key = (dll, fname)
    if want and fname not in want:
        continue
    if key in seen:
        continue
    seen.add(key)
    cs = find_callsites(slot)
    print("%-24s %-28s slot RVA %#08x VA %#08x  callsites: %s" %
          (dll, fname, slot, BASE_RT + slot,
           ", ".join("%#x(%s)" % (r, "jmp" if op == b"\xff\x25" else "call") for r, op in cs) or "(sin ff15/ff25)"))

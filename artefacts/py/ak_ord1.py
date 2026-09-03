#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ak_ord1.py — reconciliacion del export ordinal 1 de AppKeyX.dll + imports + imagen.
Lee la tabla de exports real y resuelve: ordinal -> RVA -> VA (con imagebase PE y con base runtime 0x5DF0000)."""
import struct, sys

PATH = "/mnt/c/Program Files (x86)/Compac/Contabilidad/AppKeyX.dll"
BASE_RT = 0x5DF0000  # base runtime observada en el debugger

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

def o2r(off):
    for n, va, vs, ro, rs in secs:
        if ro <= off < ro + max(vs, rs):
            return va + (off - ro)
    return None

print("imagebase PE: %#x | secciones: %s" % (imagebase, ", ".join(s[0] for s in secs)))
for n, va, vs, ro, rs in secs:
    print("  %-8s VA %#08x VS %#08x raw %#08x (%d)" % (n, va, vs, ro, rs))

# ---- export directory (dir idx 0)
def dd(rva_idx):
    return struct.unpack_from("<I", d, opt + 96 + rva_idx*8)[0]
exp_rva = dd(0)
exp = r2o(exp_rva)
nfunc, nnames = struct.unpack_from("<II", d, exp + 20)
base = struct.unpack_from("<I", d, exp + 16)[0]
fns_rva = struct.unpack_from("<I", d, exp + 28)[0]
names_rva = struct.unpack_from("<I", d, exp + 32)[0]
ord_rva = struct.unpack_from("<I", d, exp + 36)[0]
fns = [struct.unpack_from("<I", d, r2o(fns_rva) + i*4)[0] for i in range(nfunc)]
ords = [struct.unpack_from("<H", d, r2o(ord_rva) + i*2)[0] for i in range(nnames)]
print("\nexports: %d funciones (base ordinal %d), %d con nombre" % (nfunc, base, nnames))

def name_for_idx(idx):
    for i, oi in enumerate(ords):
        if oi == idx:
            nrva = struct.unpack_from("<I", d, r2o(names_rva) + i*4)[0]
            noff = r2o(nrva)
            end = d.index(b"\0", noff)
            return d[noff:end].decode("latin1")
    return ""

# ordinales pedidos
targets = sys.argv[1:] if len(sys.argv) > 1 else ["1", "2", "0"]
print("\n=== ordinal -> RVA/VA ===")
for ts in targets:
    ordn = int(ts, 0)
    idx = ordn - base
    if 0 <= idx < nfunc:
        rva = fns[idx]
        print("ordinal %d -> idx %d -> RVA %#08x | VA(PE %#x) = %#x | VA(baseRT %#x) = %#x | name: %s"
              % (ordn, idx, rva, imagebase, imagebase + rva, BASE_RT, BASE_RT + rva, name_for_idx(idx) or "(sin nombre)"))
    else:
        print("ordinal %d fuera de rango (base %d)" % (ordn, base))

# ---- imports (dir idx 1)
imp_rva = dd(1)
print("\n=== imports ===")
if imp_rva:
    off = r2o(imp_rva)
    while True:
        ilt = struct.unpack_from("<I", d, off)[0]
        name_rva = struct.unpack_from("<I", d, off + 12)[0]
        first_thunk = struct.unpack_from("<I", d, off + 16)[0]
        if name_rva == 0:
            break
        noff = r2o(name_rva)
        end = d.index(b"\0", noff)
        dll = d[noff:end].decode("latin1")
        funcs = []
        iat_rva = ilt if r2o(ilt) is not None else first_thunk
        io = r2o(iat_rva)
        if io is None:
            print("  %-28s (sin IAT mapeable)" % dll)
            off += 20
            continue
        while True:
            v = struct.unpack_from("<I", d, io)[0]
            if v == 0:
                break
            if v & 0x80000000:
                funcs.append("ord#%d" % (v & 0xFFFF))
            else:
                hn = r2o(v & 0x7FFFFFFF)
                end2 = d.index(b"\0", hn + 2)
                funcs.append(d[hn+2:end2].decode("latin1"))
            io += 4
        print("  %-28s (%d): %s" % (dll, len(funcs), ", ".join(funcs)))
        off += 20

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ak_trace.py — helpers de analisis estatico para AppKeyX.dll.
Uso:
  ak_trace.py refs <dword-hex>          -> ocurrencias del dword (LE) en todo el archivo -> RVA/seccion
  ak_trace.py skel <rva-hex> [nins]     -> esqueleto: lineas interesantes del flujo lineal
  ak_trace.py bytes <rva-hex> <n>       -> dump de bytes crudos
"""
import sys, struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

PATH = "/mnt/c/Program Files (x86)/Compac/Contabilidad/AppKeyX.dll"
d = open(PATH, "rb").read()
pe = struct.unpack_from("<I", d, 0x3C)[0]
opt = pe + 24
magic = struct.unpack_from("<H", d, opt)[0]
optsz = 224 if magic == 0x10B else 240
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

def sec_of(rva):
    for n, va, vs, ro, rs in secs:
        if va <= rva < va + max(vs, rs):
            return n
    return "?"

def refs(dw):
    pat = struct.pack("<I", dw)
    print("=== refs a dword %#x (bytes %s) ===" % (dw, pat.hex()))
    idx = 0
    hits = 0
    while True:
        i = d.find(pat, idx)
        if i < 0:
            break
        rva = None
        for n, va, vs, ro, rs in secs:
            if ro <= i < ro + max(vs, rs):
                rva = va + (i - ro)
                break
        print("  fileoff %#08x -> %s RVA %#08x" % (i, sec_of(rva) if rva is not None else "?", rva or 0))
        idx = i + 1
        hits += 1
    if hits == 0:
        print("  (sin hits)")

def skel(rva, nins):
    off = r2o(rva)
    if off is None:
        print("sin offset para %#x" % rva); return
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = False
    code = d[off:off + nins*16]
    print("=== skel @ %#x ===" % rva)
    i = 0
    for ins in md.disasm(code, rva):
        op = ins.op_str
        m = ins.mnemonic
        show = False
        tag = ""
        if m == "call":
            show = True
            if op.startswith("dword ptr [0x") or op.startswith("word ptr [0x"):
                tag = "  <-- IAT"
            else:
                # call rel32 intra-CLASE: marca destino
                try:
                    tgt = int(op, 16)
                    tag = "  -> %s" % sec_of(tgt)
                except ValueError:
                    pass
        elif m.startswith("j") or m in ("ret", "int3", "sysenter", "rdtsc", "cpuid"):
            show = True
        elif m in ("push", "mov", "lea", "cmp") and ("0x403e" in op or "0x403E" in op or "0x54ec" in op or "0x45f" in op):
            show = True
        elif "0x403e" in op or "0x403E" in op:
            show = True
        if show:
            print("  %#08x  %-24s %-7s %s%s" % (ins.address, ins.bytes.hex(), m, op, tag))
        i += 1
        if i > nins:
            break

def raw(rva, n):
    off = r2o(rva)
    if off is None:
        print("sin offset"); return
    print("bytes @ %#x (%d): %s" % (rva, n, d[off:off+n].hex()))

if __name__ == "__main__":
    a = sys.argv[1:]
    if not a:
        print(__doc__); sys.exit(0)
    if a[0] == "refs":
        refs(int(a[1], 16))
    elif a[0] == "skel":
        skel(int(a[1], 16), int(a[2]) if len(a) > 2 else 400)
    elif a[0] == "bytes":
        raw(int(a[1], 16), int(a[2]) if len(a) > 2 else 64)

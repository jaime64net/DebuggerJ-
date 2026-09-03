#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""stub_dis.py — desensambla la seccion .appkey de contabilidad_i.exe (stub validador).
Uso: stub_dis.py <rva-hex> [nins]
Imprime: primeras 40 insns completas, luego filtrado (call/jcc/int3/ret + refs 0x403e/0x50ec014)."""
import sys, struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

PATH = "/mnt/c/Program Files (x86)/Compac/Contabilidad/contabilidad_i.exe"
d = open(PATH, "rb").read()
pe = struct.unpack_from("<I", d, 0x3C)[0]
opt = pe + 24
nsec = struct.unpack_from("<H", d, pe + 6)[0]
optsz = 224 if struct.unpack_from("<H", d, opt)[0] == 0x10B else 240
secs = []
off = opt + optsz
for s in range(nsec):
    name = d[off + s*40: off + s*40 + 8].rstrip(b"\0").decode("latin1")
    vsize = struct.unpack_from("<I", d, off + s*40 + 8)[0]
    vaddr = struct.unpack_from("<I", d, off + s*40 + 12)[0]
    roff = struct.unpack_from("<I", d, off + s*40 + 20)[0]
    rsize = struct.unpack_from("<I", d, off + s*40 + 16)[0]
    secs.append((name, vaddr, vsize, roff, rsize))

# mapa inverso: raw -> RVA usando la seccion con raw-range y RVA maximo cubierto (ultima en tabla gana)
def ro2r(roff):
    best = None
    for n, va, vs, ro, rs in secs:
        if ro <= roff < ro + max(vs, rs):
            r = va + (roff - ro)
            if best is None or r > best[1]:
                best = (n, r)
    return best

def r2o(rva):
    cands = []
    for n, va, vs, ro, rs in secs:
        if va <= rva < va + max(vs, rs):
            cands.append((ro + (rva - va), n))
    # si varios, el de mayor raw-range que cubra (heuristica loader: ultima seccion de la tabla)
    cands.sort(key=lambda c: c[0])
    return cands[-1][0] if cands else None

def sec_of(rva):
    for n, va, vs, ro, rs in secs:
        if va <= rva < va + max(vs, rs):
            return n
    return "?"

rva0 = int(sys.argv[1], 16)
nins = int(sys.argv[2]) if len(sys.argv) > 2 else 700
o0 = r2o(rva0)
print("=== stub @ RVA %#x (fileoff %#x, seccion %s) ===" % (rva0, o0, sec_of(rva0)))
md = Cs(CS_ARCH_X86, CS_MODE_32)
code = d[o0:o0 + nins*16]
insns = list(md.disasm(code, rva0))
print("--- primeras 40 ---")
for ins in insns[:40]:
    print("  %#08x  %-24s %-7s %s" % (ins.address, ins.bytes.hex(), ins.mnemonic, ins.op_str))
print("--- filtrado (call/jcc/int3/ret/refs) desde insn 41 ---")
for ins in insns[40:]:
    op, m = ins.op_str, ins.mnemonic
    show = False
    tag = ""
    if m == "call":
        show = True
        if op.startswith("dword ptr [0x"):
            tag = "  <-- IAT/ptr"
        else:
            try:
                tgt = int(op, 16)
                tag = "  -> %s" % sec_of(tgt)
            except ValueError:
                pass
    elif m.startswith("j") or m in ("ret", "int3"):
        show = True
    elif "0x403e" in op or "0x54ec0" in op or "0x50ec0" in op:
        show = True
    if show:
        print("  %#08x  %-24s %-7s %s%s" % (ins.address, ins.bytes.hex(), m, op, tag))

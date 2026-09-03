#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""cti_scan4.py — fase opción 1 (cti.exe): remate.
Disasm: 0x51148/0x50EF8 (resolucion de modulo), 0x50C94/0x50D4C (expand $(EXE)),
0x4E748/0x4E760/0x4E7E0/0x2E38 (metodos del objeto EP), dump de datos 0x9C9970/0x4513D4/0x451420.
"""
import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

PATH = "/mnt/c/Program Files (x86)/Compac/Contabilidad/contabilidad_i.bin"
d = open(PATH, "rb").read()
pe = struct.unpack_from("<I", d, 0x3C)[0]
nsec = struct.unpack_from("<H", d, pe + 6)[0]
opt = pe + 24
optsz = 224 if struct.unpack_from("<H", d, opt)[0] == 0x10B else 240
secs = []
off = opt + optsz
for s in range(nsec):
    name = d[off + s * 40: off + s * 40 + 8].rstrip(b"\0").decode("latin1")
    vsize = struct.unpack_from("<I", d, off + s * 40 + 8)[0]
    vaddr = struct.unpack_from("<I", d, off + s * 40 + 12)[0]
    rsize = struct.unpack_from("<I", d, off + s * 40 + 16)[0]
    roff = struct.unpack_from("<I", d, off + s * 40 + 20)[0]
    secs.append((name, vaddr, vsize, roff, rsize))


def r2o(rva):
    for n, va, vs, ro, rs in secs:
        if va <= rva < va + max(vs, rs):
            o2 = ro + (rva - va)
            if ro <= o2 < ro + rs:
                return o2
    return None


def dis(rva, n=60):
    o = r2o(rva)
    if o is None:
        print("  (sin raw)"); return
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.skipdata = True
    print("=== disasm %08X ===" % rva)
    c = 0
    for ins in md.disasm(d[o:o + n * 16], rva):
        print("  %08X  %-10s %s" % (ins.address, ins.mnemonic, ins.op_str))
        c += 1
        if ins.mnemonic == "ret":
            break
        if c >= n:
            break


def dump_va(va, n=0x40):
    rva = va - 0x400000
    o = r2o(rva)
    if o is None:
        print("  %08X: sin raw" % va); return
    ch = d[o:o + n]
    print("  VA %08X (fileoff %08X): %s | %s" % (va, o, ch.hex(" "),
          "".join(chr(c) if 32 <= c < 127 else "." for c in ch)))


print("== datos/strings ==")
dump_va(0x9C9970, 0x30)
dump_va(0x4513D4, 0x20)
dump_va(0x451420, 0x80)
dump_va(0x451110, 0x40)
dump_va(0x451150, 0x40)

print("\n== resolucion de modulo: 0x51148 / 0x50EF8 / 0x50C94 / 0x50D4C ==")
dis(0x51148, 45)
dis(0x50EF8, 30)
dis(0x50C94, 25)
dis(0x50D4C, 25)

print("\n== metodos objeto EP ==")
dis(0x4E748, 25)
dis(0x4E760, 25)
dis(0x4E7E0, 20)
dis(0x2E38, 20)

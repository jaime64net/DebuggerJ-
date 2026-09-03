#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""cti_scan3.py — fase opción 1 (cti.exe): v3.
- dumps corregidos de cadenas hermanas (0x451360/0x44E0D0/0x9C9C08)
- disasm de helpers candidatos (thunks/wrappers) y regiones de call-site + bootstrap EP
- xrefs por call relativo (E8/E9 rel32) hacia cargadores/helpers
- scan extra de tokens de protocolo IPC
"""
import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

PATH = "/mnt/c/Program Files (x86)/Compac/Contabilidad/contabilidad_i.bin"
d = open(PATH, "rb").read()
pe = struct.unpack_from("<I", d, 0x3C)[0]
nsec = struct.unpack_from("<H", d, pe + 6)[0]
opt = pe + 24
optsz = 224 if struct.unpack_from("<H", d, opt)[0] == 0x10B else 240
IB = struct.unpack_from("<I", d, opt + 28)[0]
secs = []
off = opt + optsz
for s in range(nsec):
    name = d[off + s * 40: off + s * 40 + 8].rstrip(b"\0").decode("latin1")
    vsize = struct.unpack_from("<I", d, off + s * 40 + 8)[0]
    vaddr = struct.unpack_from("<I", d, off + s * 40 + 12)[0]
    rsize = struct.unpack_from("<I", d, off + s * 40 + 16)[0]
    roff = struct.unpack_from("<I", d, off + s * 40 + 20)[0]
    secs.append((name, vaddr, vsize, roff, rsize))
CODE = next(s for s in secs if s[0] == "CODE")
CODE_RVA, CODE_RAW, CODE_SZ = CODE[1], CODE[3], CODE[4]


def r2o(rva):
    for n, va, vs, ro, rs in secs:
        if va <= rva < va + max(vs, rs):
            o2 = ro + (rva - va)
            if ro <= o2 < ro + rs:
                return o2
    return None


def dis(rva, n=70, stop_ret=True):
    o = r2o(rva)
    if o is None:
        print("  (rva %#x sin raw)" % rva)
        return
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.skipdata = True
    print("=== disasm RVA %08X ===" % rva)
    cnt = 0
    for ins in md.disasm(d[o:o + n * 16], rva):
        print("  %08X  %-10s %s" % (ins.address, ins.mnemonic, ins.op_str))
        cnt += 1
        if stop_ret and ins.mnemonic == "ret":
            break
        if cnt >= n:
            break


def dump(label, offx, n=0x60):
    print("  -- %s (fileoff %08X) --" % (label, offx))
    chunk = d[offx:offx + n]
    print("    hex:", chunk.hex(" "))
    print("    txt:", "".join(chr(c) if 32 <= c < 127 else "." for c in chunk))


def rel_callers(wanted, label=""):
    print("=== callers relativos (E8/E9) hacia %s ===" % (label or ",".join("%X" % w for w in wanted)))
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = False
    b = d[CODE_RAW:CODE_RAW + CODE_SZ]
    for op in (b"\xE8", b"\xE9"):
        i = 0
        while True:
            i = b.find(op, i)
            if i < 0:
                break
            if i + 5 <= len(b):
                rel = struct.unpack_from("<i", b, i + 1)[0]
                tgt = (CODE_RVA + i + 5 + rel) & 0xFFFFFFFF
                if tgt in wanted:
                    site = CODE_RVA + i
                    print("  site %08X: %s -> %08X" % (site, "call" if op == b"\xE8" else "jmp", tgt))
                    o2 = r2o(site)
                    a = max(o2 - 24, 0)
                    for x in md.disasm(d[a:o2 + 16], site - (o2 - a)):
                        if site - 7 <= x.address <= site + 6:
                            print("      %08X  %-8s %s" % (x.address, x.mnemonic, x.op_str))
            i += 1


print("== A) dumps cadenas hermanas ==")
dump("0x451360 ClientDll.dll / hermana 0x451378", 0x50760, 0x80)
dump("0x44E0D0 vcltest3.dll", 0x4D4D0, 0x60)
dump("0x9C9C08 AppKey - <application_name>", 0x5C9008, 0x60)

print("\n== B) helpers candidatos (thunks?) ==")
for h in (0x6B80, 0x6BB8, 0x51148, 0x50EF8, 0x7268, 0x4DB0, 0x4DC0, 0x511B8):
    o = r2o(h)
    if o is None:
        continue
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = False
    print("-- %08X:" % h, end=" ")
    ins = list(md.disasm(d[o:o + 40], h))
    for x in ins[:4]:
        print("%s %s ;" % (x.mnemonic, x.op_str), end=" ")
    print()

print("\n== C) region F1 (call-site ClientDll 0x51324) ==")
dis(0x51320, 70)
print("\n== D) region call-site vcltest3 (0x4DDD2; funcion previa) ==")
# prologo hacia atras desde 0x4DDD2
start = 0x4DDD2
for back in range(0x4DDD2 - 4, 0x4DCC0, -1):
    if d[r2o(back):r2o(back) + 3] == b"\x55\x8B\xEC":
        start = back
        break
dis(start, 80)
print("\n== E) bootstrap EP (0x5C9B80) ==")
dis(0x5C9B80, 110)

print("\n== F) xrefs relativos ==")
rel_callers({0x511B8, 0xDCFC, 0x4E348, 0x7268, 0x6B80, 0x6BB8, 0x51148, 0x50EF8}, "cargadores/helpers")

print("\n== G) tokens IPC extra (ASCII) ==")
for label, nb in (('"%s" %d %d', b'"%s" %d %d'), ("%d %d", b"%d %d"),
                  ("%u %u", b"%u %u"), ("STILL_ACTIVE", b"STILL_ACTIVE"),
                  ("GetExitCodeProcess", b"GetExitCodeProcess"), ("CreateProcess", b"CreateProcess"),
                  ("ParamStr", b"ParamStr"), ("hx", b".hx")):
    i = 0
    hits = 0
    while True:
        i = d.find(nb, i)
        if i < 0 or hits >= 10:
            break
        rva = None
        for n, va, vs, ro, rs in secs:
            if ro <= i < ro + rs:
                rva = va + (i - ro)
                break
        a = d.rfind(b"\0", 0, i) + 1
        b2 = d.find(b"\0", i)
        s = d[a:b2 if b2 > 0 else len(d)].decode("latin1")
        print("  %-16r off=%08X rva=%s %r" % (label, i, ("%08X" % rva) if rva is not None else "-", s[:100]))
        hits += 1
        i += 1
    if hits == 0:
        print("  %-16r (sin hits)" % label)

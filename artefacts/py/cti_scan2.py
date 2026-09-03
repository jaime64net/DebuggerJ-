#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""cti_scan2.py — fase opción 1 (cti.exe): v2 de sonda.
1) strings ASCII/UTF16 de APIs (WriteProcessMemory/OpenProcess/...) y tokens AppKeyX en cti.exe
2) dump de bytes alrededor de 0x451360, 0x44E0D0, 0x9C9C08 (cadenas hermanas)
3) disasm de los cargadores 0x511B8 / 0xDCFC / 0x4E348 y callers conocidos
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


def o2r(o):
    for n, va, vs, ro, rs in secs:
        if ro <= o < ro + rs:
            return va + (o - ro)
    return None


def r2o(rva):
    for n, va, vs, ro, rs in secs:
        if va <= rva < va + max(vs, rs):
            o2 = ro + (rva - va)
            if ro <= o2 < ro + rs:
                return o2
    return None


def sec_of(o):
    for n, va, vs, ro, rs in secs:
        if ro <= o < ro + rs:
            return n
    return "?"


def ascii_strings(needle):
    res, i, seen = [], 0, set()
    while True:
        i = d.find(needle, i)
        if i < 0:
            break
        a = d.rfind(b"\0", 0, i) + 1
        b = d.find(b"\0", i)
        s = d[a:b if b > 0 else len(d)].decode("latin1")
        if s not in seen and len(s) > 2:
            seen.add(s)
            res.append((a, s))
        i += 1
    return res


def u16_strings(needle):
    res, i, seen = [], 0, set()
    while True:
        i = d.find(needle, i)
        if i < 0:
            break
        a = i
        while a >= 2 and not (d[a - 2] == 0 and d[a - 1] == 0):
            a -= 2
        b = i
        while b + 2 <= len(d) and not (d[b] == 0 and d[b + 1] == 0):
            b += 2
        s = d[a:b].decode("utf-16-le", "replace")
        if s not in seen and len(s) > 2:
            seen.add(s)
            res.append((a, s))
        i += 1
    return res


def dis(rva, n=70):
    o = r2o(rva)
    if o is None:
        print("  (rva %#x sin raw)" % rva)
        return
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.skipdata = True
    print("=== disasm RVA %08X (fileoff %08X) ===" % (rva, o))
    for ins in md.disasm(d[o:o + n * 16], rva):
        print("  %08X  %-10s %s" % (ins.address, ins.mnemonic, ins.op_str))
        if ins.mnemonic == "ret" and ins.op_str in ("",):
            break


def callers(target_rva, window=14):
    pat = struct.pack("<I", target_rva)
    print("=== callers que referencian %08X (dword) ===" % target_rva)
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = False
    cnt = 0
    i = 0
    while True:
        i = d.find(pat, i)
        if i < 0 or cnt >= 40:
            break
        rva = o2r(i)
        if rva is not None and sec_of(i) == "CODE":
            o2 = r2o(rva)
            a = max(o2 - window * 5, 0)
            print("  -- ref fileoff=%08X rva=%08X --" % (i, rva))
            for x in md.disasm(d[a:o2 + 32], rva - (o2 - a)):
                if rva - window <= x.address <= rva + 8:
                    print("      %08X  %-8s %s" % (x.address, x.mnemonic, x.op_str))
        cnt += 1
        i += 1
    if cnt == 0:
        print("  (sin refs)")


print("== 1) strings de APIs / tokens (ASCII + UTF16LE) ==")
needles = {
    "WriteProcessMemory": b"WriteProcessMemory",
    "OpenProcess": b"OpenProcess",
    "ReadProcessMemory": b"ReadProcessMemory",
    "VirtualProtectEx": b"VirtualProtectEx",
    "CreateRemoteThread": b"CreateRemoteThread",
    "IsDebuggerPresent": b"IsDebuggerPresent",
    "DebugActiveProcess": b"DebugActiveProcess",
    "MegaPAQw": b"MegaPAQw",
    "4b26608d": b"4b26608d",
    "-splash.exe": b"-splash.exe",
    "Helper": b"Helper",
    ".hx": b".hx",
    "splash": b"splash",
    ".bin": b".bin",
    "AppKey - ": b"AppKey - ",
}
for label, nb in needles.items():
    for typ, fn in (("A", ascii_strings), ("W", u16_strings)):
        hits = fn(nb if typ == "A" else nb.replace(b".", b"\x00.\x00"))
        if hits:
            for o, s in hits[:8]:
                rva = o2r(o)
                print("  [%s] %-18s off=%08X rva=%s sec=%s %r" % (
                    typ, label, o, ("%08X" % rva) if rva is not None else "-",
                    sec_of(o), s[:120]))

print("\n== 2) dumps alrededor de cadenas clave ==")
for label, offx, n in (("ClientDll.dll 0x451360", 0x50760, 0x60),
                       ("vcltest3.dll 0x44E0D0", 0x4D4D0, 0x40),
                       ("AppKey - <application_name> 0x9C9C08", 0x5C9008, 0x60)):
    print("  -- %s (fileoff %08X) --" % (label, offx))
    chunk = d[offx:n]
    printable = "".join(chr(c) if 32 <= c < 127 else "." for c in chunk)
    print("    hex:", chunk.hex(" "))
    print("    txt:", printable)

print("\n== 3) disasm cargadores ==")
dis(0x511B8)
dis(0xDCFC)
dis(0x4E348, 100)

print("\n== 4) callers de los cargadores ==")
callers(0x511B8)
callers(0xDCFC)
callers(0x4E348)

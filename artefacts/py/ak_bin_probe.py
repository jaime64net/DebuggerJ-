#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Sonda read-only de contabilidad_i.bin / cti.exe (2026-09-03).
Determina: identidad (md5/size), empaquetado (entropia por seccion, bytes en EP,
firmas de packers/compilador), imports (DLLs), dirs (rsrc/reloc/tls), y el
contenido en fileoff 0x3270 (comparativa con el bloque CC del exe).
"""
import hashlib, math, os, struct
from collections import Counter

paths = [
    "/mnt/c/Program Files (x86)/Compac/Contabilidad/contabilidad_i.bin",
    "/mnt/c/Program Files (x86)/Compac/Contabilidad/cti.exe",
]

def entropy(b):
    if not b:
        return 0.0
    c = Counter(b)
    n = len(b)
    return -sum((k / n) * math.log2(k / n) for k in c.values())

def rva2off(sections, rva):
    for nm, va, vsize, rawptr, rawsize, ch in sections:
        if va <= rva < va + max(vsize, rawsize) and rawsize:
            off = rawptr + (rva - va)
            if rawptr <= off < rawptr + rawsize:
                return off
    return None

def parse(path):
    d = open(path, "rb").read()
    print("==" * 42)
    print("ARCHIVO:", path)
    print("  tamano:", len(d), " md5:", hashlib.md5(d).hexdigest()[:16])
    if d[:2] != b"MZ":
        print("  NO es PE (sin MZ)"); return
    pe = struct.unpack_from("<I", d, 0x3C)[0]
    if d[pe:pe + 4] != b"PE\0\0":
        print("  firma PE no encontrada en", hex(pe)); return
    machine, nsec, ts, pptr, nsym, optsz, chars = struct.unpack_from("<HHIIIHH", d, pe + 4)
    magic = struct.unpack_from("<H", d, pe + 24)[0]
    print("  machine: %04X  secciones: %d  chars: %04X" % (machine, nsec, chars))
    print("  opt magic: %04X (%s)" % (magic, "PE32" if magic == 0x10B else "PE32+"))
    ep = struct.unpack_from("<I", d, pe + 24 + 16)[0]
    imgbase = struct.unpack_from("<I", d, pe + 24 + 28)[0]
    dd_off = pe + 24 + 96
    n_dd = struct.unpack_from("<I", d, pe + 24 + 92)[0]
    print("  imagebase: %08X  entry RVA: %08X" % (imgbase, ep))
    dds = []
    for i in range(n_dd):
        rva, sz = struct.unpack_from("<II", d, dd_off + i * 8)
        dds.append((rva, sz))
    sec_off = dd_off + n_dd * 8
    sections = []
    for i in range(nsec):
        nm = d[sec_off + i * 40: sec_off + i * 40 + 8].rstrip(b"\0").decode("latin1")
        vsize, va, rawsize, rawptr = struct.unpack_from("<IIII", d, sec_off + i * 40 + 8)
        ch2 = struct.unpack_from("<I", d, sec_off + i * 40 + 36)[0]
        sections.append((nm, va, vsize, rawptr, rawsize, ch2))
        if rawsize > 0x200000:
            step = rawsize // 0x200000
            sample = d[rawptr:rawptr + rawsize:step]
        else:
            sample = d[rawptr:rawptr + rawsize]
        flags = ("X" if ch2 & 0x20000000 else "") + ("R" if ch2 & 0x40000000 else "") + ("W" if ch2 & 0x80000000 else "")
        print("  sec %-8s va=%08X vsize=%08X rawptr=%08X rawsize=%08X ent=%.3f [%s]" % (nm, va, vsize, rawptr, rawsize, entropy(sample), flags))
    ep_sec = next(((s[0], s[2], s[4]) for s in sections if s[1] <= ep < s[1] + max(s[2], s[4])), None)
    print("  EP en seccion:", ep_sec)
    irva, isz = dds[1]
    if irva:
        off = rva2off(sections, irva)
        dlls, nf = [], 0
        while off and off + 20 <= len(d):
            oft, t2, fwd, name_rva, ft = struct.unpack_from("<IIIII", d, off)
            if not any((oft, t2, fwd, name_rva, ft)):
                break
            noff = rva2off(sections, name_rva)
            if noff:
                end = d.index(b"\0", noff)
                dlls.append(d[noff:end].decode("latin1"))
            off += 20
        print("  DLLs importadas (%d): %s" % (len(dlls), ", ".join(dlls)))
    for idx, nm in [(2, "resource"), (5, "basereloc"), (9, "tls"), (13, "iat"), (14, "delayimport")]:
        rva, sz = dds[idx]
        if rva:
            print("  dir %-11s RVA=%08X size=%08X" % (nm, rva, sz))
    sigs = [b"UPX0", b"UPX1", b"UPX!", b".aspack", b"ASPack", b"MPRESS", b"PECompact", b"Themida",
            b"VMProtect", b".vmp0", b"PEC2", b"FSG!", b"Petite", b"Borland", b"Embarcadero", b"CodeGear",
            b"Delphi", b"TurboLinker", b"Microsoft Linker", b"SmartCheck", b"Enigma", b"tElock", b"Armadillo"]
    found = [s.decode("latin1") for s in sigs if s in d]
    print("  firmas packer/compilador:", ", ".join(found) if found else "(ninguna de las 23 buscadas)")
    epoff = rva2off(sections, ep)
    if epoff:
        print("  EP fileoff: %08X  bytes: %s" % (epoff, d[epoff:epoff + 24].hex(" ")))
        try:
            from capstone import Cs, CS_ARCH_X86, CS_MODE_32
            md = Cs(CS_ARCH_X86, CS_MODE_32)
            md.detail = False
            print("  --- desensamblado EP (hasta 24 insns) ---")
            for ins in md.disasm(d[epoff:epoff + 96], imgbase + ep):
                print("    %08X  %-8s %s" % (ins.address, ins.mnemonic, ins.op_str))
        except ImportError:
            print("  (capstone no disponible)")
    print("  fileoff 0x3270 (32 B): %s" % d[0x3270:0x3270 + 32].hex(" "))

for p in paths:
    if os.path.exists(p):
        parse(p)
    else:
        print("NO existe:", p)

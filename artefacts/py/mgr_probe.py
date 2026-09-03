#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""mgr_probe.py — sonda read-only de contabilidad_i.mgr (PE renombrado) + cabeceras PE
embebidas en .dtx/.dat. Fase opción 1: ¿es .mgr el hijo/servicio validador AppKey?"""
import struct

BASE = "/mnt/c/Program Files (x86)/Compac/Contabilidad/"


def parse_pe(path, off=0):
    d = open(path, "rb").read()
    b = d[off:]
    if b[:2] != b"MZ":
        return None
    pe = struct.unpack_from("<I", b, 0x3C)[0]
    if b[pe:pe + 4] != b"PE\0\0":
        return None
    machine, nsec = struct.unpack_from("<HH", b, pe + 4)
    opt = pe + 24
    magic = struct.unpack_from("<H", b, opt)[0]
    optsz = 224 if magic == 0x10B else 240
    is64 = magic == 0x20B
    subsys = struct.unpack_from("<H", b, opt + 68)[0]
    imgbase = struct.unpack_from("<Q" if is64 else "<I", b, opt + 24 + (8 if is64 else 4))[0] if False else struct.unpack_from("<I", b, opt + 28)[0]
    ep = struct.unpack_from("<I", b, opt + 16)[0]
    dd_off = opt + 96
    return d, off, b, pe, machine, nsec, is64, subsys, imgbase, ep, dd_off


def sections(b, pe, nsec, is64):
    optsz = 240 if is64 else 224
    opt = pe + 24
    dd_off = opt + 96
    sec_off = dd_off + 16 * 8
    out = []
    for i in range(nsec):
        name = b[sec_off + i * 40: sec_off + i * 40 + 8].rstrip(b"\0").decode("latin1")
        vsize, va, rsize, roff = struct.unpack_from("<IIII", b, sec_off + i * 40 + 8)
        out.append((name, va, vsize, roff, rsize))
    return out


def r2o(secs, rva):
    for n, va, vs, ro, rs in secs:
        if va <= rva < va + max(vs, rs):
            o = ro + (rva - va)
            if ro <= o < ro + rs:
                return o
    return None


def scan_strings(b, needles):
    for lab, nb in needles:
        i = hits = 0
        first = []
        while True:
            i = b.find(nb, i)
            if i < 0 or hits >= 5:
                break
            first.append(i)
            hits += 1
            i += 1
        print("    %-22s %s" % (lab, ("offsets " + ", ".join("%08X" % x for x in first)) if first else "(sin hits)"))


print("======== contabilidad_i.mgr ========")
r = parse_pe(BASE + "contabilidad_i.mgr")
if not r:
    print("no es PE")
else:
    d, off, b, pe, machine, nsec, is64, subsys, imgbase, ep, dd_off = r
    secs = sections(b, pe, nsec, is64)
    print("  machine=%04X secciones=%d imgbase=%08X epRVA=%08X subsystem=%d tamano=%d" % (
        machine, nsec, imgbase, ep, subsys, len(d)))
    for n, va, vs, ro, rs in secs:
        flags = ""
        print("  sec %-8s RVA=%08X vsize=%08X raw=%08X(+%08X)" % (n, va, vs, ro, rs))
    imp_rva = struct.unpack_from("<I", b, dd_off + 8)[0]
    dlls = []
    o = r2o(secs, imp_rva)
    while o and o + 20 <= len(b):
        ilt, t2, fwd, name_rva, ft = struct.unpack_from("<IIIII", b, o)
        if not any((ilt, t2, fwd, name_rva, ft)):
            break
        no = r2o(secs, name_rva)
        if no:
            e = b.index(b"\0", no)
            dlls.append(b[no:e].decode("latin1"))
        o += 20
    print("  dlls importadas (%d): %s" % (len(dlls), ", ".join(dlls)))
    print("  strings clave (ASCII):")
    scan_strings(b, [
        ("ClientDll", b"ClientDll"), ("Client_Entry", b"Client_Entry"),
        ("AppKey", b"AppKey"), ("AppKey - ", b"AppKey - "),
        ("vcltest3", b"vcltest3"), ("MegaPAQw", b"MegaPAQw"),
        ("4b26608d", b"4b26608d"), (".hx", b".hx"), ("Helper", b"Helper"),
        ("-splash.exe", b"-splash.exe"), (".bin", b".bin"),
        ("WriteProcessMemory", b"WriteProcessMemory"), ("OpenProcess", b"OpenProcess"),
        ("ReadProcessMemory", b"ReadProcessMemory"), ("VirtualProtectEx", b"VirtualProtectEx"),
        ("CreateRemoteThread", b"CreateRemoteThread"), ("STILL_ACTIVE", b"STILL_ACTIVE"),
        ("CreateProcess", b"CreateProcess"), ("GetExitCodeProcess", b"GetExitCodeProcess"),
        ('"%s" %d %d', b'"%s" %d %d'),
    ])

for f, offs in (("contabilidad_i.dtx", (0xAA03, 0xAB88, 0x14B03, 0x3A8C2)),
                ("contabilidad_i.dat", (0x557E, 0x143C3, 0x1A482, 0x2C3BD))):
    print("\n======== %s (PE embebidos) ========" % f)
    full = open(BASE + f, "rb").read()
    for offx in offs:
        b = full[offx:]
        if b[:2] == b"MZ" and offx + 0x40 < len(full):
            pe = struct.unpack_from("<I", b, 0x3C)[0]
            if b[pe:pe + 4] == b"PE\0\0":
                machine, nsec = struct.unpack_from("<HH", b, pe + 4)
                opt = pe + 24
                magic = struct.unpack_from("<H", b, opt)[0]
                is64 = magic == 0x20B
                optsz = 240 if is64 else 224
                imgbase = struct.unpack_from("<I", b, opt + 28)[0]
                ep = struct.unpack_from("<I", b, opt + 16)[0]
                subsys = struct.unpack_from("<H", b, opt + 68)[0]
                secs = sections(b, pe, nsec, is64)
                secn = ", ".join(s[0] for s in secs)
                print("  @%08X: PE32%s machine=%04X sec=%d imgbase=%08X ep=%08X subsys=%d secs=[%s]" % (
                    offx, "+" if is64 else "", machine, nsec, imgbase, ep, subsys, secn[:80]))
                # strings de interes cerca
                for lab, nb in (("ClientDll", b"ClientDll"), ("AppKey", b"AppKey"),
                                ("vcltest", b"vcltest"), (".hx", b".hx"), ("WriteProcessMemory", b"WriteProcessMemory")):
                    j = full.find(nb, offx, min(offx + 0x300000, len(full)))
                    print("    %-22s %s" % (lab, "%08X" % j if j > 0 else "-"))

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""svr_probe.py — sonda read-only de AppKeyAuthServer.exe / AppKeyLicenseServer.exe
(fase opción 1 → cierre: ¿el validador que escribe los 99 B está en el servidor local?)."""
import struct

BASE = "/mnt/c/Program Files (x86)/Compac/Servidor de Licencias/AppKey/"


def load(path):
    b = open(path, "rb").read()
    if b[:2] != b"MZ":
        return None
    pe = struct.unpack_from("<I", b, 0x3C)[0]
    if b[pe:pe + 4] != b"PE\0\0":
        return None
    machine, nsec = struct.unpack_from("<HH", b, pe + 4)
    opt = pe + 24
    magic = struct.unpack_from("<H", b, opt)[0]
    is64 = magic == 0x20B
    optsz = 240 if is64 else 224
    ib = struct.unpack_from("<Q" if is64 else "<I", b, opt + 24 + (16 if is64 else 0))[0]
    ib = struct.unpack_from("<I", b, opt + 28)[0]
    ep = struct.unpack_from("<I", b, opt + 16)[0]
    subsys = struct.unpack_from("<H", b, opt + 68)[0]
    dd_off = opt + 96
    sec_off = dd_off + 16 * 8
    secs = []
    for i in range(nsec):
        name = b[sec_off + i * 40: sec_off + i * 40 + 8].rstrip(b"\0").decode("latin1")
        vsize, va, rsize, roff = struct.unpack_from("<IIII", b, sec_off + i * 40 + 8)
        secs.append((name, va, vsize, roff, rsize))
    return b, ib, ep, nsec, machine, is64, subsys, secs


def r2o(secs, rva):
    for n, va, vs, ro, rs in secs:
        if va <= rva < va + max(vs, rs):
            o = ro + (rva - va)
            if ro <= o < ro + rs:
                return o
    return None


NEEDLES = [
    ("ClientDll", b"ClientDll"), ("vcltest3", b"vcltest3"), ("AppKey", b"AppKey"),
    ("AppKey - ", b"AppKey - "), ("MegaPAQw", b"MegaPAQw"), ("4b26608d", b"4b26608d"),
    (".hx", b".hx"), ("Helper", b"Helper"), ("-splash.exe", b"-splash.exe"), (".bin", b".bin"),
    ("WriteProcessMemory", b"WriteProcessMemory"), ("OpenProcess", b"OpenProcess"),
    ("ReadProcessMemory", b"ReadProcessMemory"), ("VirtualProtectEx", b"VirtualProtectEx"),
    ("VirtualProtect", b"VirtualProtect"), ("CreateRemoteThread", b"CreateRemoteThread"),
    ("STILL_ACTIVE", b"STILL_ACTIVE"), ("CreateProcess", b"CreateProcess"),
    ("GetExitCodeProcess", b"GetExitCodeProcess"), ('"%s" %d %d', b'"%s" %d %d'),
    ("NtWriteVirtualMemory", b"NtWriteVirtualMemory"), ("WriteProcessMemoryEx", b"WriteProcessMemoryEx"),
]

import os
for fn in sorted(os.listdir(BASE)):
    p = BASE + fn
    if not os.path.isfile(p):
        continue
    r = load(p)
    print("==== %s (%d B) ====" % (fn, os.path.getsize(p)))
    if not r:
        print("  no PE"); continue
    b, ib, ep, nsec, machine, is64, subsys, secs = r
    print("  PE32%s imgbase=%08X ep=%08X nsec=%d subsys=%d" % (
        "+" if is64 else "", ib, ep, nsec, subsys))
    for s0 in secs[:4]:
        print("  sec %-8s RVA=%08X vsize=%08X raw=%08X(+%08X)" % s0)
    # imports
    dd_off = struct.unpack_from("<I", b, 0x3C)[0] + 24 + 96
    imp_rva = struct.unpack_from("<I", b, dd_off + 8)[0]
    o = r2o(secs, imp_rva)
    dlls = set()
    while o and o + 20 <= len(b):
        ilt, t2, fwd, name_rva, ft = struct.unpack_from("<IIIII", b, o)
        if not any((ilt, t2, fwd, name_rva, ft)):
            break
        no = r2o(secs, name_rva)
        if no:
            e = b.index(b"\0", no)
            dlls.add(b[no:e].decode("latin1"))
        o += 20
    print("  dlls: %s" % ", ".join(sorted(dlls)))
    for lab, nb in NEEDLES:
        i = hits = 0
        pos = []
        while True:
            i = b.find(nb, i)
            if i < 0 or hits >= 6:
                break
            pos.append(i)
            hits += 1
            i += 1
        if pos:
            print("    %-22s %s" % (lab, ", ".join("%08X" % x for x in pos)))

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ex_scan.py — estructura de contabilidad_i.exe + localizacion del bloque CC + refs al validador.
Subcomandos:
  ex_scan.py secs <archivo>            -> secciones + entry + imports rva
  ex_scan.py dump <archivo> <off-hex> <n>
  ex_scan.py rva2off <archivo> <rva-hex>
  ex_scan.py ccregion                    -> dump comparativo de fileoff 0x3270..0x3340 en exe/cti/.bin/.dat/.mgr
  ex_scan.py find <archivo> <hexbytes> [max]   -> fileoffs + (si mapea) RVA
"""
import sys, struct

DIR = "/mnt/c/Program Files (x86)/Compac/Contabilidad"
FILES = ["contabilidad_i.exe", "cti.exe", "contabilidad_i.bin", "contabilidad_i.dat",
         "contabilidad_i.mgr", "contabilidad_i.dtx", "AppKeyX.dll"]

def parse(path):
    d = open(path, "rb").read()
    if d[:2] != b"MZ":
        return None, "no-MZ"
    pe = struct.unpack_from("<I", d, 0x3C)[0]
    if d[pe:pe+4] != b"PE\0\0":
        return None, "no-PE"
    nsec = struct.unpack_from("<H", d, pe + 6)[0]
    opt = pe + 24
    magic = struct.unpack_from("<H", d, opt)[0]
    optsz = 224 if magic == 0x10B else 240
    is64 = magic == 0x20B
    entry = struct.unpack_from("<I", d, opt + 16)[0]
    imagebase = struct.unpack_from("<I", d, opt + 28)[0] if not is64 else struct.unpack_from("<Q", d, opt + 24)[0]
    imp = struct.unpack_from("<I", d, opt + 104)[0] if not is64 else 0
    exp = struct.unpack_from("<I", d, opt + 112)[0] if not is64 else 0
    secs = []
    off = opt + optsz
    for s in range(nsec):
        name = d[off+s*40: off+s*40+8].rstrip(b"\0").decode("latin1")
        vsize = struct.unpack_from("<I", d, off+s*40+8)[0]
        vaddr = struct.unpack_from("<I", d, off+s*40+12)[0]
        rsize = struct.unpack_from("<I", d, off+s*40+16)[0]
        roff = struct.unpack_from("<I", d, off+s*40+20)[0]
        secs.append((name, vaddr, vsize, roff, rsize))
    return (d, imagebase, entry, imp, exp, secs, is64), None

def r2o(secs, rva):
    for n, va, vs, ro, rs in secs:
        if va <= rva < va + max(vs, rs):
            return ro + (rva - va)
    return None

def secs_cmd(path):
    info, err = parse(path)
    if err:
        print(err); return
    d, ib, entry, imp, exp, secs, is64 = info
    print("%s | imagebase %#x | entry_rva %#x | import_rva %#x | export_rva %#x | pe%d" %
          (path.split("/")[-1], ib, entry, imp, exp, 64 if is64 else 32))
    print("%-10s %10s %10s %10s %10s" % ("sec", "RVA", "VSize", "RawOff", "RawSz"))
    for n, va, vs, ro, rs in secs:
        print("%-10s %#10x %10d %#10x %10d" % (n, va, vs, ro, rs))

def dump_cmd(path, off, n):
    d = open(path, "rb").read()
    print("%s @ %#x (%d): %s" % (path.split("/")[-1], off, n, d[off:off+n].hex()))

def r2o_cmd(path, rva):
    info, err = parse(path)
    if err:
        print(err); return
    d, ib, entry, imp, exp, secs, is64 = info
    o = r2o(secs, rva)
    print("RVA %#x -> fileoff %s" % (rva, hex(o) if o is not None else "sin mapeo"))

def ccregion():
    off, n = 0x3270, 0xD0
    for f in FILES:
        p = DIR + "/" + f
        try:
            d = open(p, "rb").read()
        except OSError as e:
            print(f, "ERR", e); continue
        print("=== %s (%d B)" % (f, len(d)))
        print("  off %#x: %s" % (off, d[off:off+n].hex()))

def find_cmd(path, hexbytes, maxhits):
    d = open(path, "rb").read()
    info, err = parse(path)
    secs = info[5] if not err else []
    pat = bytes.fromhex(hexbytes)
    idx = 0
    hits = 0
    while hits < maxhits:
        i = d.find(pat, idx)
        if i < 0:
            break
        rva = ""
        for n, va, vs, ro, rs in secs:
            if ro <= i < ro + max(vs, rs):
                rva = "%s RVA %#x" % (n, va + (i - ro))
                break
        print("  %s: fileoff %#08x  %s" % (path.split("/")[-1], i, rva))
        idx = i + 1
        hits += 1
    if hits == 0:
        print("  (sin hits)")

if __name__ == "__main__":
    a = sys.argv[1:]
    if not a:
        print(__doc__); sys.exit(0)
    if a[0] == "secs":
        secs_cmd(a[1])
    elif a[0] == "dump":
        dump_cmd(a[1], int(a[2], 16), int(a[3]))
    elif a[0] == "rva2off":
        r2o_cmd(a[1], int(a[2], 16))
    elif a[0] == "ccregion":
        ccregion()
    elif a[0] == "find":
        find_cmd(a[1], a[2], int(a[3]) if len(a) > 3 else 20)

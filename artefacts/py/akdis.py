#!/usr/bin/env python3
"""akdis.py — disassembler offline para AppKeyX.dll (capstone).
Uso:
  akdis.py <rva-hex> [count]            -> desensambla desde el RVA
  akdis.py --fns <rva-hex> [depth]      -> desensambla recursivo (funciones)
  akdis.py --scan <text>                -> busca patrones (fs:[0x30], int 2d, rdtsc, int 1, pushfd/popfd, pushfd/popf)
  akdis.py --xrefs <rva-hex>            -> referencias de codigo a un RVA
  akdis.py --str <rva-hex>              -> lee una cadena (ascii) en un RVA
"""
import sys, struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

PATH = "/mnt/c/Program Files (x86)/Compac/Contabilidad/AppKeyX.dll"

def load():
    d = open(PATH, "rb").read()
    pe = struct.unpack_from("<I", d, 0x3C)[0]
    opt = pe + 24
    nsec = struct.unpack_from("<H", d, pe + 6)[0]
    magic = struct.unpack_from("<H", d, opt)[0]
    optsz = 224 if magic == 0x10B else 240
    secs = []
    off = opt + optsz
    for s in range(nsec):
        name = d[off+s*40: off+s*40+8].rstrip(b"\0").decode("latin1")
        vsize = struct.unpack_from("<I", d, off+s*40+8)[0]
        vaddr = struct.unpack_from("<I", d, off+s*40+12)[0]
        roff = struct.unpack_from("<I", d, off+s*40+20)[0]
        rsize = struct.unpack_from("<I", d, off+s*40+16)[0]
        secs.append((name, vaddr, vsize, roff, rsize))
    def r2o(rva):
        for n, va, vs, ro, rs in secs:
            if va <= rva < va + max(vs, rs):
                return ro + (rva - va)
        return None
    return d, r2o, secs

d, r2o, secs = load()

def disasm(rva, count=40):
    off = r2o(rva)
    if off is None:
        print("rva %#x sin offset" % rva); return
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    code = d[off:off + count*16]
    print(f"=== disasm @ {rva:#x} (off {off:#x}) ===")
    for ins in md.disasm(code, rva):
        s = f"  {ins.address:#08x}  {ins.bytes.hex():24} {ins.mnemonic:8} {ins.op_str}"
        print(s)

def scan(patterns):
    # patrones: bytes a buscar en todo CODE
    code_rva = None; code_off = None; code_sz = None
    for n, va, vs, ro, rs in secs:
        if n == "CODE":
            code_rva, code_off, code_sz = va, ro, vs
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    for pat in patterns:
        p = bytes.fromhex(pat)
        print(f"=== scan {pat} ===")
        idx = 0
        hits = 0
        while True:
            i = d.find(p, code_off + idx, code_off + code_sz)
            if i < 0 or hits > 40:
                break
            rva = code_rva + (i - code_off)
            # disasm one
            ins = list(md.disasm(d[i:i+8], rva))
            txt = ins[0].mnemonic + " " + ins[0].op_str if ins else "?"
            print(f"  {rva:#08x}: {txt}")
            idx = (i - code_off) + 1
            hits += 1
        if hits == 0:
            print("  (sin hits)")

def xrefs(rva):
    code_rva = None; code_off = None; code_sz = None
    for n, va, vs, ro, rs in secs:
        if n == "CODE":
            code_rva, code_off, code_sz = va, ro, vs
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    code = d[code_off:code_off+code_sz]
    print(f"=== xrefs -> {rva:#x} ===")
    n = 0
    for ins in md.disasm(code, code_rva):
        # find immediate or displacement matching rva
        if ins.mnemonic in ("call", "jmp", "push") and ins.op_str.endswith(hex(rva)):
            print(f"  {ins.address:#08x}: {ins.mnemonic} {ins.op_str}")
            n += 1
        elif hex(rva) in ins.op_str and ins.mnemonic in ("mov","lea","cmp","add","sub"):
            print(f"  {ins.address:#08x}: {ins.mnemonic} {ins.op_str}")
            n += 1
        if n > 200:
            break
    if n == 0:
        print("  (sin refs)")

def string_at(rva):
    off = r2o(rva)
    if off is None:
        print("sin offset"); return
    end = d.index(b"\0", off)
    print(f"str @ {rva:#x}: {d[off:end][:200]!r}")

if __name__ == "__main__":
    a = sys.argv[1:]
    if not a:
        print(__doc__); sys.exit(0)
    if a[0] == "--scan":
        scan(a[1:])
    elif a[0] == "--xrefs":
        xrefs(int(a[1], 16))
    elif a[0] == "--str":
        string_at(int(a[1], 16))
    else:
        rva = int(a[0], 16)
        cnt = int(a[1]) if len(a) > 1 else 40
        disasm(rva, cnt)

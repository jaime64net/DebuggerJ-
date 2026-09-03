#!/usr/bin/env python3
"""akscan.py — escanea AppKeyX.dll CODE buscando anti-debug primitivas.
Busca: pushfd/popfd (TF), int 1/int 3, rdtsc, cpuid, fs:[0x30]/fs:[0x18], sldt, str.
Uso: akscan.py [patron1 patron2 ...]  (patrones: tf, int1, int3, rdtsc, cpuid, peb, teb, sldt)
"""
import sys, struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_OP_IMM, CS_OP_MEM

PATH = "/mnt/c/Program Files (x86)/Compac/Contabilidad/AppKeyX.dll"

d = open(PATH, "rb").read()
pe = struct.unpack_from("<I", d, 0x3C)[0]
opt = pe + 24
nsec = struct.unpack_from("<H", d, pe + 6)[0]
optsz = 224 if struct.unpack_from("<H", d, opt)[0] == 0x10B else 240
secs = []
off = opt + optsz
for s in range(nsec):
    name = d[off+s*40: off+s*40+8].rstrip(b"\0").decode("latin1")
    vsize = struct.unpack_from("<I", d, off+s*40+8)[0]
    vaddr = struct.unpack_from("<I", d, off+s*40+12)[0]
    roff = struct.unpack_from("<I", d, off+s*40+20)[0]
    rsize = struct.unpack_from("<I", d, off+s*40+16)[0]
    secs.append((name, vaddr, vsize, roff, rsize))

code_rva = code_off = code_sz = None
for n, va, vs, ro, rs in secs:
    if n == "CODE":
        code_rva, code_off, code_sz = va, ro, vs
code = d[code_off:code_off+code_sz]

md = Cs(CS_ARCH_X86, CS_MODE_32)
md.detail = True

want = set(sys.argv[1:]) if len(sys.argv) > 1 else {"tf", "int1", "rdtsc", "cpuid", "peb", "teb", "sldt"}

def hit(tag, ins, note=""):
    print(f"  {ins.address:#08x}: {ins.mnemonic} {ins.op_str}   [{tag}] {note}")

for ins in md.disasm(code, code_rva):
    m = ins.mnemonic
    if "tf" in want and m in ("pushfd", "popfd", "pushf", "popf"):
        hit("tf", ins)
    if "int1" in want and m == "int" and ins.op_str.strip() in ("1", "0x1"):
        hit("int1", ins)
    if "int3" in want and m == "int3":
        # solo reportar los que NO son thunks conocidos (heuristica: thunk tiene mov ebx, imm antes)
        hit("int3", ins)
    if "rdtsc" in want and m == "rdtsc":
        hit("rdtsc", ins)
    if "cpuid" in want and m == "cpuid":
        hit("cpuid", ins)
    if "sldt" in want and m == "sldt":
        hit("sldt", ins)
    if "peb" in want and m.startswith("mov") and "fs:[0x30]" in ins.op_str:
        hit("peb", ins)
    if "teb" in want and m.startswith("mov") and "fs:[0x18]" in ins.op_str:
        hit("teb", ins)

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""dump_range.py — disasm lineal RVA[inicio..fin] de AppKeyX.dll sin cortar en ret."""
import sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_32
P = "/mnt/c/Program Files (x86)/Compac/Contabilidad/AppKeyX.dll"
d = open(P, "rb").read()
start = int(sys.argv[1], 16)
end = int(sys.argv[2], 16)
# CODE: rva 0x1000 <-> fileoff 0x400  => off = 0x400 + (rva - 0x1000)
off0 = 0x400 + (start - 0x1000)
off1 = 0x400 + (end - 0x1000)
md = Cs(CS_ARCH_X86, CS_MODE_32)
a = 0x400000 + start
for ins in md.disasm(d[off0:off1], a):
    print("0x%X  %-7s %s" % (ins.address - 0x400000, ins.mnemonic, ins.op_str))

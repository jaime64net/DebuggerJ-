#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""xref_call.py — busca callers E8 rel32 (byte-level) hacia una lista de RVAs
objetivo dentro de CODE. Uso: xref_call.py 0x13F40 [0x....]"""
import struct, sys
P = "/mnt/c/Program Files (x86)/Compac/Contabilidad/AppKeyX.dll"
d = open(P, "rb").read()
CODE_OFF, CODE_LEN = 0x400, 0x58E00
code = d[CODE_OFF:CODE_OFF + CODE_LEN]
targets = {int(x, 16) for x in sys.argv[1:]}
print("buscando callers hacia:", ["0x%X" % t for t in sorted(targets)])
j = 0
while j < len(code) - 5:
    if code[j] in (0xE8, 0xE9):
        (rel,) = struct.unpack_from("<i", code, j + 1)
        t = 0x1000 + j + 5 + rel
        if t in targets:
            print("  0x%X  %s -> 0x%X" % (0x1000 + j, "call" if code[j] == 0xE8 else "jmp ", t))
        j += 5
    else:
        j += 1

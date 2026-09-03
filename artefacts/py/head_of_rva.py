#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""head_of_rva.py — escanea hacia atras desde un rva buscando prologo tipico
(55 8B EC / 53.. / 56.. / push ebp) y reporta candidatos. Uso: head_of_rva.py 0x14252"""
import sys
P = "/mnt/c/Program Files (x86)/Compac/Contabilidad/AppKeyX.dll"
d = open(P, "rb").read()
CODE_OFF, CODE_LEN = 0x400, 0x58E00
code = d[CODE_OFF:CODE_OFF + CODE_LEN]
rva = int(sys.argv[1], 16)
j = rva - 0x1000  # offset en code
start = max(0, j - 0x200)
for i in range(start, j):
    b = code[i]
    # prologos: 55 8B EC | 55 8B E5 | 53 56 57 | 6Axx | 83 EC xx | 8B FF 55
    if b == 0x55 and code[i+1] in (0x8B,) and code[i+2] in (0xEC, 0xE5):
        print("prologo 55 8B EC/E5 @ rva 0x%X" % (0x1000 + i))
    elif b == 0x8B and code[i+1] == 0xFF and code[i+2] == 0x55:
        print("prologo 8B FF 55 @ rva 0x%X" % (0x1000 + i))
    elif b in (0x53, 0x56, 0x57) and code[i+1] == 0x55 and code[i+2] == 0x8B:
        print("prologo 53/56/57 55 8B @ rva 0x%X" % (0x1000 + i))

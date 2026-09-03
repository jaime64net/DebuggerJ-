#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""chain_up.py — desde un rva, remonta la cadena de llamadas: prologo previo ->
callers -> prologo del caller... hasta agotar. Uso: chain_up.py 0x14908"""
import struct, sys
P = "/mnt/c/Program Files (x86)/Compac/Contabilidad/AppKeyX.dll"
d = open(P, "rb").read()
code = d[0x400:0x400 + 0x58E00]

def prologue_before(rva, window=0x260):
    j = rva - 0x1000
    found = []
    for i in range(max(0, j - window), j):
        b = code[i]
        if b == 0x55 and code[i+1] in (0x8B,) and code[i+2] in (0xEC, 0xE5):
            found.append(0x1000 + i)
    return found

def callers_of(target):
    out = []
    j = 0
    while j < len(code) - 5:
        if code[j] in (0xE8, 0xE9):
            (rel,) = struct.unpack_from("<i", code, j + 1)
            t = 0x1000 + j + 5 + rel
            if t == target:
                out.append(0x1000 + j)
            j += 5
        else:
            j += 1
    return out

cur = int(sys.argv[1], 16)
seen = set()
for step in range(12):
    print("nivel %d: rva actual 0x%X" % (step, cur))
    if cur in seen:
        print("  (repetido, corto)")
        break
    seen.add(cur)
    c = callers_of(cur)
    if not c:
        print("  sin callers directos (o solo via puntero) -> FIN")
        break
    # agrupar callers por funcion contenedora (prologo previo mas cercano)
    groups = {}
    for cc in c:
        pl = prologue_before(cc)
        head = pl[-1] if pl else 0
        groups.setdefault(head, []).append(cc)
    for head, ccs in sorted(groups.items()):
        print("  caller(s) %s -> dentro de funcion con prologo 0x%X" % (
            ",".join("0x%X" % x for x in ccs), head))
    # continuar por el grupo mas reciente (mayor head)
    head, ccs = max(groups.items())
    cur = head
    if head == 0:
        print("  (caller sin prologo localizado) FIN")
        break

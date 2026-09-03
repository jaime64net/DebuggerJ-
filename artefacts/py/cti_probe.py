#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""cti_probe.py — sonda read-only de contabilidad_i.bin == cti.exe (fase opción 1, 2026-09-03).
Enumera: PE básico + imports; strings AppKey/ClientDll/vcltest3/application_name (ASCII y
UTF-16LE) con offset/RVA/VA/sección; xrefs (dword LE = VA) en todo el archivo y ventanas
desensambladas alrededor de cada ref de las cadenas clave.
"""
import struct, sys
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

PATH = "/mnt/c/Program Files (x86)/Compac/Contabilidad/contabilidad_i.bin"

d = open(PATH, "rb").read()
pe = struct.unpack_from("<I", d, 0x3C)[0]
nsec = struct.unpack_from("<H", d, pe + 6)[0]
opt = pe + 24
magic = struct.unpack_from("<H", d, opt)[0]
optsz = 224 if magic == 0x10B else 240
imagebase = struct.unpack_from("<I", d, opt + 28)[0]
entry = struct.unpack_from("<I", d, opt + 16)[0]
n_dd = struct.unpack_from("<I", d, opt + 92)[0]
dd_off = opt + 96

secs = []
off = opt + optsz
for s in range(nsec):
    name = d[off + s * 40: off + s * 40 + 8].rstrip(b"\0").decode("latin1")
    vsize = struct.unpack_from("<I", d, off + s * 40 + 8)[0]
    vaddr = struct.unpack_from("<I", d, off + s * 40 + 12)[0]
    rsize = struct.unpack_from("<I", d, off + s * 40 + 16)[0]
    roff = struct.unpack_from("<I", d, off + s * 40 + 20)[0]
    secs.append((name, vaddr, vsize, roff, rsize))
print("== PE %s" % PATH)
print("  imagebase=%08X entryRVA=%08X dd=%d secciones=%d" % (imagebase, entry, n_dd, nsec))
for n, va, vs, ro, rs in secs:
    print("  sec %-8s RVA=%08X vsize=%08X raw=%08X(+%08X)" % (n, va, vs, ro, rs))


def o2r(off_):
    for n, va, vs, ro, rs in secs:
        if ro <= off_ < ro + rs:
            return va + (off_ - ro)
    return None


def r2o(rva):
    for n, va, vs, ro, rs in secs:
        if va <= rva < va + max(vs, rs):
            o2 = ro + (rva - va)
            if ro <= o2 < ro + rs:
                return o2
    return None


def sec_of_off(off_):
    for n, va, vs, ro, rs in secs:
        if ro <= off_ < ro + rs:
            return n
    return "?"


# imports (dir table 1)
def imports():
    imp_rva = struct.unpack_from("<I", d, dd_off + 1 * 8)[0]
    out = {}
    if not imp_rva:
        return out
    o = r2o(imp_rva)
    while o and o + 20 <= len(d):
        ilt, t2, fwd, name_rva, ft = struct.unpack_from("<IIIII", d, o)
        if not any((ilt, t2, fwd, name_rva, ft)):
            break
        no = r2o(name_rva)
        if no:
            e = d.index(b"\0", no)
            dll = d[no:e].decode("latin1")
            iat = ilt if r2o(ilt) is not None else ft
            io = r2o(iat)
            if io:
                idx = 0
                while True:
                    v = struct.unpack_from("<I", d, io)[0]
                    if v == 0:
                        break
                    if v & 0x80000000:
                        fn = "ord#%d" % (v & 0xFFFF)
                    else:
                        hn = r2o(v & 0x7FFFFFFF)
                        e2 = d.index(b"\0", hn + 2)
                        fn = d[hn + 2:e2].decode("latin1")
                    out[fn] = dll
                    io += 4
                    idx += 1
        o += 20
    return out


imp = imports()
print("== imports (%d): %s" % (len(imp), ", ".join(sorted(set(imp.values())))))
want = [k for k in imp if k in ("LoadLibraryA", "LoadLibraryW", "GetProcAddress",
        "WriteProcessMemory", "VirtualProtect", "VirtualAlloc", "CreateProcessA",
        "OpenProcess", "ReadProcessMemory", "IsDebuggerPresent")]
print("  funciones de interes importadas:", {k: imp[k] for k in want})


def ascii_strings_around(needle):
    """Devuelve lista de (off, texto) con la cadena ASCII completa que contiene needle."""
    res = []
    i = 0
    seen = set()
    while True:
        i = d.find(needle, i)
        if i < 0:
            break
        # delimitar por NULs
        a = d.rfind(b"\0", 0, i) + 1
        b = d.find(b"\0", i)
        if b < 0:
            b = len(d)
        txt = d[a:b]
        try:
            s = txt.decode("ascii")
        except Exception:
            s = txt.decode("latin1")
        if len(s) > 3 and s not in seen:
            seen.add(s)
            res.append((a, s))
        i += 1
    return res


def u16_strings_around(needle_le):
    res = []
    i = 0
    seen = set()
    while True:
        i = d.find(needle_le, i)
        if i < 0:
            break
        # delimitar por pares NUL
        a = i
        while a >= 2 and not (d[a - 2] == 0 and d[a - 1] == 0):
            a -= 2
        b = i
        while b + 2 <= len(d) and not (d[b] == 0 and d[b + 1] == 0):
            b += 2
        txt = d[a:b]
        try:
            s = txt.decode("utf-16-le")
        except Exception:
            s = ""
        if len(s) > 3 and s not in seen:
            seen.add(s)
            res.append((a, s))
        i += 1
    return res


def show(label, needle_b, needle_u16=None):
    print("\n== strings %s (ASCII) ==" % label)
    for o, s in ascii_strings_around(needle_b):
        rva = o2r(o)
        va = (imagebase + rva) if rva is not None else None
        print("  off=%08X rva=%s va=%s sec=%s %r" % (
            o, ("%08X" % rva) if rva is not None else "-",
            ("%08X" % va) if va is not None else "-", sec_of_off(o), s[:160]))
    if needle_u16:
        print("== strings %s (UTF-16LE) ==" % label)
        for o, s in u16_strings_around(needle_u16):
            rva = o2r(o)
            va = (imagebase + rva) if rva is not None else None
            print("  off=%08X rva=%s va=%s sec=%s %r" % (
                o, ("%08X" % rva) if rva is not None else "-",
                ("%08X" % va) if va is not None else "-", sec_of_off(o), s[:160]))


show("ClientDll", b"ClientDll")
show("vcltest3", b"vcltest3")
show("AppKey", b"AppKey")
show("application_name", b"application_name")

# --- xrefs de las cadenas clave: dword LE = VA, y disasm de la ventana ---
key_strings = []
for needle in (b"ClientDll.dll", b"AppKey - <application_name>", b"vcltest3.dll"):
    for o, s in ascii_strings_around(needle):
        rva = o2r(o)
        if rva is not None:
            key_strings.append((s, imagebase + rva, o))
print("\n== cadenas clave (texto, VA, fileoff) ==")
for s, va, o in key_strings:
    print("  %-40s VA=%08X off=%08X" % (repr(s), va, o))

md = Cs(CS_ARCH_X86, CS_MODE_32)
md.detail = False

for s, va, o in key_strings:
    print("\n== xrefs dword-LE hacia %s (VA %08X) ==" % (repr(s), va))
    pat = struct.pack("<I", va)
    cnt = 0
    i = 0
    while True:
        i = d.find(pat, i)
        if i < 0 or cnt >= 60:
            break
        rva = o2r(i)
        sec = sec_of_off(i)
        print("  ref fileoff=%08X rva=%s sec=%s" % (i, ("%08X" % rva) if rva is not None else "-", sec))
        if rva is not None and sec in ("CODE",):
            # disasm 10 insns antes/despues del ref
            o2 = r2o(rva)
            a = max(o2 - 40, 0)
            insn = list(md.disasm(d[a:o2 + 48], rva - (o2 - a)))
            for x in insn:
                if rva - 8 <= x.address <= rva + 16:
                    print("      %08X  %-8s %s" % (x.address, x.mnemonic, x.op_str))
        cnt += 1
        i += 1
    if cnt == 0:
        print("  (sin refs dword)")

# --- tambien refs estilo Delphi: lea reg,[VA] / mov reg,VA con opcode 8D/B8/B9/BA/BB/BD/BE/BF ---
print("\n== busqueda de refs a las VA clave via operando disp32 (scan bruto de opcodes) ==")
opc = {0xB8: "mov eax", 0xB9: "mov ecx", 0xBA: "mov edx", 0xBB: "mov ebx",
       0xBC: "mov esp", 0xBD: "mov ebp", 0xBE: "mov esi", 0xBF: "mov edi"}
for s, va, o in key_strings:
    pat = struct.pack("<I", va)
    hits = 0
    for i in range(len(d) - 5):
        if d[i + 1:i + 5] == pat and d[i] in opc:
            rva = o2r(i)
            if rva is not None and sec_of_off(i) == "CODE":
                print("  %s VA=%08X en %08X rva=%08X (%s)" % (opc[d[i]], va, i, rva, s[:40]))
                hits += 1
                if hits > 30:
                    break
    if hits == 0:
        print("  (sin refs mov-reg directos en CODE para %s)" % s[:40])

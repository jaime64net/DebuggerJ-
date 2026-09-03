#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ak3_ctree.py — arbol de llamadas recursivo sobre AppKeyX.dll.
Uso:
  ak3_ctree.py tree <rva-hex> [depth]        -> arbol de calls hasta depth (default 2)
  ak3_ctree.py fn <rva-hex>                  -> analisis detallado de una funcion
  ak3_ctree.py stats                         -> histograma global de funciones (heuristica)
"""
import sys, re
from ak3_lib import PE, DLL, disasm, rel_target

pe = PE(DLL)
IMPORTS = pe.imports()                       # name -> (dll, slot_rva)
SLOT_VA = {name: pe.imagebase + slot for name, (dll, slot) in IMPORTS.items()}
# mapa va-slot -> nombre
VA2IMP = {v: n for n, v in SLOT_VA.items()}

WANT = {"VirtualProtect", "VirtualQuery", "VirtualAlloc", "CreateFileA", "ReadFile",
        "WriteFile", "SetFilePointer", "SetEndOfFile", "MapViewOfFile",
        "CreateFileMappingA", "RegOpenKeyExA", "RegQueryValueExA", "GetLocalTime",
        "GetDateFormatA", "GetDiskFreeSpaceA", "CreateProcessA", "GetProcAddress",
        "LoadLibraryA", "CreateFileMappingA", "MessageBoxA", "IsDebuggerPresent",
        "GetModuleFileNameA", "GetSystemMetrics", "FindFirstFileA", "FindNextFileA",
        "GetFileSize", "Sleep", "CreateEventA", "WaitForSingleObject", "VirtualFree",
        "GetTickCount", "RaiseException", "GetModuleHandleA", "GetVersionExA",
        "ExitProcess", "UnhandledExceptionFilter", "SetFilePointer", "GetCurrentProcessId",
        "RegCloseKey", "GetVersion"}


def insn_str(ins):
    return "  %#08x  %-24s %-7s %s" % (ins.address, ins.bytes.hex(), ins.mnemonic, ins.op_str)


def fn_info(start, maxins=6000):
    insns = disasm(pe, start, maxins, stop_at_ret=True)
    calls = []          # (addr, target)
    irefs = []          # (addr, imp_name)
    strrefs = []        # (addr, rva_cadena, preview)
    immeds = {}         # interesantes
    jcc = 0
    backjumps = 0
    repops = 0
    for ins in insns:
        m, op = ins.mnemonic, ins.op_str
        if m == "call":
            t = rel_target(pe, ins)
            if t is not None:
                calls.append((ins.address, t))
            elif op.startswith("dword ptr [0x") or op.startswith("word ptr [0x"):
                v = int(op.split("0x")[1].rstrip("]"), 16)
                if v in VA2IMP:
                    irefs.append((ins.address, VA2IMP[v]))
        if m.startswith("j"):
            jcc += 1
            if m in ("jmp",) or m.startswith("j"):
                try:
                    t = int(op, 16)
                    if t < ins.address:
                        backjumps += 1
                except ValueError:
                    pass
        if m in ("rep", "repne") or op.startswith("rep"):
            repops += 1
        toks = re.findall(r"(0x[0-9a-fA-F]{6,8})", op)
        for tk in toks:
            v = int(tk, 16)
            rva = v - pe.imagebase
            if rva in VA2IMP and (m, op) and m != "call":
                irefs.append((ins.address, VA2IMP[rva]))
            # refs a cadenas en CODE (literales inline)
            if 0 <= rva < len(pe.d):
                b = pe.raw(rva, 8)
                if b and all(0x20 <= c < 0x7f for c in b[:4]) and b[:2] != b"\x00\x00":
                    s = pe.strz(rva, 80)
                    if s and len(s) >= 3 and m in ("push", "mov", "lea", "cmp"):
                        strrefs.append((ins.address, rva, s))
    end = insns[-1].address + len(insns[-1].bytes) if insns else start
    n = len(insns)
    return dict(start=start, n=n, end=end, calls=calls, irefs=irefs,
                strrefs=strrefs, jcc=jcc, backjumps=backjumps, repops=repops)


def fmt_sizes(pe, info):
    pass


def tree(root, depth):
    seen = {}
    def rec(rva, d, path):
        if rva in seen:
            return seen[rva]
        if d > depth:
            return None
        info = fn_info(rva)
        seen[rva] = info
        pad = "  " * d
        calls = info["calls"]
        u = {}
        for a, t in calls:
            u.setdefault(t, []).append(a)
        imp_names = sorted(set(x[1] for x in info["irefs"] if x[1] in WANT))
        # tamanno aproximado
        print("%s%08x n=%-5d end=%08x calls=%d jcc=%d back=%d rep=%d %s%s" %
              (pad, rva, info["n"], info["end"], len(calls), info["jcc"],
               info["backjumps"], info["repops"],
               ("API:" + ",".join(imp_names)) if imp_names else "",
               "  <== GRANDE" if info["n"] >= 60 else ""))
        # una linea por hijo
        for t in sorted(u):
            sub = rec(t, d + 1, path + [t])
        return info
    rec(root, 0, [root])


def fn_detail(start):
    info = fn_info(start)
    insns = disasm(pe, start, 6000, stop_at_ret=True)
    imp = pe.imports()
    rev = {pe.imagebase + slot: name for name, (dll, slot) in imp.items()}
    print("== fn %#x .. %#x  (%d insns)" % (start, info["end"], info["n"]))
    for ins in insns:
        m, op = ins.mnemonic, ins.op_str
        tag = ""
        t = None
        if m == "call":
            t = rel_target(pe, ins)
            if t is not None:
                tag = "  -> %#x" % t
        # marcar refs a slots IAT en cualquier operando
        for tk in re.findall(r"(0x[0-9a-fA-F]{6,8})", op):
            v = int(tk, 16)
            if v in rev:
                tag += "  IAT:%s" % rev[v]
        for rva, mm, oo in [(int(tk, 16) - pe.imagebase, m, op) for tk in re.findall(r"(0x[0-9a-fA-F]{6,8})", op)]:
            pass
        # strings en CODE (RVA mapeado con bytes ascii)
        for tk in re.findall(r"(0x[0-9a-fA-F]{6,8})", op):
            v = int(tk, 16)
            rva = v - pe.imagebase
            b = pe.raw(rva, 12)
            if b and sum(1 for c in b if 0x20 <= c < 0x7f) >= 6:
                s = pe.strz(rva, 70)
                if s:
                    tag += "  STR[%#x]=%r" % (rva, s)
                    break
        if m.startswith("j") or m in ("call", "ret") or "int3" in m or tag or \
           m in ("mov", "lea", "cmp", "push") and "0x40" in op or m in ("mov",) and "0x5d" in op:
            print(insn_str(ins) + tag)


if __name__ == "__main__":
    a = sys.argv[1:]
    if not a:
        print(__doc__); sys.exit(0)
    if a[0] == "tree":
        tree(int(a[1], 16), int(a[2]) if len(a) > 2 else 2)
    elif a[0] == "fn":
        fn_detail(int(a[1], 16))
    else:
        print(__doc__)

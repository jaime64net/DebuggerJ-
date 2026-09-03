#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""find_callers.py — importa disasm_akx2 (parse PE + lineal sweep) y reporta
callers de stubs/APIs sensibles, con su funcion contenedora (nearest export o
head del modelo). Solo lectura."""
import sys
sys.path.insert(0, "/home/jaime/.gemini/tmp/jaime/memory")
import disasm_akx2 as A
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

# --- 1) mapear ambas jump-tables de stubs: stubRVA -> (dll, api) ---
# tabla A: 0x1100..0x12B6 (jmp [slot]; nop)  y cola 0x12DC..0x131A
def build_table(r0, r1):
    tab = {}
    blob = A.code[r0 - A.cva: r1 - A.cva]
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    for ins in md.disasm(blob, A.va_of(r0)):
        rva = ins.address - A.IB
        if ins.mnemonic == "jmp" and len(ins.operands) == 1 and ins.operands[0].type == 3:
            tab[rva] = A.SLOT.get(ins.operands[0].mem.disp)
    return tab
TAB1 = build_table(0x1100, 0x131C)
TAB2 = {rva: api for rva, (api, _slot) in A.THUNKS.items()}
TAB = {}
for rva, api in list(TAB1.items()) + list(TAB2.items()):
    if api:
        TAB.setdefault(rva, api)

# heads de funcion: exports + heads modelo
def container(rva):
    best = 0
    for h in A.HEADS:
        if h <= rva and h > best:
            best = h
    return best

def lab(h):
    if h == 0:
        return "?"
    return "%s @0x%X" % (A.HEADS[h], h)

SENS = ["VirtualProtect", "VirtualAlloc", "VirtualFree", "VirtualQuery",
        "HeapAlloc", "LocalAlloc", "LocalFree", "HeapFree",
        "CreateFileMappingA", "MapViewOfFile", "UnmapViewOfFile",
        "WriteFile", "ReadFile", "CreateProcessA", "ExitProcess",
        "RegOpenKeyExA", "RegQueryValueExA", "RegCloseKey",
        "GetProcAddress", "LoadLibraryA", "LoadLibraryExA",
        "GetModuleHandleA", "GetModuleFileNameA", "GetExitCodeProcess",
        "IsDebuggerPresent", "CreateEventA", "SetEvent", "ResetEvent",
        "TlsAlloc", "Sleep", "GetCurrentProcessId", "GetProcessId",
        "CloseHandle", "CompareStringA", "CreateFileA", "FindFirstFileA",
        "FindNextFileA", "FindClose", "FreeLibrary", "FormatMessageA"]

# --- 2) recorrer SITES: targets que caen en TAB (stub) => API; func internos no resueltos
from collections import defaultdict
stub_calls = defaultdict(list)   # api -> [(caller_rva, tipo)]
func_calls = defaultdict(list)   # target -> [caller_rva]  (calls a funcs internas NO stub)
for rva in sorted(A.SITES):
    info = A.SITES[rva]
    if info["api"] is not None:
        stub_calls[info["api"][1]].append((rva, info["tipo"], info["api"][0]))
    else:
        t = info.get("target")
        if info["tipo"] == "func":
            if t in TAB:
                api = TAB[t]
                stub_calls[api[1]].append((rva, "func->stub", api[0]))
            else:
                func_calls[t].append(rva)
        elif info["tipo"] == "iat":
            stub_calls["?"].append((rva, "iat?", info.get("slot")))

want = set(SENS) | {"?"}
print("== callers por API sensible (caller RVA, forma, dll, funcion contenedora) ==")
for api in sorted(want):
    if api not in stub_calls:
        continue
    lst = sorted(stub_calls[api])
    print("\n### %s  n=%d" % (api, len(lst)))
    for (crva, tipo, dll) in lst:
        print("   caller 0x%X  %-12s %-12s en %s" % (crva, tipo, dll, lab(container(crva))))

# targets internos mas llamados (posibles funciones nucleo no-export)
print("\n== top funciones internas por numero de callers ==")
top = sorted(func_calls.items(), key=lambda kv: -len(kv[1]))[:25]
for t, callers in top:
    print("   func 0x%X  llamada desde %d sitios (container %s)" % (t, len(callers), lab(container(callers[0]))))

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""scan_slots.py — scan byte-level (alignment-free) de referencias en CODE a los
slots IAT de AppKeyX.dll. Un slot aparece como operando imm32: E4 51 49 00 (LE).
Para cada hit intenta realinear (call/jmp/push dword ptr [slot]: opcode 2B antes;
mov eax,[slot]=A1 5B antes; mov reg,[slot] 8B ?? = 3B antes) y reporta el RVA.
Solo lectura."""
import struct
P = "/mnt/c/Program Files (x86)/Compac/Contabilidad/AppKeyX.dll"
d = open(P, "rb").read()
CODE_RVA, CODE_OFF, CODE_LEN = 0x1000, 0x400, 0x58E00
code = d[CODE_OFF:CODE_OFF + CODE_LEN]

# slotRVA -> nombre (reutiliza el parseo .idata manual rapido)
import sys
sys.path.insert(0, "/home/jaime/.gemini/tmp/jaime/memory")
import disasm_akx2 as A  # parsea PE (imports/exports) - pesa poco

want = ["VirtualProtect", "VirtualAlloc", "VirtualFree", "VirtualQuery",
        "HeapAlloc", "LocalAlloc", "LocalFree", "HeapFree", "MapViewOfFile",
        "UnmapViewOfFile", "CreateFileMappingA", "WriteFile", "ReadFile",
        "CreateProcessA", "ExitProcess", "RegOpenKeyExA", "RegQueryValueExA",
        "RegCloseKey", "GetProcAddress", "LoadLibraryA", "LoadLibraryExA",
        "GetModuleHandleA", "GetModuleFileNameA", "GetExitCodeProcess",
        "IsDebuggerPresent", "CreateEventA", "SetEvent", "ResetEvent",
        "TlsAlloc", "Sleep", "GetCurrentProcessId", "GetProcessId",
        "CloseHandle", "CreateFileA", "FindFirstFileA", "FreeLibrary"]

slot_of = {}
for (dl, fn, s) in A.IMPORTS:
    if fn in want and fn not in slot_of:
        slot_of[fn] = s

def head_of(rva):
    best = 0
    for h in A.HEADS:
        if h <= rva and h > best:
            best = h
    return best

for fn in want:
    if fn not in slot_of:
        print("### %-22s (no importada)" % fn)
        continue
    slot_rva = slot_of[fn]
    pat = struct.pack("<I", 0x400000 + slot_rva)
    hits = []
    i = 0
    while True:
        j = code.find(pat, i)
        if j < 0:
            break
        hits.append(j)
        i = j + 1
    print("### %-22s slot 0x%X  refs en CODE: %d" % (fn, slot_rva, len(hits)))
    for j in hits[:25]:
        rva = CODE_RVA + j
        h = head_of(rva)
        print("   ref @rva 0x%X (fileoff 0x%X)  en %s @0x%X" % (
            rva, CODE_OFF + j, A.HEADS.get(h, "?"), h))

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""scan_rel.py — mapa definitivo de llamadores via byte-level:
 1) localiza TODOS los stubs `ff 25 <slot>` (ambas tablas) por slot importado;
 2) escanea CODE buscando E8/E9 rel32 (call/jmp) cuyo destino cae en un stub,
    y FF 15 (call dword ptr [slot]) directos;
 3) por API: lista caller RVA + head contenedor (exports/heads del modelo).
Solo lectura."""
import struct, sys
sys.path.insert(0, "/home/jaime/.gemini/tmp/jaime/memory")
import disasm_akx2 as A

P = "/mnt/c/Program Files (x86)/Compac/Contabilidad/AppKeyX.dll"
d = open(P, "rb").read()
CODE_RVA, CODE_OFF, CODE_LEN = 0x1000, 0x400, 0x58E00
code = d[CODE_OFF:CODE_OFF + CODE_LEN]

# slot VA -> (dll, fn)
SLOTVA = {}
for (dl, fn, s) in A.IMPORTS:
    SLOTVA.setdefault(0x400000 + s, (dl, fn))

def head_of(rva):
    best = 0
    for h in A.HEADS:
        if h <= rva and h > best:
            best = h
    return best

# 1) stubs ff25: opcode@i, disp@i+2  => stub opcode rva
stub_of_slot = {}     # slotVA -> stub rva (primero)
stubs_by_api = {}     # fn -> [stub rva]
i = 0
while i < len(code) - 6:
    if code[i] == 0xFF and code[i+1] == 0x25:
        (slotva,) = struct.unpack_from("<I", code, i + 2)
        if slotva in SLOTVA:
            rva = CODE_RVA + i
            stub_of_slot.setdefault(slotva, rva)
            stubs_by_api.setdefault(SLOTVA[slotva][1], []).append(rva)
        i += 6
    else:
        i += 1
print("== stubs ff25 hallados: %d (APIs: %d) ==" % (len(stub_of_slot), len(stubs_by_api)))

# 2) callers: E8/E9 rel32
def target_at(i):
    (rel,) = struct.unpack_from("<i", code, i + 1)
    return CODE_RVA + i + 5 + rel

STUB_RVAS = {r for r in stub_of_slot.values()}
# slotVA por stub rva (reverso)
slot_by_stub = {}
for sva, r in stub_of_slot.items():
    slot_by_stub.setdefault(r, sva)

api_callers = {}
direct_call_slot = {}
j = 0
while j < len(code) - 5:
    b = code[j]
    if b in (0xE8, 0xE9):
        t = target_at(j)
        rva = CODE_RVA + j
        # destino a stub ff25?
        if t in STUB_RVAS:
            slotva = slot_by_stub[t]
            fn = SLOTVA[slotva][1]
            api_callers.setdefault(fn, []).append(rva)
        j += 5
    elif b == 0xFF and code[j+1] == 0x15:
        (slotva,) = struct.unpack_from("<I", code, j + 2)
        if slotva in SLOTVA:
            fn = SLOTVA[slotva][1]
            direct_call_slot.setdefault(fn, []).append(CODE_RVA + j)
        j += 6
    else:
        j += 1

want = ["VirtualProtect", "VirtualAlloc", "VirtualFree", "VirtualQuery",
        "HeapAlloc", "LocalAlloc", "LocalFree", "MapViewOfFile",
        "CreateFileMappingA", "WriteFile", "ReadFile", "CreateProcessA",
        "ExitProcess", "RegOpenKeyExA", "RegQueryValueExA", "RegCloseKey",
        "GetProcAddress", "LoadLibraryA", "LoadLibraryExA",
        "GetModuleHandleA", "GetModuleFileNameA", "GetExitCodeProcess",
        "IsDebuggerPresent", "CreateEventA", "SetEvent", "ResetEvent",
        "TlsAlloc", "Sleep", "GetCurrentProcessId", "GetProcessId",
        "CloseHandle", "CreateFileA", "FindFirstFileA", "FreeLibrary",
        "GetCurrentThreadId", "GetTickCount", "QueryPerformanceCounter",
        "GetSystemTime", "lstrlenA", "lstrcmpA", "WideCharToMultiByte",
        "MultiByteToWideChar", "GetLastError", "SetLastError", "RtlUnwind",
        "GetCommandLineA", "GetStartupInfoA", "GetEnvironmentStringsA"]

print("\n== callers E8/E9 a stub por API ==")
for fn in sorted(api_callers):
    lst = sorted(set(api_callers[fn]))
    print("### %-22s n=%d" % (fn, len(lst)))
    for c in lst[:30]:
        h = head_of(c)
        print("   caller 0x%X en %s @0x%X" % (c, A.HEADS.get(h, "?"), h))
print("\n== call directos FF15 [slot] por API ==")
for fn in sorted(direct_call_slot):
    lst = sorted(set(direct_call_slot[fn]))
    print("### %-22s n=%d" % (fn, len(lst)))
    for c in lst[:30]:
        h = head_of(c)
        print("   caller 0x%X en %s @0x%X" % (c, A.HEADS.get(h, "?"), h))

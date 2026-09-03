#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Append §15 (opción 2 remodelación 0x1561C + opción 1 cti.exe/ClientDll, 2026-09-03)
to C:\\Discos\\contexto_debugger.md. Preserves CRLF / UTF-8-no-BOM. Anchors validated;
abort without writing on mismatch.
"""
import os

PATH = "/mnt/c/Discos/contexto_debugger.md"
with open(PATH, "rb") as f:
    data = f.read()
assert not data.startswith(b"\xef\xbb\xbf"), "BOM presente"
text = data.decode("utf-8")
assert "\n" not in text.replace("\r\n", ""), "linea sin CR"
n_crlf = text.count("\r\n")
assert n_crlf == 510, f"lineas CRLF={n_crlf} != 510"

TAIL_ANCHOR = "secciones/entropía, EP disasm, imports, firmas, rsrc)."
assert text.rstrip("\r\n").endswith(TAIL_ANCHOR), "ancla final no coincide"

CRLF = "\r\n"
body = [
    "## 15. Anexo — opción 2 (remodelación estática de 0x1561C) y opción 1 (cti.exe/ClientDll) — 2026-09-03",
    "",
    "### 15.1 Corrección de base: imagebase de AppKeyX.dll = 0x400000",
    "- Los literales del código (0x4158xx, 0x45FFF0, 0x406A24…) son VAs estáticos → **RVA = VA − 0x400000**.",
    "  Base runtime ASLR 0x5DF0000 (delta +0x59F0000). Secciones: CODE 0x1000 (vsize 0x58D04), DATA 0x5A000,",
    "  BSS 0x64000 (vsize 0x308C1), .idata 0x95000, .edata 0x96000, .reloc 0xC8000, .rsrc 0xD0000.",
    "  Los strings 0x4158xx viven dentro de CODE (Delphi: const en .text).",
    "- **DESCUBRIMIENTO: 0x6454–0x6634 NO son funciones (artefacto del ctree) sino jump-table de imports**:",
    "  bloque de thunks `jmp dword ptr [0x495xxx]` (paso 8 B). Fórmula kernel32:",
    "  `addr_thunk = 0x650C + 2*(0x495250 − slot)`; 2º grupo 0x6604–0x6630 → user32 (slots 0x4952B4–0x4952C8:",
    "  MessageBoxA/LoadStringA/GetSystemMetrics/Char*). 60 thunks mapeados; **162 call-sites directos",
    "  `call/jmp [IAT]` en CODE** (artefacto `thunk_apis.txt`). → Corrige §14.3 (\"sin call/jmp [IAT] directos\":",
    "  falso a medias: la tabla existe y hay calls directos; Reg*/oleaut32/user32 parcial sí van por GetProcAddress).",
    "- Thunks sueltos relevantes: 0x153B8 = `jmp [0x495300]` = **IsDebuggerPresent**;",
    "  0x153C0 = `jmp [0x4952FC]` = **GetProcessId**.",
    "",
    "### 15.2 Modelo completo del validador 0x1561C (168 insns; SEH 0x415847→0x3E30)",
    "1. Init: 0x136B8 (subárbol: LoadLibraryA×4 + GetProcAddress×15 + VirtualAlloc×6 + **único VirtualProtect",
    "   del subárbol en 0x14012**), 0x1526C, 0x14E50 → objeto gestor en **[0x45FFF4]**.",
    "2. Identidad: GetModuleFileNameA (0x154E0→0x153C8) vs \"MegaPAQw\"@0x415860 (0x7700); enumeración",
    "   0x2D1C/0x2D84/0x48A0 con **ExitProcess(0)** en la rama de match (0x156BB) → en proceso MegaPAQw ord1 no sigue.",
    "3. Request IPC: GetCurrentProcessId (0x156C6) → build `'\"%s\" %d %d'`@0x415890 vía 0x8638/0x864C/0x8274",
    "   (2 veces: 0x15721 y 0x157AC; la 2ª con edi = GetProcessId(hProc1)); **2 spawns CreateProcessA** vía",
    "   wrapper 0x15504 (0x1573A y 0x157C5). Strings satélite: \".bin\"@0x415880, \"-splash.exe\"@0x4158A4,",
    "   \"4b26608d\"@0x4158B8.",
    "4. Poll 0x157D0: Sleep(100 ms) (0xC338) + GetExitCodeProcess(hProc,&code). code==259 (STILL_ACTIVE) →",
    "   0x15810 IsDebuggerPresent: sin debug → vuelve a pollear; **debug → procede sin esperar al hijo**;",
    "   code≠259 → loop 0x157F8 (rama error/verificación con \"4b26608d\" vía 0xAF2C sobre objeto [0x406A24] + 0x3E68).",
    "5. Éxito: 0x15348→0x1519C (objeto [0x45FFEC] + \"Helper_NMR\"@0x415364) + método virtual",
    "   0x14EE8→0x14DB4→0x14D60 (`call eax`) sobre [0x45FFF4] → cleanup 0x44DC(8) → ret 0x15846.",
    "- Mecanismo Helper (strings 0x4152D8+): \"Helper_Entry\", \"HelperClientStubDll.dll\", \"$(EXE).hx$(IDX)\",",
    "  \"Helper_NML\", \"Helper_NMR\" → cliente de servicio vía DLL stub + ficheros hx compartidos (IPC).",
    "",
    "### 15.3 Restore de los 99 B: NO ocurre dentro de AppKeyX (0 hits)",
    "- 0 hits de literales 0x3E70/0x3270/0x403E70/0x403ED3 en toda AppKeyX.dll; **0 VirtualProtect/escritores",
    "  en la ruta de ord1** (el VP de 0x14012 está en init, no escribe el OEP) → quien valida/escribe es",
    "  **otro proceso o un servicio** (el hijo de CreateProcessA o el servicio local AppKey).",
    "- Encaje temporal: fallo ~1 s bajo debugger (rama \"debug → procede\" sin esperar al hijo, que aún no ha",
    "  escrito) y ~3.5 s con el parche jmp (hijo escribiendo mientras el parche salta el gate; luego el",
    "  retry-loop 0x3ED3+ detecta estado incompleto). Los **0 hits del DR0 write-hwbp**: con licencia inválida",
    "  NADIE escribe los 99 B.",
    "",
    "### 15.4 Opción 1 — contabilidad_i.bin == cti.exe: call-sites de AppKey/ClientDll (resultado)",
    "- Recap §14.8: PE32 Delphi plano, imagebase 0x400000, EP RVA 0x5C9B80, CODE 0x1000 (vsize 0x5C8C24).",
    "  Cadenas (layout AnsiString: refcount −1 y len delante del texto) y VAs:",
    "  - \"ClientDll.dll\"@VA 0x451360, \"$(EXE).dtx\"@0x451378 (string hermana), \"Client_Entry\"@0x45138C;",
    "    \"vcltest3.dll\"@0x44E0D0 + \"RegisterAutomation\"@0x44E0E0;",
    "    \"AppKey - <application_name>\"@0x9C9C08 (plantilla; en el extremo final del CODE, a 0x1C B del EP).",
    "- **F1 @0x51320** (EP 0x5C9BB2: se ejecuta sólo si 0x2E38()≥1; si ==0 va a la rama de registro/UI):",
    "  `0x511B8(\"$(EXE).dtx\", \"ClientDll.dll\")` = resolver módulo (0x51148: ya cargado → si NULL, 0x50EF8 =",
    "  LoadLibraryA vía thunk IAT 0x6B80) → `GetProcAddress(h, \"Client_Entry\")` → **`call eax`** (0x51344/0x5134D).",
    "  Gemelo estructural del Helper_Entry de AppKeyX.",
    "- IAT de cti resuelto: 0x6B80=LoadLibraryA, 0x6BB8=SetErrorMode, 0x6AC8=GetProcAddress,",
    "  **0x7268=SetWindowTextA (user32)** (no GetProcAddress como se sospechaba).",
    "- EP/objeto [0x9CB028]: 0x4E748 (callback global [0x9CAF88]), **0x4E348 = guarda \"AppKey - <app>\" en",
    "  [ebx+0x8C] y, si flag [ebx+0xA4], SetWindowTextA(hWnd=[ebx+0x30], PChar(nombre))**, 0x4E760/0x4E7E0",
    "  (init 0x4455DC→0x8584…). → cti usa el nombre AppKey como **título de ventana** del cliente de licencia.",
    "- vcltest3.dll: LoadLibrary + GetProcAddress(\"RegisterAutomation\") + call (0x4DDD2–0x4DE25; carga previa",
    "  con SetErrorMode 0x8000) → registro de automatización del componente.",
    "- **NO es el validador/escritor de los 99 B**: 0 imports y 0 strings de WriteProcessMemory/OpenProcess/",
    "  ReadProcessMemory/VirtualProtectEx/CreateRemoteThread (ni siquiera por GetProcAddress dinámico) y 0 tokens",
    "  del protocolo de AppKeyX ('\"%s\" %d %d', .hx, Helper, MegaPAQw, 4b26608d, splash, STILL_ACTIVE,",
    "  CreateProcess). Es el **cliente AppKey** (UI/registro/automation) del componente \"CTi\".",
    "",
    "### 15.5 contabilidad_i.mgr = \"AppKeyMgr\" (GUI) — tampoco valida",
    "- PE32 Delphi (EP RVA 0xACE000; imports GUI: kernel32/user32/advapi32/oleaut32/version/gdi32/comctl32).",
    "  Strings: `HKLM\\SOFTWARE\\Computación en Acción, SA CV\\AppKey\\LogPath`, \"AppKey.log\", \"AppKeyGui.log\",",
    "  \"[AppKeyMgr] Internal error %s: %s\" → componente GUI del cliente AppKey. Sin ClientDll/Client_Entry/",
    "  Helper/.hx/tokens IPC/APIs de escritura → tampoco es el validador.",
    "",
    "### 15.6 Lado servidor local (cierre del lead): ClientDll/vcltest3 NO instalados",
    "- find exhaustivo read-only (Windows System32+SysWOW64, Program Files, Program Files (x86)/Compac,",
    "  C:\\Compac, C:\\Apps, ProgramData, Discos): **ClientDll.dll y vcltest3.dll no existen en disco** → el",
    "  flujo ClientDll de cti/.mgr está inerte en este equipo; la validación real corre por los servicios",
    "  locales: `AppkeyAuthServer_Compac_V4` y `AppKeyLicenseServer_Compac_V4` →",
    "  `C:\\Program Files (x86)\\Compac\\Servidor de Licencias\\AppKey\\AppKey{Auth,License}Server.exe`.",
    "- Ambos servers: PE32 Delphi GUI (7.3 MB; EP 0x6E39B4/0x6E4404); contienen strings \"AppKey\", \"vcltest3\",",
    "  **\"ReadProcessMemory\"** (0x59A3A6/0x59A966) y **\"VirtualProtect\"** (0x6E60F6/0x6E6B3C) como literales",
    "  (resolución GetProcAddress dinámica); LicenseServer además \"CreateProcess\" (0x6E705E). Acompañan:",
    "  **CrypKeyDLL.dll** (SDK de terceros CrypKey; imports ADVAPI32/KERNEL32/USER32), AuthPingServer.dll,",
    "  DetectaFirewall.exe, *Stop.exe, AppKeyRT.dll (variante), logs activos (AppKeyLicenseServer.log, hoy).",
    "- Interpretación: **el validador es el servidor local CrypKey/AppKey**; la escritura de los 99 B es",
    "  en-proceso (VirtualProtect + escritura directa, no WriteProcessMemory) y sólo cuando el servidor valida",
    "  OK → bytes generados por la criptografía de licencia (CrypKey) a partir de licencia/registro: por eso no",
    "  hay literales de los 99 B en ningún binario (§14.4) y con licencia inválida nadie escribe (§15.3).",
    "- contabilidad_i.dat/.dtx: cabeceras KL/ZB (no PE); contienen MZ embebidos sin firma PE en los offsets",
    "  muestreados (contenedores). \"$(EXE).dtx\" en cti.exe sirve para localizar el módulo ya cargado por",
    "  nombre (GetModuleHandle), no es un PE que cti cargue por LoadLibrary en esta ruta.",
    "",
    "### 15.7 Estado y pendientes",
    "- Registro restaurado al original (sufijo `20251024103558302`), servicios AppKey Running, binarios",
    "  intactos (0 modificaciones en la fase), target MCP `exited` (requiere `restart`).",
    "- Opción 1 cerrada: el \"hijo\" lanzado por 0x1561C **NO es cti.exe (== contabilidad_i.bin) ni .mgr**",
    "  (ninguno implementa el protocolo ni tiene APIs de escritura). Verificación dinámica read-only pendiente",
    "  para confirmar la identidad real del hijo y si los slots IAT runtime 0x5E852FC/0x5E85300 están hookeados",
    "  (requiere target up/restart y autorización del usuario). Reloj atrás: sigue sin autorizar.",
    "- Artefactos en memory/: ak1561c_note.md (remodelación §15.1–15.3), thunk_apis.txt (162 call-sites),",
    "  cti_probe.py/cti_scan2.py/cti_scan3.py/cti_scan4.py/cti_iat.py/mgr_probe.py/svr_probe.py (sondas",
    "  read-only + *_out.txt), upd_ctx15.py (este anexo).",
    "",
]

text2 = text.rstrip("\r\n") + CRLF + CRLF + CRLF.join(body) + CRLF
out = text2.encode("utf-8")
assert not out.startswith(b"\xef\xbb\xbf")
tmp = PATH + ".tmp"
with open(tmp, "wb") as f:
    f.write(out)
os.replace(tmp, PATH)

with open(PATH, "rb") as f:
    v = f.read().decode("utf-8")
print("OK lineas CRLF:", v.count("\r\n"))
print("OK no-CR:", v.replace("\r\n", "").count("\n"))
print("OK 15.4:", "### 15.4 Opción 1" in v)
print("OK fin:", repr(v[-60:]))

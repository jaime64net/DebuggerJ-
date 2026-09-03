#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""upd_ctx18.py — append del anexo §16.7 (re-analisis guiado por el usuario:
"la app trae antidebugger; contabilidad_i.bin es la clave") a C:\Discos\contexto_debugger.md.
Preserva CRLF / UTF-8-sin-BOM. Ancla validada; escritura tmp + os.replace; auto-verificacion."""
import os

PATH = "/mnt/c/Discos/contexto_debugger.md"
with open(PATH, "rb") as f:
    data = f.read()
assert not data.startswith(b"\xef\xbb\xbf"), "BOM presente"
text = data.decode("utf-8")
n_crlf = text.count("\r\n")
assert n_crlf == 718, "lineas CRLF=%d != 718" % n_crlf
assert "\n" not in text.replace("\r\n", ""), "hay CR sueltos"
TAIL_ANCHOR = r"Pendiente de limpieza: C:\Discos\ak_watch.ps1."
assert text.rstrip("\r\n").endswith(TAIL_ANCHOR), "ancla final no coincide"

CRLF = "\r\n"
body = [
    "## 16.7 Anexo - Re-analisis guiado por el usuario: \"la app trae antidebugger; contabilidad_i.bin es la clave\" (2026-09-03)",
    "",
    "- Nota de arranque: la limpieza pendiente de §16.6 ya se hizo (C:\\Discos\\ak_watch.ps1 borrado; ak_watch.json no existia).",
    "- El usuario oriento el analisis a (1) el anti-debugger de la app y (2) contabilidad_i.bin como pieza clave.",
    "  Trabajo read-only: md5 + dumps de archivo + parseo PE + barrido de strings (0 escrituras).",
    "- Resultado principal: CORRECCION de atribucion del bloque CC (vive en contabilidad_i.exe, NO en el .bin)",
    "  + geometria PE del exe (protegido .appkey) + cierre del hueco anti-debug por nombre en el .bin.",
    "",
    "### 16.7.1 Identidad de los tres binarios (md5, 2026-09-03)",
    "- contabilidad_i.exe: md5 5a54dba70ffaeea1daae971266df972b, 84.286.872 B (Oct 16 2025) -> EL TARGET.",
    "  Es la imagen que contiene el OEP CC (16.7.2).",
    "- contabilidad_i.bin: md5 dd5d731939e831c15a0efb57dac149db, 6.137.240 B (Oct 16 2025).",
    "- cti.exe: md5 IDENTICO a contabilidad_i.bin -> son el MISMO archivo (byte a byte). El hijo de 0x1561C",
    "  (62016/55816/42876, §16.6) = cti.exe RENOMBRADO a contabilidad_i.bin. NO es copia del exe principal",
    "  (md5 distinto): es un binario aparte, el cliente AppKey \"plano\" de §15.4 (6 MB).",
    "",
    "### 16.7.2 El bloque CC de 99 B pertenece a contabilidad_i.exe (CORRECCION de atribucion)",
    "- Dump fileoff 0x3270: contabilidad_i.exe = CC CC CC... (los 99 int3); contabilidad_i.bin = codigo normal",
    "  (8b 3e 83 c6 06 8a 4e 06 38 d9 74 18 ...).",
    "- Dump fileoff 0x32D3: contabilidad_i.exe = 90 55 E8 D6 E0 FF FF ... (el \"codigo real desde 0x403ED3\"",
    "  de §13.2); contabilidad_i.bin = 0a 5b 59 5a c3 e9 ...",
    "- => RVA 0x3E70 / fileoff 0x3270 (el \"OEP\" 0x403E70 que empuja el stub) pertenece a la imagen de",
    "  contabilidad_i.exe. Las formulaciones previas \"bloque CC de 99 B en cti.exe\" eran imprecisas: el unico",
    "  archivo con los 99 CC en fileoff 0x3270 es el exe principal; en contabilidad_i.bin esa zona es codigo sano.",
    "",
    "### 16.7.3 Geometria PE de contabilidad_i.exe (84 MB; 10 secciones; PROTEGIDO .appkey)",
    "- .text RVA 0x1000 vsize 0x234B000 raw 0x400 | .data RVA 0x234C000 | .bss 0x2853000 | .rdata 0x2B4A000 |",
    "  .jidata RVA 0x4FA7000 | .idata RVA 0x4FEA000 (rsize 0x400) | .jedata RVA 0x4FEB000 |",
    "  **.appkey RVA 0x50EC000 vsize 0x207000** | .rsrc 0x52F3000 | .config 0x5359000.",
    "- EP_RVA = 0x50EC080 (0x80 dentro de .appkey). Cabecera: ImageBase = 0x1000 (anomalo), DynamicBase = NO,",
    "  SIN seccion .reloc.",
    "- Carga efectiva 0x400000 (coherente con todo lo observado en runtime: stub 0x54EC080 = 0x400000 + 0x50EC080;",
    "  trampa 0x403E70 = 0x400000 + RVA 0x3E70). Un PE sin .reloc y con preferred base 0x1000 NO puede cargar en",
    "  0x400000 via el loader estandar -> el exe se auto-protege/descifra (custom loader; coherente con VM/SEH de",
    "  §14). El analisis estatico previo uso VA = 0x400000 + RVA, correcto para la imagen en runtime.",
    "- contabilidad_i.bin/cti.exe: cabecera tambien ImageBase = 0x1000, EP_RVA 0x5C9B80, DynamicBase NO. El",
    "  analisis §15.4 con base 0x400000 sigue consistente (p. ej. \"ClientDll.dll\" VA 0x451360 = 0x400000 + RVA",
    "  0x51360 -> fileoff 0x50760, verificado en cti_scan2). Cabecera con ImageBase trucado a 0x1000 = sello del",
    "  protector en ambos binarios.",
    "",
    "### 16.7.4 Barrido anti-debug por nombre sobre contabilidad_i.bin (cierra hueco de §15.4)",
    "- strings -a -n 5 (ASCII): unicos hits relevantes = GetTickCount y UnhandledExceptionFilter (ubicuos en",
    "  Delphi/VCL; sin correlato adicional no prueban anti-debug activo).",
    "- 0 hits de: IsDebuggerPresent, CheckRemoteDebuggerPresent, DebugActiveProcess, DebugPort,",
    "  NtQueryInformationProcess, NtQuerySystemInformation, NtSetInformationThread, NtQueryObject,",
    "  NtQuerySystemTime, ZwQuery*, OpenProcess, ReadProcessMemory, WriteProcessMemory, VirtualProtectEx,",
    "  GetThreadContext, SetThreadContext, SuspendThread, ResumeThread, OutputDebugString,",
    "  QueryPerformanceCounter, CreateToolhelp32Snapshot, Process32First, SetUnhandledExceptionFilter.",
    "- => el hijo contabilidad_i.bin NO dispone (ni por import ni por GetProcAddress con nombre en claro) de",
    "  ninguna API para inspeccionar al padre ni anti-debug clasico por nombre. Reafirma §15.4 y DESCARTADA la",
    "  via \"el hijo detecta el debugger del padre con APIs de proceso\". El anti-debug efectivo (§6: muerte aun",
    "  con PEB parcheado -> DebugPort/otros; §15.3: rama IsDebuggerPresent del poll en AppKeyX) reside en la",
    "  cadena principal exe/AppKeyX.",
    "",
    "### 16.7.5 Captura del cmdline del hijo: preparada pero CANCELADA (pendiente si se autoriza)",
    "- Objetivo: decodificar el request '\"%s\" %d %d' de 0x1561C (que PIDs recibe contabilidad_i.bin al nacer;",
    "  pendiente de ak1561c_note y §16.5). Se creo child_cmdline.sh (watcher: list_children cada 1 s buscando",
    "  PID fuera de {62016, 55816, 42876} + UNA query wmic de cmdline al hijo nuevo, max 18 s).",
    "- Estado: el watcher NO se ejecuto (denegado por el usuario). obs_run.py si corrio en background y volvio a",
    "  alcanzar la trampa (régimen B estable): 0x403E71 / esp 0x18FF78 a 5.45 s, mem[0x403E70..] todo CC.",
    "  Sin captura de cmdline -> sigue PENDIENTE.",
    "",
    "### 16.7.6 Sintesis para la hipotesis del usuario",
    "- Cadena real: contabilidad_i.exe (84 MB, protegido .appkey; contiene el OEP CC 99 B en su .text) = proceso",
    "  principal; AppKeyX cargada en el valida y restauraria los 99 B con licencia valida (§15.3). El hijo =",
    "  contabilidad_i.bin == cti.exe (6 MB; cliente AppKey independiente: F1 -> \"$(EXE).dtx\" = contabilidad_i.dtx,",
    "  que SI existe (12.7 MB) -> el fallback ClientDll.dll ausente no aplica al correr como .bin).",
    "- Lo que SI sostiene \"contabilidad_i.bin es la clave\": correlacion 1:1 hijo <-> trampa y muerte 0x1E sin hijo",
    "  vs 0x1F con hijo (§16.6); el padre pollea al hijo (Sleep 100 + GetExitCodeProcess + rama IsDebuggerPresent,",
    "  §15.3).",
    "- Lo que NO sostiene: que el hijo ejecute el anti-debugger contra el padre (16.7.4: sin APIs de proceso).",
    "  El anti-debug observado vive en la cadena principal. El rol exacto del hijo sigue abierto; decodificar su",
    "  cmdline (16.7.5) es el siguiente paso natural si el usuario lo autoriza.",
    "- Estado: 0 bps; target exited tras el run bg de obs_run.py; disco/registro INTACTOS (solo lecturas + go +",
    "  restart). Artefactos: child_cmdline.sh (creado, NO ejecutado), obs_child_out.txt (run régimen B),",
    "  upd_ctx18.py (este anexo).",
]
text2 = text.rstrip("\r\n") + CRLF + CRLF + CRLF.join(body) + CRLF
out = text2.encode("utf-8")
tmp = PATH + ".tmp"
with open(tmp, "wb") as f:
    f.write(out)
os.replace(tmp, PATH)
with open(PATH, "rb") as f:
    v = f.read().decode("utf-8")
print("OK lineas CRLF:", v.count("\r\n"))
print("OK no-CR:", "\n" not in v.replace("\r\n", ""))
print("OK 16.7:", "### 16.7.6" in v and "16.7.4" in v)
print("OK 16.6 intacto:", "### 16.6" in v)

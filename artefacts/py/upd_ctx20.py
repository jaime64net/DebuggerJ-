#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""upd_ctx20.py — append §16.9 (cmdline del hijo CAPTURADO + decode + bootstrap .dtx) a C:\Discos\contexto_debugger.md"""
import os

PATH = "/mnt/c/Discos/contexto_debugger.md"
with open(PATH, "rb") as f:
    data = f.read()
assert not data.startswith(b"\xef\xbb\xbf"), "BOM presente"
text = data.decode("utf-8")
n_crlf = text.count("\r\n")
assert n_crlf == 821, "lineas CRLF=%d != 821" % n_crlf
assert "\n" not in text.replace("\r\n", ""), "hay CR sueltos"
TAIL_ANCHOR = "disco/registro intactos."
assert text.rstrip("\r\n").endswith(TAIL_ANCHOR), "ancla final no coincide"

CRLF = "\r\n"
body = [
    "## 16.9 Anexo - CMDLINE DEL HIJO CAPTURADO + decode del request + bootstrap .dtx (2026-09-03, 2a parte)",
    "",
    "### 16.9.1 Captura exitosa (metodo watcher PowerShell persistente)",
    "- En el run regimen B nº4 (obs_run.py bg; trampa 0x403E71 @6.76 s, mem CC) el watcher",
    "  watcher_cmd.ps1 (Get-CimInstance Win32_Process cada 150 ms filtrando Name IN",
    "  {contabilidad_i.bin, cti.exe} y excluyendo PIDs conocidos, arrancado ANTES del run)",
    "  capturo al hijo al nacer:",
    "    HIT_PID=16504  HIT_NAME=contabilidad_i.bin",
    "    HIT_EXE=C:\\Program Files (x86)\\Compac\\Contabilidad\\contabilidad_i.bin",
    '    HIT_CMDLINE="C:\\Program Files (x86)\\Compac\\Contabilidad\\contabilidad_i.bin" 43788 0',
    "- Por que fallaron los intentos 1-3: (a) wmic NO existe en este Windows (salio vacio en",
    "  silencio con 2>/dev/null); (b) el hijo MUERE en <1-2 s -> los retries PowerShell-CIM a",
    "  posteriori (child_cmd2.sh, 10x0.6s) nunca lo encontraron vivo; (c) la latencia de spawn",
    "  de powershell.exe (~1.5-2 s) hace inutil arrancar el capturador despues del run. Solucion:",
    "  proceso PS persistente activo antes del restart, polling CIM en-proceso cada 150 ms.",
    "",
    "### 16.9.2 Decodificacion del request de 0x1561C (ak1561c_note)",
    "- El request '\"%s\" %d %d' queda decodificado EMPIRICAMENTE:",
    "  %s = ruta completa del .bin entre comillas; %d(1) = 43788 = GetCurrentProcessId del",
    "  spawner (AppKeyX dentro del target contabilidad_i.exe de ESE run); %d(2) = 0 = el 2º",
    "  build (0x157AC, edi=GetProcessId(hProc1)) devolvio 0 -> hProc1 invalido/cerrado en ese",
    "  punto (o el 2º spawn 0x157C5 no llego a construirse). El hijo nace pues como:",
    '    contabilidad_i.bin "<su propia ruta>" <pid_del_padre> 0',
    "- Correlacion de PIDs: el target vivo DESPUES del run es 46584 (auto-restart post-trampa,",
    "  patron §16), distinto de 43788 -> 43788 fue el pid del target durante el run en que el",
    "  hijo nacio (el arg del hijo = pid del padre al nacer, no el actual). Hijo 16504 ya muerto",
    "  (esperable: con licencia invalida sale rapido, §ak1561c implicacion).",
    "- Pendiente ak1561c_note resuelto: identidad del hijo = contabilidad_i.bin (ya sabido §16.7)",
    "  y cmdline REAL = (ruta, pid_padre, 0). Queda abierta la semantica del 0 (hProc1 vs 2º",
    "  spawn) - solo disasm fino de 0x157AC/0x157C5 la cerraria (opcional, estatico).",
    "",
    "### 16.9.3 Bootstrap del .bin decodificado (estatico, EP 0x5C9B80)",
    "- Disasm del EP de contabilidad_i.bin/cti.exe (base 0x400000):",
    "    0x5C9B80 push ebp / mov ebp,esp / add esp,-0x10",
    "    ... init de objetos (mov eax,0x9c9970; call 0x67e8; push 1; call 0x6a68/0x6bd0; ...)",
    "    call 0x2E38          ; 'mode AppKey'? retorna >=1 si hay que ir por la ruta cliente",
    "    dec eax / jl 0x5c9bb9 ; si <1 -> init UI normal (VCL, titulo 'AppKey - <app>')",
    "    call 0x51320         ; F1: resolver y cargar helper -> Client_Entry",
    "    jmp 0x5c9bfa",
    "    0x5c9bb9: (UI normal: Application.Initialize/CreateForm con 0x9cb028, 0x9c9c08,",
    "              0x4513d4, 0x9cae28) ; 0x5c9bfa: call 0x4808 (cleanup/exit)",
    "- Imports del .bin: 383; GetCommandLineA (IAT VA 0x5CE17C) presente pero 0 referencias",
    "  call/jmp [IAT] directas en CODE -> o se consume via RTL/ParamStr indirecto o los 2 ints",
    "  se pasan tal cual a Client_Entry. F1 (0x51320, §15.4) carga \"$(EXE).dtx\" =",
    "  contabilidad_i.dtx (12.7 MB, EXISTE) y llama Client_Entry -> LA LOGICA HIJA REAL =",
    "  Client_Entry dentro de contabilidad_i.dtx. El .dtx pasa a ser el candidato nº1 para el",
    "  protocolo/anti-debug del lado hijo (pendiente estatico opcional: PE/strings/imports del",
    "  .dtx; §15.5 lo trato como contenedor MZ-sin-firma junto a .dat/.mgr).",
    "- 0x2E38 (18 insns vistas): prologo SEH (handler 0x402e91), call 0x1284, call 0x2cd4",
    "  (lea edx,[ebp-8]) -> determina el modo (>=1 = ruta cliente). Semantica exacta pendiente.",
    "",
    "### 16.9.4 Estado final y artefactos",
    "- MCP debugger 8378: ECONNRESET tras el run (server caido/wedged tras el auto-restart) ->",
    "  requiere restart del usuario para mas runs dinamicos. list_bp no verificable ahora pero",
    "  obs_run es go-only (0 bps). Target: contabilidad_i.exe PID 46584 vivo (auto-restart).",
    "- Artefactos en memory/: watcher_cmd.ps1 (NUEVO, metodo ganador), watcher_out.txt (hit),",
    "  obs_child_out4.txt (trampa @6.76 s), child_cmdline.sh + child_cmd2.sh (fallidos: wmic",
    "  ausente en este Windows), upd_ctx19.py (§16.8), upd_ctx20.py (este anexo).",
    "- Documento: 821 lineas CRLF antes de este anexo; binarios/registro/servicios intactos.",
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
print("OK 16.9:", "### 16.9.1" in v)
print("OK 16.8 intacto:", "### 16.8" not in v)
print("OK 16.7 intacto:", "### 16.7.6" in v)

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""upd_ctx19.py — append del anexo §16.8 (autorizacion del usuario + protocolo de ejecucion)
a C:\Discos\contexto_debugger.md. Preserva CRLF / UTF-8-sin-BOM. Ancla validada."""
import os

PATH = "/mnt/c/Discos/contexto_debugger.md"
with open(PATH, "rb") as f:
    data = f.read()
assert not data.startswith(b"\xef\xbb\xbf"), "BOM presente"
text = data.decode("utf-8")
n_crlf = text.count("\r\n")
assert n_crlf == 795, "lineas CRLF=%d != 795" % n_crlf
assert "\n" not in text.replace("\r\n", ""), "hay CR sueltos"
TAIL_ANCHOR = "upd_ctx18.py (este anexo)."
assert text.rstrip("\r\n").endswith(TAIL_ANCHOR), "ancla final no coincide"

CRLF = "\r\n"
body = [
    "## 16.8 Anexo - Autorizacion del usuario y protocolo de ejecucion (2026-09-03, 2a parte)",
    "",
    "- El usuario autoriza ejecutar la observacion dinamica pendiente (captura del cmdline del hijo",
    "  contabilidad_i.bin al nacer, child_cmdline.sh, §16.7.5) con la condicion de documentar TODO primero",
    "  en este doc. Tambien queda en curso el decode estatico del manejo de argumentos en contabilidad_i.bin/",
    "  cti.exe (bootstrap EP 0x5C9B80 / F1 0x51320 / carga de $(EXE).dtx).",
    "- Protocolo (read-only; 0 escrituras a disco/registro/binarios; 0 bps residuales; UNA unica query wmic):",
    "  1. [estatico] imports de contabilidad_i.bin filtrados (GetCommandLineA presente, ver abajo) + disasm del",
    "     bootstrap EP 0x5C9B80 + flujo EP -> 0x2E38 -> F1 (0x51320): confirmar si al correr como .bin carga",
    "     \"$(EXE).dtx\" = contabilidad_i.dtx (12.7 MB, EXISTE en el folder) y llama Client_Entry; y donde se",
    "     consumen los 2 enteros del request '\"%s\" %d %d' de 0x1561C.",
    "  2. [dinamico] run regimen B: obs_run.py (go-only; trampa 0x403E71 a ~5-6 s; el hijo nace ~1-2 s antes)",
    "     en background + child_cmdline.sh (watcher: list_children cada 1 s; al detectar PID fuera de",
    "     {62016, 55816, 42876} -> UNA query wmic CommandLine/ExecutablePath; max 18 s).",
    "  3. Lectura de obs_child_out.txt (confirmacion de trampa), verificacion list_bp vacio, target exited.",
    "- Criterio de exito del paso 2: cmdline real del hijo que decodifica el request de 0x1561C (que PIDs recibe",
    "  y bajo que nombre) - pendiente nº de ak1561c_note / §16.5 / §16.7.5.",
    "- Limites reiterados: sin step_into en el arranque (regimen A mata el run); sin bps dentro de AppKeyX; sin",
    "  write_mem en este experimento (obs_run.py solo go + lecturas de memoria); interop Windows al minimo.",
    "- Sonda estatica inicial (hecha): imports de contabilidad_i.bin = 383; entre los relevantes: GetCommandLineA,",
    "  GetCurrentProcessId, GetCurrentProcess, GetModuleFileNameA, LoadLibraryA/LoadLibraryExA, GetProcAddress,",
    "  GetTickCount, UnhandledExceptionFilter, ExitProcess (kernel32). SIN CreateProcess*/GetExitCodeProcess/",
    "  OpenProcess/IsDebuggerPresent (el spawner/poll es AppKeyX, §15.3; el anti-debug no esta aqui por nombre).",
    "  GetCommandLineA presente -> el .bin PUEDE parsear su propia argv (Delphi/VCL lo hace en init).",
    "- Estado previo: 795 lineas CRLF; §16.7 cerrado; target exited; list_bp vacio; disco/registro intactos.",
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
print("OK 16.8:", "### 16.8" in v)
print("OK 16.7 intacto:", "### 16.7.6" in v)

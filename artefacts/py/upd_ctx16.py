#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Append §16 (verificación dinámica read-only del paso 4, 2026-09-03)
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
assert n_crlf == 610, f"lineas CRLF={n_crlf} != 610"

TAIL_ANCHOR = "read-only + *_out.txt), upd_ctx15.py (este anexo)."
assert text.rstrip("\r\n").endswith(TAIL_ANCHOR), "ancla final no coincide"

CRLF = "\r\n"
body = [
    "## 16. Anexo — verificación dinámica read-only (paso 4, autorizada) — 2026-09-03",
    "",
    "### 16.1 Sesión de verificación dinámica: DebuggerJ++ MCP (read-only estricto)",
    "- Conectividad: el MCP del debugger escucha en **TCP 8378** (no 8377 como sugería la nota previa);",
    "  helper `dbg.mjs` (`DBGJPP_PORT=8378 node dbg.mjs <cmd> ['<args-json>']`), token de sesión en",
    "  memory/debuggerjpp-token (no imprimirlo). Server MCP: `C:\\Discos\\Proyectos\\NEXCODE\\DebuggerJ++\\mcp\\",
    "  server.mjs` (esquemas de tools dbg_* en líneas 48–160).",
    "- Tools usadas (todas read-only o de control de sesión): status, get_regs, read_mem, disasm, list_bp,",
    "  del_bp, set_bp, list_children, set_follow_children, switch_to_child, attach, poll_events, step_into,",
    "  go, restart, modules, threads. **NO se usó write_mem/patch/assemble ni escritura de registros/reloj**",
    "  → 0 modificaciones a binarios, DLLs compartidas o registro del sistema (sólo bps software efímeros del",
    "  debugger, retirados al terminar; un bp en AppKeyX sí altera el run — ver §16.4).",
    "- El target (binario CONTPAQ bajo análisis) arranca bajo el MCP, que lo auto-reinicia al morir (target",
    "  `exited` → restart); el proceso principal se relanza repetidamente y el debugger debe ejecutarse fresco",
    "  tras cada restart.",
    "",
    "### 16.2 Slots IAT runtime — CONFIRMADO SIN HOOKING (paso 4b, cerrado)",
    "- AppKeyX.dll se carga bajo **ASLR**: la base runtime varía por run. Bases observadas en esta fase:",
    "  0x5CF0000, 0x5DF0000, 0x5E10000, 0x5DD0000, 0x5DE0000, 0x5EC0000, **0x5E80000**. Antes de usar",
    "  cualquier slot se confirmó la base real leyendo el MZ (2 bytes '4D5A').",
    "- Instancia observada (base real 0x5E80000, confirmada por MZ). Thunks IAT de interés — relativos a",
    "  imagebase 0x400000 son RVA+0x953B8 / RVA+0x953C0 (§15.1: 0x153B8/0x153C0):",
    "  - `0x5E953B8` = `jmp [0x5F15300]` (IsDebuggerPresent). Slot 0x5F15300 → **0x7627D980** = kernel32",
    "    stub `jmp [0x762E1178]` → **0x777CAA00** kernelbase: `mov eax,fs:[0x30]; movzx eax,[eax+2]; ret`",
    "    (cuerpo canónico de IsDebuggerPresent).",
    "  - `0x5E953C0` = `jmp [0x5F152FC]` (GetProcessId). Slot 0x5F152FC → **0x7627DA60** = kernel32",
    "    hotpatch (`8B FF 55 8B EC` = mov edi,edi; push ebp; mov ebp,esp) `jmp [0x762E17F8]` →",
    "    **0x777CEA10** kernelbase GetProcessId (`mov edi,edi; push ebp; mov ebp,esp; sub esp,0x1C; …`).",
    "- Conclusión: ambos slots resuelven a **kernel32/kernelbase genuinos** (cadenas completas de export",
    "  verificadas por disasm); ningún puntero apunta a AppKeyX ni a ntdll → **sin hooking de IAT en runtime**.",
    "  Consistente con el estático (§15.1): los thunks 0x153B8/0x153C0 → slots 0x495300/0x4952FC se resuelven",
    "  limpios. Queda verificado que el cliente AppKeyX no interpone hooks propios en esas dos APIs críticas.",
    "",
    "### 16.3 Hijo real capturado: PID 62016 (paso 4a — identidad PENDIENTE)",
    "- `set_follow_children` ON antes de lanzar. Tras restart + `step_into` (sobre el int3 del park del loader,",
    "  §16.4) + `go`: poll_events registró **seq 950 `create_process_child` pid 62016** (el MCP detecta al",
    "  hijo que el proceso principal lanza), seguido de cargas de DLLs, auto-pausa en la trampa del binario",
    "  0x403E70 y finalmente `exit 0x4000001F` del proceso principal.",
    "- `list_children` → [62016]: **un único hijo registrado**. Este es el candidato a \"hijo real\" que el",
    "  modelo estático de 0x1561C predecía (2 spawns CreateProcessA; §15.2) y a quien habría que atribuir la",
    "  validación/escritura de los 99 B (§15.3) si sobrevive al gate de IsDebuggerPresent.",
    "- El hijo terminó antes de poder identificarlo: `switch_to_child 62016` (ok, \"switching\") y",
    "  `attach {\"pid\":62016}` (ok, \"attaching\") fueron aceptados por el MCP, pero status seguía mostrando el",
    "  target `exited` y `threads` vacío → el hijo ya no vivía al observarlo (o el switch no adjuntó de forma",
    "  efectiva un target ya fenecido).",
    "- La identificación Windows (nombre/ruta/línea de comandos del PID 62016) **NO se completó**: queries",
    "  CIM (Get-CimInstance Win32_Process) y tasklist.exe colgaron por saturación de la interop WSL↔Windows.",
    "  Causa raíz: 3 watchers PowerShell `ak_watch.ps1` martillando Win32_Process cada ~25 ms desde WSL",
    "  saturaban la interop; los 3 fueron matados junto con el tasklist. Los watchers NUNCA registraron evento",
    "  (método `ak_watch.ps1` + `C:\\Discos\\ak_watch.json` → **descartado como método**; limpiar al terminar).",
    "- PENDIENTE (paso 4a): identificar la imagen del hijo — o bien `attach 62016` si aún viviera, o bien un",
    "  relanzamiento con estrategia limpia: restart → step_into → go con set_follow_children y **una sola**",
    "  query CIM puntual (sin watchers ni loops) en el instante del evento.",
    "",
    "### 16.4 Mecánica operativa del run (observaciones de sesión)",
    "- Tras `restart`, el proceso queda en un park del loader: ntdll `LdrpDoDebuggerBreak` (int3, eip",
    "  ~0x77CB87F8). `go` a veces no sale del park; `step_into` (EIP pasa el int3 → 0x77CB87F9) + `go` deja",
    "  correr el run con normalidad.",
    "- Run natural (sin bps dentro de AppKeyX): carga de DLLs → auto-pausa en la trampa int3 del binario",
    "  0x403E70 (zona del gate de licencia) → `exit 0x4000001F`.",
    "- **Un bp software dentro de código de AppKeyX altera el run**: en la fase previa, un bp en 0x5D057D0",
    "  (run con base 0x5D00000) mató el run directo con exit 0x4000001F sin alcanzar la trampa → para capturar",
    "  hijos NO poner bps dentro de AppKeyX. (Los bps software reescriben el byte en memoria; los DR0 hwbp",
    "  serían read-only equivalentes, pero no se usaron en esa zona.)",
    "- Con el debugger conectado el validador detecta debug (rama IsDebuggerPresent del poll, §15.3): el run",
    "  principal procede sin esperar al hijo (~1 s), consistente con los tiempos de la fase estática.",
    "",
    "### 16.5 Estado y pendientes",
    "- Estado: fase dinámica autorizada por el usuario (\"continua con todo\", sudo incluido) y ejecutada como",
    "  **read-only estricto**. Paso 4b CERRADO (IAT runtime sin hooks). Paso 4a EN CURSO: PID del hijo",
    "  capturado (62016) pero imagen sin identificar.",
    "- Pendientes: (i) identificar imagen/cmdline del hijo (nuevo run con estrategia limpia, o attach si vive);",
    "  (ii) confirmar en list_bp y eliminar el bp temporal `ak_ep_tmp` (0x54EC080) si el server conserva la",
    "  sesión; (iii) limpiar `C:\\Discos\\ak_watch.ps1` y `C:\\Discos\\ak_watch.json` (método fallido); (iv) no",
    "  cerrar §16 hasta completar 4a.",
    "- Nota de proceso: se respetó el freno del usuario (canceló el último get_regs de sondeo). El próximo",
    "  reintento de identificación del hijo se hará informando primero y con su visto bueno.",
    "- Artefactos en memory/: debuggerjpp-mcp.md (conexión MCP/tools), dbg.mjs (helper), ak_watch.ps1 (método",
    "  fallido, en C:\\Discos), upd_ctx16.py (este anexo).",
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
print("OK 16.2:", "### 16.2 Slots IAT runtime" in v)
print("OK 16.3:", "PID 62016" in v)
print("OK fin:", repr(v[-60:]))

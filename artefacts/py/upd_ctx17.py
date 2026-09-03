#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""upd_ctx17.py — append del anexo §16.6 (experimento parche variante-b re-run + hijo identificado)
a C:\Discos\contexto_debugger.md. Preserva CRLF / UTF-8-sin-BOM. Anclas validadas;
escritura tmp + os.replace; auto-verificacion."""
import os

PATH = "/mnt/c/Discos/contexto_debugger.md"
with open(PATH, "rb") as f:
    data = f.read()
assert not data.startswith(b"\xef\xbb\xbf"), "BOM presente"
text = data.decode("utf-8")
n_crlf = text.count("\r\n")
assert n_crlf == 690, f"lineas CRLF={n_crlf} != 690"
assert "\n" not in text.replace("\r\n", ""), "hay CR sueltos"
TAIL_ANCHOR = "upd_ctx16.py (este anexo)."
assert text.rstrip("\r\n").endswith(TAIL_ANCHOR), "ancla final no coincide"

CRLF = "\r\n"
body = [
    "### 16.6 Re-run del parche variante (b) (2026-09-03) + HIJO IDENTIFICADO = contabilidad_i.bin (paso 4a cerrado)",
    "",
    "- Encargo: \"intentar la opcion de los 90 bytes NOP\" (variante (b) de §13.4: bloque CC 0x403E70..0x403ED2).",
    "- RECETA que alcanza la trampa (régimen B): **solo `go` repetido** desde los parks del loader",
    "  (secuencia observada: park 0x77c5bf30 -> go -> park 0x77cf87f9 -> go -> park 0x77c5bf30 -> go -> TRAMPA",
    "  0x403E71 esp 0x18FF78 a los ~5.7-6.9 s). `step_into` = régimen A: muerte pre-trampa determinista con",
    "  exit **0x4000001E** y SIN create_process_child (8+ ciclos identicos, seq 1013-1183).",
    "- Parche (b) aplicado y verificado: write_mem 0x403E70 len=99 -> {ok:true, written:99}; bloque pre-parche CC",
    "  puro (99 x CC); post-parche `90 E9 5D 00 00 00` + 93 NOPs (jmp -> 0x403ED3). eip estaba en 0x403E71.",
    "- Tras el go: el proceso NO muere en el gate; carga ~30 DLLs de inicializacion real (events load_dll",
    "  seq 1350-1362, +0.2 s), luego park en int3 ntdll **0x77CF87F8** (esp 0x1AFA54, hilo distinto al principal,",
    "  marcador pre-muerte documentado en §13.3), go -> **exit_process 0x4000001F** (seq 1364, 0.82 s).",
    "  => mismo resultado que §13.4: el parche da vida extra (init real) pero el verificador/vigilante mata igual;",
    "  sin neutralizar al verificador no hay salida. SIN bypass funcional (esperado).",
    "- **HIJO IDENTIFICADO (paso 4a cerrado)**: correlacion 1:1 entre `create_process_child` y alcanzar la trampa:",
    "  hijo 62016 (seq 950) -> trampa seq 964; hijo 55816 (seq 1248) -> trampa seq 1262; hijo 42876 (seq 1314)",
    "  -> trampa seq 1328 (4210288 = 0x403E70). Runs pre-trampa (exit 0x1E): SIN hijo. Los PIDs hijos mueren",
    "  rapido; el PID 42876 se capturo VIVO con una sola query tasklist (interop limpia):",
    "  **`contabilidad_i.bin`** (Console Session 2, ~5.4 MB) => confirma la prediccion estatica de §15.2",
    "  (spawner 0x1561C, string \".bin\" @0x415880). Los hijos 62016/55816 eran casi seguro tambien",
    "  contabilidad_i.bin (== cti.exe, md5 dd5d7319..., §15.4). `list_children` ACUMULA entre runs",
    "  (62016, 55816, 42876); el evento create_process_child NO se reemite por run en poll_events.",
    "- Muerte 0x1E (pre-trampa, sin hijo) vs 0x1F (con hijo/trampa): refuerza que el hijo participa en el camino",
    "  de validacion ANTES del gate (aunque §15.4 no le hallo APIs de escritura -> su rol exacto sigue abierto;",
    "  ver §16.5 pendientes). El breakpoint 0x77CF87F8 (y 0x77DF87F8 en otro ASLR) precede el exit 0x1F.",
    "- Estado: 0 bps puestos (list_bp vacio); target exited tras el experimento; disco/registro INTACTOS (los",
    "  parches solo vivieron en memoria de procesos ya muertos). Artefactos: trap_nop_b.py (+ trap_nop_b_out*.txt),",
    "  obs_run.py (receta go-only), upd_ctx17.py (este anexo). Pendiente de limpieza: C:\\Discos\\ak_watch.ps1.",
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
print("OK 16.6:", "### 16.6" in v)
print("OK 16.5 intacto:", "### 16.5" in v and "### 16.6" in v)

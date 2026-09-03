#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Append §14 (static analysis 2026-09-03) + header note to C:\\Discos\\contexto_debugger.md.
Preserves CRLF / UTF-8-no-BOM. Validated anchors: abort without writing on mismatch.
"""
import os, sys

PATH = "/mnt/c/Discos/contexto_debugger.md"

with open(PATH, "rb") as f:
    data = f.read()

assert not data.startswith(b"\xef\xbb\xbf"), "BOM presente, abortando"
text = data.decode("utf-8")
assert "\n" not in text.replace("\r\n", ""), "hay fines de linea sin CR, abortando"
n_crlf = text.count("\r\n")
assert n_crlf == 405, f"lineas CRLF = {n_crlf} != 405, abortando"

HDR_ANCHOR = "> (0x4000001F en runs limpios)."
assert text.count(HDR_ANCHOR) == 1, f"ancla cabecera count={text.count(HDR_ANCHOR)}, abortando"

TAIL_ANCHOR = "salida completa de `akscan.py` (§11.4)."
assert text.rstrip("\r\n").endswith(TAIL_ANCHOR), "ancla final no coincide, abortando"

CRLF = "\r\n"

header_add = [
    "> **Actualizado el 2026-09-03** con el anexo §14: análisis estático de AppKeyX ord1 — mecanismo del gate",
    "> (entry `.appkey` 0x50EC080 → ord1 → OEP 0x403E70), 99 B no residentes en disco, retry-loop en 0x403ED3+,",
    "> y propuestas en evaluación (DLL AppKeyX falsa; desempaquetar contabilidad_i.bin).",
]

body = [
    "## 14. Anexo — análisis estático 2026-09-03: el gate (entry .appkey → AppKeyX ord1 → OEP 0x403E70)",
    "",
    "### 14.1 Reconciliación de direcciones (ord1 de AppKeyX.dll)",
    "- Tabla de exports real de AppKeyX.dll (7826 exports, base 1, parseo con `ak_ord1.py`): **ord1 = RVA 0x158C4 →",
    "  runtime 0x5E058C4** (base 0x5DF0000). La bala (b) de §13.8 ya daba por correcto `0x5E058C4`; la memoria privada",
    "  anotaba `0x5DF58C4` (erróneo) → **corregido en `debuggerjpp-mcp.md` el 2026-09-03**.",
    "- `ak_ord1.py` corrige además el fallback de parseo ILT→FirstThunk (dumps de imports previos con direcciones falsas).",
    "",
    "### 14.2 Mecanismo del gate (hallazgo central de la fase)",
    "- Entry del exe: **RVA 0x50EC080** (sección `.appkey`; fileoff 0x4DF1C80) = thunk de 14 B:",
    "  `push eax; mov [esp],0x403E70; jmp [0x54EC014]`. El slot IAT **0x54EC014** resuelve a **AppKeyX.ord1**.",
    "- Es decir: **0x403E70 se usa como return address de ord1**. Si la licencia es válida, ord1 puebla los 99 B",
    "  (0x403E70..0x403ED2) y su `ret` cae en el OEP real; si falla, el `ret` cae en los 99 `int3` → pausa first-chance",
    "  0x403E71 → exit 0x4000001F.",
    "- Explica a posteriori: (a) los **0 hits** del DR0 write-hwbp (en fallo NADIE escribe los 99 B); (b) por qué el",
    "  parche jmp→0x403ED3 solo ganó ~3.5 s; (c) la pila \"leaf\" sin frames de AppKeyX (0x403E70 entró como dirección",
    "  de retorno, no como call).",
    "- Única referencia al dword 0x403E70 en todo el exe: `.appkey`+0x84 (dentro del thunk). Sin literales",
    "  0x403E70/0x403E71/0x403ED3 en AppKeyX.dll.",
    "",
    "### 14.3 ord1 = dispatcher de init (y qué importa la DLL)",
    "- ord1 (RVA 0x158C4): si byte [RVA 0x45FFF0]==0 → call **0x1561C** (el validador real; 168 insns; ret en 0x15846)",
    "  y pone el flag a 1; luego `ret`. SEH: handler 0x15901→0x3D04.",
    "- Imports de AppKeyX.dll: kernel32 (VirtualProtect/VirtualQuery/VirtualAlloc/LocalAlloc/CreateFileA/ReadFile/",
    "  WriteFile/SetFilePointer/MapViewOfFile/CreateFileMappingA/GetProcAddress/LoadLibraryExA/CreateProcessA/",
    "  GetLocalTime/GetDateFormatA/GetDiskFreeSpaceA/GetVersionExA/IsDebuggerPresent/ExitProcess…), advapi32",
    "  (RegOpenKeyExA/RegQueryValueExA/RegCloseKey), user32, oleaut32 (SafeArray*/Variant*).",
    "- **Sin call-sites `call/jmp [IAT]` directos en el CODE de AppKeyX** → las APIs se invocan indirectamente",
    "  (GetProcAddress dinámico / wrappers VM). `ak_iat.py` mapeó los slots IAT runtime (p. ej. RegQueryValueExA 0x5E8519C).",
    "",
    "### 14.4 Los 99 B NO existen en claro en ningún binario accesible",
    "- La secuencia contigua post-bloque (`90 55 E8 D6 E0 FF FF E9 94 00 00 00 90`; fileoff 0x32D3 = RVA 0x403ED3)",
    "  solo está en el propio exe; ausente en AppKeyX.dll, cti.exe (== contabilidad_i.bin), contabilidad_i.mgr,",
    "  AppKey21.dll y AppKeyRT.dll.",
    "- Hay una sola copia del exe en todo el disco (`C:\\Program Files (x86)\\Compac\\Contabilidad\\`); AppKeyX.dll es",
    "  byte-idéntica en Contabilidad/Bancos/\"Descarga de CFDI\"/Servidor (en Bancos/AdminPAQSDK existe una variante de",
    "  389 KB).",
    "- Conclusión: los 99 B se **entregan/descifran en runtime** (datos criptográficos de los servicios AppKey locales),",
    "  NO se recuperan por copia de un binario hermano; quien valida es quien los escribe en memoria.",
    "",
    "### 14.5 Código real desde 0x403ED3 (por qué el parche de §13.4 no basta)",
    "- Desde fileoff 0x32D3 hay código real pero **asume el estado restaurado**: incluye un retry-loop que re-cae en la",
    "  zona CC (0x3ED4 `call 0x1FB0`; 0x3EE0…; 0x3F09–0x3F2E con `call 0x12F0` (push 0x3F/0x2A), `call 0x2350`,",
    "  `jne 0x3ED4`; branches a 0x3F70…; calls a 0x233F048/0x233F078 = RVAs altos, dispatch de tabla).",
    "- El parche \"rellenar el bloque + saltar a 0x403ED3\" (variantes a/b, §13.4) ganó ~3.5 s y luego el flujo vuelve a",
    "  caer en bytes CC / el verificador mata el proceso (exit 0x4000001F).",
    "- Implicación: para correr hace falta el **estado completo** (99 B restaurados + las condiciones que el retry-loop",
    "  espera), no solo un salto.",
    "",
    "### 14.6 contabilidad_i.bin / cti.exe — \"el .bin es un .exe renombrado\" (confirmado)",
    "- Confirmación del usuario (2026-09-03): contabilidad_i.bin es un .exe renombrado. Verificado en la fase:",
    "  **contabilidad_i.bin == cti.exe byte-idénticos** (md5 dd5d7319…, 6 137 240 B), PE32 con entry RVA 0x5C9B80 y",
    "  secciones CODE/DATA/BSS/.idata/.tls/.rdata/.reloc/.rsrc → **otro programa**, no la app principal.",
    "- En el mismo fileoff 0x3270 donde el exe tiene el bloque CC, cti/bin tiene código real distinto (sin CC) → **no",
    "  sirve como plantilla** de los 99 B ni como \"exe desempaquetado\".",
    "- Objetivo intermedio del usuario: sondear si está empaquetado y qué es (resultado en §14.8).",
    "",
    "### 14.7 Propuestas en evaluación (2026-09-03) — decisión pendiente",
    "- (1) **Parche del thunk + prólogo neutro** (relleno del bloque CC) en memoria o copia de instalación. Límite",
    "  conocido: retry-loop/verificador (§14.5).",
    "- (2) **Retroceder el reloj de Windows** a ~2025-11-01 (NTP off) para capturar los 99 B de un run que validó OK.",
    "  Requiere autorización explícita.",
    "- (3) **Bajar un nivel en el árbol de 0x1561C** (rama validar→restaurar y origen de los bytes). Herramientas listas:",
    "  `ak3_lib.py`/`ak3_ctree.py`; mapas `o_tree1561c.txt`/`o_tree158c4.txt`. Costoso en turnos.",
    "- (4) **Nueva idea del usuario: reescribir AppKeyX.dll** (mismas funciones, respuesta \"llave válida\"). Análisis:",
    "  - El gate depende de ord1; una DLL falsa cuyo ord1 \"valide\" **no conoce los 99 B** (no están en disco, §14.4): su",
    "    `ret` caería igual en `int3` salvo que ella escriba el bloque; escribir un trampolín equivale al parche en",
    "    memoria de §13.4 con el mismo techo (~3.5 s, §14.5).",
    "  - Riesgos extra: (a) el exe podría importar más ordinals de AppKeyX o resolverlos por GetProcAddress en runtime",
    "    (no verificado); (b) AppKeyX.dll es compartida byte-idéntica por ≥4 productos → reemplazarla en disco afecta a",
    "    todo el equipo y puede saltar chequeos de integridad/actualizador CONTPAQ; (c) posibles chequeos estilo CrypKey",
    "    (desconocidos); (d) parchear la DLL en disco **no está autorizado** (a lo sumo prueba sobre una copia de la",
    "    instalación).",
    "  - Conclusión: no supera el techo actual sin resolver antes **de dónde salen los 99 B** (opción 3) o sin un run",
    "    que valide OK (opción 2).",
    "- (5) Objetivo intermedio en curso (hoy): sonda read-only de contabilidad_i.bin → §14.8.",
    "- Estado al documentar: registro restaurado al original (sufijo `20251024103558302`), servicios AppKey Running,",
    "  binarios intactos, target MCP `exited` (requiere `restart`).",
    "",
]

text2 = text.replace(HDR_ANCHOR, HDR_ANCHOR + CRLF + CRLF.join(header_add), 1)
text2 = text2.rstrip("\r\n") + CRLF + CRLF + CRLF.join(body) + CRLF

out = text2.encode("utf-8")
assert not out.startswith(b"\xef\xbb\xbf")
tmp = PATH + ".tmp"
with open(tmp, "wb") as f:
    f.write(out)
os.replace(tmp, PATH)

# verification
with open(PATH, "rb") as f:
    v = f.read().decode("utf-8")
print("OK nuevo tamano:", len(v))
print("OK lineas CRLF:", v.count("\r\n"))
print("OK no-CR lines:", v.replace("\r\n", "").count("\n"))
print("OK ancla 14.7 presente:", "### 14.7 Propuestas en evaluación" in v)
print("OK fin:", repr(v[-80:]))

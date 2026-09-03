# Tools Python de análisis — artefactos para DebuggerJ++

Copiadas el 2026-09-03 desde la carpeta de sesión del agente (investigación CONTPAQ i:
búsqueda del original de los 99 B del OEP 0x403E70 y desensamblado estático de la ruta
ord1 de AppKeyX.dll). **Copia fiel** — solo lectura sobre los binarios objetivo; ninguna
modifica el software analizado.

- **67 scripts**, ~290 KB en total.
- Grupos: **A** análisis estático (disco) · **B** drivers dinámicos sobre el MCP del
  debugger · **C** utilidades de mantenimiento de la bitácora (no reutilizables).

## Requisitos

| Dependencia | Ámbito |
|---|---|
| Python 3 (solo stdlib) | mayoría del grupo A y todo el C |
| `capstone` (x86, `CS_MODE_32`) | 13 scripts marcados **[capstone]** (+ `ak3_ctree.py` por importar `ak3_lib`) |
| DebuggerJ++ con MCP activo en Windows (8377/8378), helper `dbg.mjs` y token de sesión | grupo B (ver `mcp/README.md` y `debuggerjpp-mcp.md`) |

Instalación del requisito único: `pip install capstone` (o usar `tools/python-embed` del repo).

## Convención de rutas (importante)

Los scripts de análisis del grupo A fijan **rutas WSL** (`/mnt/c/...`) hardcodeadas, porque se
crearon y ejecutaron desde WSL contra la instalación `C:\Program Files (x86)\Compac`. Para
ejecutarlos desde Windows (p. ej. con `tools/python-embed`) hay que **sustituir el prefijo
`/mnt/c/` por `C:\`** en el propio script o parametrizar la ruta. Los scripts de propósito
genérico (`peinfo.py`, `exports.py`, `ex_scan.py`, `akdis.py`, `dump_range.py`, `ak_iat.py`,
`ak_trace.py`, `head_of_rva.py`, `chain_up.py`, `xref_call.py`, `ak3_*`) aceptan RVAs/args y
son los más portables; el resto apuntan a la instalación CONTPAQ concreta.

Todas las direcciones son **RVAs** salvo que se indique "VA" o "absoluto".

---

## Grupo A — Análisis estático de binarios (read-only, disco)

### A.1 PE genérico (portables)

| Script | Qué hace | Uso |
|---|---|---|
| `peinfo.py` | Parsea un PE32: cabecera, secciones (RVA/raw offset/tamaños), entry point; extrae strings ASCII/UTF-16 por sección filtrando por palabras clave. | `peinfo.py <archivo> [--strings-words "licencia,key"] [--strings-min 5] [--section .rdata]` |
| `exports.py` | Resuelve direcciones **absolutas** de funciones exportadas: RVA de exportación + base del módulo = VA en el proceso. | `exports.py <dll-path> <module-base-hex> [func1 func2 ...]` — sin funcs lista todas. Ej.: `exports.py "C:/Windows/SysWOW64/user32.dll" 0x75980000 MessageBoxA` |
| `ex_scan.py` | Estructura de un exe + localización del bloque CC + refs al validador. | `ex_scan.py secs <archivo>` · `dump <archivo> <off-hex> <n>` · `rva2off <archivo> <rva-hex>` · `ccregion` (dump comparativo de fileoff 0x3270..0x3340 en exe/cti/.bin/.dat/.mgr) · `find <archivo> <hexbytes> [max]` |

### A.2 AppKeyX.dll / contabilidad_i.exe (instalación CONTPAQ i)

| Script | Qué hace | Uso |
|---|---|---|
| `scan_oep.py` | Verifica los 4 exes `.appkey`: localiza el bloque CC del OEP (99 B en fileoff 0x3270) y los EP por sección. | `scan_oep.py` (sin args; rutas fijas) |
| `stub_dis.py` | Desensambla la sección `.appkey` del exe (stub validador: push OEP + jmp a AppKeyX ord1); imprime primeras 40 insns y filtrado de call/jcc/int3/ret + refs. | `stub_dis.py <rva-hex> [nins]` **[capstone]** |
| `akdis.py` | Disassembler offline de AppKeyX.dll con capstone. | `akdis.py <rva-hex> [count]` · `--fns <rva-hex> [depth]` (recursivo) · `--scan <text>` (anti-debug: fs:[0x30], int 2d, rdtsc…) · `--xrefs <rva-hex>` · `--str <rva-hex>` **[capstone]** |
| `akscan.py` | Escanea CODE de AppKeyX buscando primitivas anti-debug: pushfd/popfd (TF), int 1/3, rdtsc, cpuid, fs:[0x30]/fs:[0x18], sldt, str. | `akscan.py [patron1 patron2 ...]` — patrones: `tf, int1, int3, rdtsc, cpuid, peb, teb, sldt` **[capstone]** |
| `ak_ord1.py` | Reconciliación del export ordinal 1: lee la tabla de exports real y resuelve ordinal → RVA → VA (con imagebase PE 0x400000 y con base runtime 0x5DF0000). | `ak_ord1.py [1 2 0 ...]` (ordinales a resolver; defecto 1 2 0) |
| `ak_iat.py` | Mapea slots IAT de AppKeyX y busca sus call-sites FF15/FF25 en CODE. | `ak_iat.py [func1 func2 ...]` — con funciones imprime slot (RVA/VA) y refs; sin args, mapa completo |
| `ak_trace.py` | Helpers de análisis estático. | `refs <dword-hex>` (ocurrencias del dword LE → RVA/sección) · `skel <rva-hex> [nins]` (esqueleto del flujo lineal) · `bytes <rva-hex> <n>` **[capstone]** |
| `disasm_akx2.py` | **Toolbox principal** read-only de AppKeyX.dll (parsing PE + sweep capstone). | `iat` (dump imports .idata: slot RVA/VA + tabla de thunks 0x6454–0x6634) · `sites [api...]` (sweep de CODE: call/jmp [IAT] y a thunk; mapa por API con RVA del call-site y función contenedora) · `reach` (grafo de calls intra-CODE desde export#1 0x158C4 y 0x1561C/0x136B8) · `funcs <rva-hex>...` (desensamblado completo de funciones) · `xrefs <rva-hex>...` · `strdump <rva-hex>...` · `str <texto>` (busca strings) · `mz` (scan MZ/PE00 por secciones) **[capstone]** |
| `dump_range.py` | Desensamblado lineal de un rango RVA[ini..fin] sin cortar en `ret`. | `dump_range.py <rva-ini-hex> <rva-fin-hex>` **[capstone]** |
| `scan_slots.py` | Scan **byte-level alignment-free** de referencias en CODE a los slots IAT (operando imm32 LE) con realineo del opcode (FF15/FF25/A1/8B). | `scan_slots.py` (sin args) |
| `scan_rel.py` | Mapa definitivo de llamadores: localiza todos los stubs `ff 25 <slot>` (ambas tablas), escanea CODE por E8/E9 rel32 hacia stubs y FF15 directos; por API: caller RVA + función contenedora. | `scan_rel.py` (sin args) |
| `find_callers.py` | Importa `disasm_akx2` y reporta los callers de stubs/APIs sensibles con su función contenedora. | `find_callers.py` (sin args) **[capstone]** |
| `xref_call.py` | Busca callers `E8 rel32` (byte-level) hacia una lista de RVAs objetivo dentro de CODE. | `xref_call.py 0x13F40 [0x...]` |
| `head_of_rva.py` | Escanea hacia atrás desde un RVA buscando prólogo típico (`55 8B EC` / `53..` / `56..` / `push ebp`) y reporta cabezas candidatas. | `head_of_rva.py 0x14252` |
| `chain_up.py` | Desde un RVA remonta la cadena de llamadas: prólogo previo → callers → prólogo del caller… hasta agotar. | `chain_up.py 0x14908` |
| `ak3_lib.py` | Librería común de parseo PE + desensamblado lineal (capstone) para AppKeyX/exe; reutilizada por `ak3_*`. | importar (`from ak3_lib import PE, DLL, disasm, rel_target`) **[capstone]** |
| `ak3_ctree.py` | Árbol de llamadas recursivo sobre AppKeyX.dll. | `ak3_ctree.py tree <rva-hex> [depth]` · `fn <rva-hex>` (análisis detallado) · `stats` (histograma de funciones) |

### A.3 Componentes hermanos: cti.exe / .bin / .mgr / servidores / .dat

| Script | Qué hace | Uso |
|---|---|---|
| `ak_bin_probe.py` | Sonda read-only de contabilidad_i.bin == cti.exe: identidad (md5/size), empaquetado (entropía por sección, bytes del EP, firmas), imports (DLLs), dirs (rsrc/reloc/tls) y contenido de fileoff 0x3270 vs bloque CC del exe. | `ak_bin_probe.py` (sin args) **[capstone]** |
| `cti_probe.py` | Sonda read-only de cti.exe: PE+imports; strings AppKey/ClientDll/vcltest3/application_name (ASCII y UTF-16LE) con offset/RVA/VA/sección; xrefs (dword LE = VA) y ventanas desensambladas en cada ref de cadenas clave. | `cti_probe.py` (sin args) **[capstone]** |
| `cti_scan2.py` | v2 fase opción 1: strings de APIs (WriteProcessMemory/OpenProcess/…) y tokens AppKeyX en cti.exe; dumps de 0x451360/0x44E0D0/0x9C9C08; disasm de los cargadores 0x511B8/0xDCFC/0x4E348 y callers. | `cti_scan2.py` (sin args) **[capstone]** |
| `cti_scan3.py` | v3: dumps corregidos de cadenas hermanas; disasm de helpers candidatos (thunks/wrappers) y call-sites + bootstrap EP; xrefs por call relativo (E8/E9) hacia cargadores/helpers; scan de tokens de protocolo IPC. | `cti_scan3.py` (sin args) **[capstone]** |
| `cti_scan4.py` | Remate opción 1: disasm de 0x51148/0x50EF8 (resolución de módulo), 0x50C94/0x50D4C (expand $(EXE)), métodos del objeto EP 0x4E748/0x4E760/0x4E7E0/0x2E38; dumps de 0x9C9970/0x4513D4/0x451420. | `cti_scan4.py` (sin args) **[capstone]** |
| `cti_iat.py` | Resuelve slots IAT de cti.exe (thunks `jmp [VA]`) a nombres de API y vuelca strings ASCII en VAs concretos. | `cti_iat.py` (sin args) |
| `mgr_probe.py` | Sonda read-only de contabilidad_i.mgr (PE renombrado) + cabeceras PE embebidas en .dtx/.dat (¿validador/servicio?). | `mgr_probe.py` (sin args) |
| `svr_probe.py` | Sonda read-only de AppKeyAuthServer.exe / AppKeyLicenseServer.exe (¿el validador que escribe los 99 B está en el servidor local?). | `svr_probe.py` (sin args) |

### A.4 Entropía, diffs y búsqueda de blob (comparativas de producto)

| Script | Qué hace | Uso |
|---|---|---|
| `ent_appkeyx.py` | Entropía de Shannon por sección de las 2 copias de AppKeyX.dll (Contabilidad/Servidor) + SHA256; detecta zonas de alta entropía (blob cifrado/empaquetado). | `ent_appkeyx.py` (sin args) |
| `sweep_entropy.py` | Barrido de entropía por ventanas (multi-fichero: exe/.dat/.bin/…) para localizar blobs criptográficos enterrados. | `sweep_entropy.py` (sin args) |
| `diff_fast.py` | Diff byte a byte Contabilidad vs Bancos **por bloques de 4 KB** (los 84 MB×2 no se comparan byte a byte en python puro); % de bytes distintos y top de secciones. | `diff_fast.py` (sin args) |
| `diff_rdata.py` | Variante de diff que separa el análisis por sección (énfasis en `.rdata` y datos) entre Contabilidad y Bancos. | `diff_rdata.py` (sin args) |
| `locate_blob.py` | Búsqueda del original de los 99 B: compara por secciones Contabilidad↔Bancos y reporta regiones candidatas (ventanas de alta divergencia/entropía). | `locate_blob.py` (sin args) |
| `locate_blob2.py` | v2 de la búsqueda (barrido por bloques con umbrales). Resultado: 96,42 % de bytes distintos → sin blob común (ver §17.7). | `locate_blob2.py` (sin args) |
| `check_bin99.py` | Para cada pareja (.bin/.exe y .exe hermano) verifica si el bloque fileoff 0x3270 (99 B del OEP) coincide o está a CC en ambos. | `check_bin99.py` (sin args) |
| `check88.py` | Compara el artefacto `C:\902B2E65508C6.EE7` (88 B): imprime tamaño/cabecera y busca su SIG16 (primeros 16 B) dentro de los candidatos listados (exe/.bin/AppKeyX/servidores). | `check88.py` (sin args) |
| `check88b.py` | Variante de barrido: SIG16 del `.EE7` + conteo de CC en 0x3270+99 recorriendo **todo** el árbol `C:\Program Files (x86)\Compac`. | `check88b.py` (sin args) |

---

## Grupo B — Drivers dinámicos sobre DebuggerJ++ MCP (runtime)

Ejecutan al debugger en Windows vía `node dbg.mjs` (protocolo TCP JSON-lines, token de
sesión). Útiles para **automatizar regímenes de ejecución** del binario analizado. Cada uno
trae su propia estrategia de polling para esquivar el auto-resume del server (~1–2 s tras
pausa por hwbp). Los nombres de addresses se refieren al objetivo contabilidad_i.exe
(entry 0x54EC080, trampa 0x403E70) y a AppKeyX.dll (base runtime 0x5DF0000).

| Script | Qué hace | Uso |
|---|---|---|
| `dbg_run.py` | Orquesta el debugger con go hasta condición: entrada (EIP==entry) o dirección concreta; modo observe (go + status/regs repetidos). | `dbg_run.py go_until_entry` · `go_until <hex>` · `observe <n>` |
| `trace_entry.py` | Lanza (si hace falta) y traza paso a paso desde el entry 0x54EC080. | `trace_entry.py <nsteps>` |
| `trace_step.py` | Trace paso a paso genérico del proceso depurado. | `trace_step.py <nsteps> [addr_stop]` |
| `trace_death.py` | Captura el run-trace desde el entry hasta la muerte del proceso. | `trace_death.py [tail_n]` |
| `exit_catch.py` | Caza el punto exacto de muerte: hwb en choke-points de salida; al disparar, EIP está en la API y [esp] = caller (el sitio anti-debug de AppKeyX). | `exit_catch.py` |
| `exit_catch2.py` | v2 con cadencia probada: fase A avance por loader hasta el entry (sw bp, sleeps 0.4 s); fase B go + poll rápido (0.08 s) para cazar el hwb antes del auto-resume. | `exit_catch2.py` |
| `exit_catch3.py` | Para en el primer pause post-loader y hace dump completo (regs/pila/caller/disasm) para decidir sin continuar. | `exit_catch3.py` |
| `clean_run.py` | Lanza el target SIN ningún bp/hwb: responde si el proceso muere por el mero DebugPort o por la instrumentación. | `clean_run.py` |
| `clean_run2.py` | Sin bps: atraviesa los pauses del loader; si queda vivo y pausado, lee 0x403E70 (¿OEP restaurado?) y EIP. | `clean_run2.py` |
| `obs_run.py` | Run limpio tras experimento (p. ej. renombrado de fechas en registro): ¿cambia la validación? Trampa en 0x403E70 = sigue fallando; código real = AppKeyX restauró el OEP. | `obs_run.py` |
| `trap_jump.py` | EXPERIMENTO: pausado en la trampa (0x403E71), parchea `jmp 0x403E71→0x403ED3` (salta la zona CC) y continúa para ver si la app arranca sin la restauración. | `trap_jump.py` |
| `trap_jump2.py` | Parche de trampa (0x403E70=NOP, 0x403E71=jmp 0x403ED3) + hwb de diagnóstico: DR1 EXEC (¿quién salta a 0x403E70?) y DR0 WRITE (¿quién reescribe el CC?). | `trap_jump2.py` |
| `trap_nop_b.py` | Re-run de la variante (b): bloque 99 B → `90 E9 5D 00 00 00` + 93 NOPs, con child-tracking ON (¿la recaída es remapeo de página o proceso nuevo auto-restartado?). | `trap_nop_b.py` |
| `stack_trap.py` | En la pausa de la trampa vuelca la pila: la dirección de retorno del transferidor (AppKeyX→0x403E70) y frames superiores mapean la cadena de decisión del fallo. | `stack_trap.py` |
| `chain_probe.py` | Sondas dinámicas log_only sobre los sites del modelo ak1561c (RVAs → abs = base + rva); discrimina la instancia viva de AppKeyX entre los módulos acumulados. | `chain_probe.py` |
| `chain_log.py` | Run limpio con TODAS las sondas log_only (cero pausas): registra en poll_events qué sites de la cadena se ejecutan y cuántas veces. | `chain_log.py` |
| `leafwatch.py` | Caza del escritor de los 99 B: DR0 WRITE @0x403E70 (si salta, EIP = escritor real); lee leaf_14D60 y el estado del manager; `--noleaf` = control sin bp software. | `leafwatch.py [--noleaf]` |

> ⚠️ Los drivers de este grupo **ejecutan el binario protegido** (o sus parches en memoria)
> bajo el debugger. Úsarlos requiere licencia de análisis/entorno aislado y alcance
> "Modificación" del MCP (write_mem). Los que parchean la trampa son **experimentos
> documentales** de la investigación (§13/§16), no herramientas de elusión de licencia.

---

## Grupo C — Mantenimiento de la bitácora canónica (NO reutilizables)

Appends/correcciones a `C:\Discos\contexto_debugger.md` (preservan CRLF/UTF-8 sin BOM;
validan anclas y abortan sin escribir si no cuadran; escritura tmp + `os.replace`).
**Históricos de una sola sesión — el debugger no debe ejecutarlos.**

| Script | Qué hace |
|---|---|
| `update_ctx_doc.py` | Anexo 13 + correcciones (2026-09-02 tarde). |
| `fix_doc2.py`, `fix_doc3.py` | Pases de alineado/pulido de la sección 1 y restos históricos. |
| `edit_objs.py` | Edición puntual (sección 1 + nota de actualización). |
| `upd_ctx14.py`, `upd_ctx14b.py` | Anexos §14 / §14.8 (estático 2026-09-03 + sonda .bin). |
| `upd_ctx15.py` | Anexo §15 (opción 2 remodelación 0x1561C + opción 1 cti.exe/ClientDll). |
| `upd_ctx16.py` | Anexo §16 (verificación dinámica read-only del paso 4). |
| `upd_ctx17.py` | Anexo §16.6 (experimento parche variante-b + hijo identificado). |
| `upd_ctx18.py` | Anexo §16.7 (re-análisis: "la app trae antidebugger; .bin es la clave"). |
| `upd_ctx19.py` | Anexo §16.8 (autorización del usuario + protocolo de ejecución). |
| `upd_ctx20.py` | Anexo §16.9 (cmdline del hijo capturado + decode + bootstrap .dtx). |
| `upd_ctx21.py` | Anexo §16.10 (estrategia attach .bin + flip jz/jnz/je → veredicto). |

---

## Contexto de los objetos analizados (referencia rápida)

- `C:\Program Files (x86)\Compac\Contabilidad\contabilidad_i.exe` — x86, imageBase 0x400000,
  stub `.appkey` con EP 0x50EC080; **99 B CC en fileoff 0x3270 = RVA 0x3E70 = VA 0x403E70**
  (erasure de fábrica del OEP original); código intacto desde 0x403ED3.
- `AppKeyX.dll` (Contabilidad/Servidor byte-idénticas, 647.680 B): imageBase 0x400000,
  CODE rva 0x1000/fileoff 0x400, dos tablas de stubs (LOW 0x1100–0x131A, MID 0x6454–0x6634),
  export ord1 → RVA 0x158C4, módulo interno "ClientStub.dll"; base runtime observada 0x5DF0000.
- `contabilidad_i.bin` ≡ `cti.exe` (6.137.240 B, md5 dd5d7319…): componente Delphi v25.0.0
  renombrado; es el hijo que lanza 0x1561C con el request `(ruta, pid_padre, 0)`.
- Resultado de la investigación: **no existe blob estático** del original de los 99 B; la
  restauración solo puede ocurrir en memoria vía el módulo PE que BTMemoryModule carga en
  runtime (fichero con magia 0xD7B3 / JEXP / hijo) — ver §17.7/§17.8 del canónico.

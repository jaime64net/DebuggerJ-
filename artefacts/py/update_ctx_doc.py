#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Actualiza C:\\Discos\\contexto_debugger.md con el anexo 13 y correcciones (2026-09-02 tarde).
Preserva CRLF y UTF-8. Cada ancla se valida (count == esperado) antes de sustituir."""
import sys

P = '/mnt/c/Discos/contexto_debugger.md'
NL = '\r\n'

def B(s):
    return s.strip('\n').replace('\n', NL)

t = open(P, 'rb').read().decode('utf-8')

def rep(old, new, label, expect=1):
    global t
    n = t.count(old)
    if n != expect:
        print('FALLO ancla [%s]: count=%d esperado=%d' % (label, n, expect))
        sys.exit(1)
    t = t.replace(old, new, expect)
    print('OK  [%s]' % label)

# 1) Cabecera: nueva línea de "Actualizado" tras la del anexo §12
rep('> descubrió el mecanismo del OEP borrado/restaurado por AppKeyX.' + NL,
    '> descubrió el mecanismo del OEP borrado/restaurado por AppKeyX.' + NL + B(r'''> **Actualizado el 2026-09-02 (tarde)** con el anexo §13: experimentos encargados (parche en memoria sobre la trampa y
> fecha de licencia en el registro) con la corrección empírica del bloque CC (99 B: 0x403E70..0x403ED2) y del arg de exit
> (0x4000001F en runs limpios).''') + NL,
    'cabecera')

# 2) §2: corregir bloque 0x70->99 B (líneas 42-43) y anotar ejecución
rep('el OEP original (0x403E70) está borrado en disco (0x70 bytes' + NL +
    '  de int3) y AppKeyX solo lo restaura en runtime si la validación pasa; bajo debugger no restaura → `ret` a int3 →',
    'el OEP original (0x403E70) está borrado en disco con un bloque de int3 de **99 B (0x63): `0x403E70..0x403ED2`**' + NL +
    '  (medición fina, §13.2 — no 0x70) y AppKeyX solo lo restaura en runtime si la validación pasa; bajo debugger no restaura → `ret` a int3 →',
    's2 bloque 99B')

rep('exit `0x4000001E`, sin pasar por NtTerminateProcess',
    'exit `0x4000001F` en runs limpios de la tarde (`0x4000001E` solo con exc-bp instalado), sin pasar por NtTerminateProcess',
    's2 exit')

rep('  restaurado en 0x403E70 durante un run que valide OK.',
    B(r'''  restaurado en 0x403E70 durante un run que valide OK. Ya ejecutado en la tarde (§13): la trampa persiste en 0x403E71;
  el parche en memoria alarga ~3.5 s pero el proceso re-cae; el experimento de fecha en el registro fue negativo;
  todo revertido.'''),
    's2 accion')

# 3) §2: nueva bala de corrección antes de "Ángulo malware"
rep('- **Ángulo malware**: proceso `csrss.exe` (PID 37836) impostor',
    B(r'''- **Corrección empírica de la tarde (anexo §13)**: el bloque CC mide 99 B (0x403E70..0x403ED2), no 0x70; en runs limpios
  el proceso muere con exit `0x4000001F`, no `0x4000001E`. Parche en memoria: +3.5 s de vida pero re-cae; experimento de
  fecha en el registro: sin efecto. Todo revertido.
- **Ángulo malware**: proceso `csrss.exe` (PID 37836) impostor'''),
    's2 bala correccion')

# 4) §9: nueva bala de artefactos antes de "App MCP (Windows)" (balas de §9 en columna 0)
rep('- App MCP (Windows):',
    B(r'''- (2026-09-02 tarde, experimentos del anexo §13): `trap_jump.py`, `trap_jump2.py`, `stack_trap.py`, `obs_run.py`;
  `.ps1` de registro: `ak_dump.ps1`/`ak_dump2.ps1`, `ak_dbg.ps1`, `ak_rename.ps1`/`ak_rename2.ps1`/`ak_rename3.ps1`,
  `ak_svc.ps1`.
- App MCP (Windows):'''),
    's9 artefactos')

# 5) §11: nuevo ítem 6 tras el ítem 5
rep('según la estrategia acordada con el usuario.' + NL,
    'según la estrategia acordada con el usuario.' + NL + B(r'''6. Cierre 2026-09-02 tarde: los experimentos encargados (parche en memoria / fecha en registro) ya se ejecutaron y
   quedaron revertidos (anexo §13); la elección del siguiente paso (reloj de Windows / análisis estático de AppKeyX
   ord1 / parar y documentar) está pendiente del usuario (§13.8).''') + NL,
    's11 item6')

# 6) §12.2/12.3: correcciones de medición y arg de exit
rep('0x70 bytes de **CC** (int3). `mem[0x403EE0]` = código real: `56 57 6A 00 E8 C7 E6 FF FF…` (prologue).',
    'bloque de int3 (medido después con precisión: **99 B, 0x403E70..0x403ED2**, §13.2). Código real desde `0x403ED3` (`90 55 E8 D6 E0 FF FF…`); el fragmento `56 57 6A 00 E8 C7 E6 FF FF` de 0x403EE0 cae dentro del código intacto.',
    's12.3 mem')

rep('el código real intacto desde RVA 0x3EE0 (fileoff 0x32E0).',
    'el código real intacto desde RVA 0x3ED3 (fileoff 0x32D3; medición fina posterior, §13.2).',
    's12.3 fileoff')

rep('con 0x70 bytes de int3 (ya en el archivo).',
    'con 99 bytes (0x63) de int3 (ya en el archivo; medición fina §13.2).',
    's12.3 paso1')

rep('**restaura los 0x70 bytes** y hace `ret` al OEP.',
    '**restaura los 99 bytes** y hace `ret` al OEP.',
    's12.3 paso2')

rep('muerte (exit `0x4000001E`, sin pasar por los puntos de salida).',
    'muerte (exit `0x4000001F` en runs limpios de la tarde; `0x4000001E` solo con exc-bp instalado), sin pasar por los puntos de salida.',
    's12.3 paso3')

# 7) Anexo §13 al final
sec13 = B(r'''
## 13. Anexo — experimentos encargados 2026-09-02 tarde: parche en memoria (parcial) y fecha en registro (negativo)

> Sesión 15:04–15:10 (posterior a §12 / `CONTEXTO1.txt`). Encargo del usuario: (1) parchear en memoria la trampa para
> que el proceso siga vivo y (2) experimentar con la fecha de licencia en el registro. Ambos autorizados
> explícitamente. Al cierre todo quedó **revertido** (registro original, servicios Running, binarios intactos,
> target `exited`).

### 13.1 Punto de partida
- MCP operativo en 8378; target `contabilidad_i.exe` cargado pero `exited` tras los runs previos → `restart` antes de
  cada run.
- Revisados `clean_run.py` y el esquema de `write_mem {addr, hex}` en `server.mjs` (escritura de bytes crudos,
  imageBase 0x400000).

### 13.2 Medición fina del bloque CC (corrige §12.3)
- El bloque de int3 mide exactamente **99 bytes (0x63): `0x403E70..0x403ED2`**. El código intacto arranca en
  **`0x403ED3`** (RVA 0x3ED3 / fileoff 0x32D3):
  `90 55 E8 D6 E0 FF FF E9 94 00 00 00 90 56 57 6A 00 E8 C7 E6 FF FF 8B 44 24 18 83 C0 01 50 E8 EA E0 FF FF 8B E8…`
- El fragmento `56 57 6A 00 E8 C7 E6 FF FF` que §12.3 citaba en 0x403EE0 existe: cae dentro del código real (offset
  0xD desde 0x403ED3); por eso la lectura previa "código desde 0x403EE0" era correcta pero incompleta (omitía los
  primeros 0xD bytes del prologue real, que empieza `90 55 E8 D6 E0 FF FF`).
- Archivo == memoria, sin descifrado en runtime. El flujo sigue 0x403ED3 → … → 0x403F73.
- Antes se asumía un bloque de 0x70 B (112) con código desde 0x403EE0 → **corregido por medición** (99 B reales).

### 13.3 La trampa de "licencia no válida" (confirmada SIN instrumentación)
- Run limpio (sin bps ni hwb): pausa first-chance en **0x403E71** ~0.2–1.4 s después del `go` final; **ESP constante
  = 0x18FF78** en todas las pausas.
- Volcado de pila (0xF0 B, `stack_trap.py`): solo frames de arranque — `[esp]=0x76275D49` (kernel32+0x15D49: retorno
  del call al entry), `0x76275D30` (BaseThreadInitThunk), `0x77C4E12B`/`0x77C624D0`/`0x77C4E0B1` (ntdll),
  `[0x18FFF4]=0x054EC080` (entry) → AppKeyX transfiere a 0x403E70 como jmp/ret "leaf": sin frames propios en la pila.
- **4 hilos** ya presentes a ~1.4 s (posible hilo vigilante/auto-restart).
- Muerte posterior: **arg de exit `0x4000001F` (1073741855)**, precedida de events `breakpoint` en `0x77CF87F8` y
  `breakpoint` en **`0x403E70`** justo antes → patrón consistente con auto-restart (server u otro hilo) o con un
  verificador que mata el proceso.
- Nota: §6/§12 reportan exit `0x4000001E` en runs instrumentados con exc-bp; los runs de la tarde (limpios o
  parcheados) murieron con `0x4000001F`. Diferencia anotada; no resuelto si es vector distinto o efecto de la
  instrumentación.

### 13.4 Parche de la trampa en memoria (autorizado) — PARCIAL / negativo
- Variante (a) `trap_jump.py`: `write_mem` con jmp en 0x403E71 → 0x403ED3 (98 B parcheados).
- Variante (b): `90 E9 5D 00 00 00` en 0x403E70 + NOPs hasta 0x403ED3 (99 B, bloque completo).
- Resultado en ambas: el proceso **vive ~3.5 s más** (events `load_dll` de inicialización real) pero **re-cae en
  0x403E70** → exit `0x4000001F` (~4.2–5.0 s desde el `go`).
- DR0 **write-hwbp** (type=1, len=1) en 0x403E70: armó OK y dio **0 hits** → nadie reescribe el CC instrucción a
  instrucción; la recaída = re-mapeo de página o **proceso nuevo** (auto-restart).
- **Exec-hwbp** (type=0) en 0x403E70: **no arma** (`ok:false`) — quirk del server.
- Hipótesis dominante: **chequeo de integridad del área** (bytes en memoria ≠ disco → mata). Parchear en memoria sin
  neutralizar al verificador no tiene salida → vías restantes: lograr que la validación pase (reloj/activación) o
  análisis estático de la rama validar→restaurar en AppKeyX.

### 13.5 Experimento "fecha de licencia en el registro" — NEGATIVO (revertido)
- La única fecha en el registro es el **sufijo de 17 dígitos (yyyyMMddHHmmssfff) en los NOMBRES** de los 4 valores de
  `HKLM\SOFTWARE\WOW6432Node\Computación en Acción, SA CV\AppKey\Contpaq_i\Temp`:
  `Serial-20251024103558302`, `SerialKey-*`, `SiteCode-*`, `ActivationKey-*`
  (**valores literales NO reproducidos en este doc**; releer con `reg_lic*.ps1` / `ak_dbg.ps1`).
- Procedimiento: renombrados los 4 a sufijo `20260902150401306` (datos intactos; la escritura HKLM **no elevada fue
  permitida por ACL**) + `Restart-Service` (elevado vía UAC) de `AppkeyAuthServer_Compac_V4` y
  `AppKeyLicenseServer_Compac_V4` → ambos quedaron Running.
- Verificación (`obs_run.py`, run limpio; auto-pausa + lectura de 0x403E70 si el proceso pasa de running >8 s):
  **la trampa sigue idéntica** (pausa en 0x403E71, esp 0x18FF78, 99 CC) → la validación NO cambió; el server **no
  reescribió** los valores (comprobado tras el run).
- **Revertido** manualmente al sufijo original `20251024103558302` (verificado).
- Conclusión: la fecha efectiva no vive en el sufijo del nombre; vive en los datos criptográficos de los valores o en
  el **estado interno del servidor** (archivos `.dtz` de 6–10 MB de AppKeyLicenseServer/AppKeyAuthServer). El log
  `AppKeyLicenseServer.log` (24 KB) está **cifrado** (ilegible); `CrypKeyDLL.dll` = vendor comercial de licencias.
- Mapa ampliado del registro (dumps `ak_dump.ps1`/`ak_dump2.ps1`): bajo `…\Computación en Acción, SA CV` →
  `AppKey\{Contpaq_i\Temp (licencia), Logs}` + `CONTPAQ i\18.4.1` (config, sin fechas) + productos hermanos
  (p. ej. Bancos, con cadenas de URL de servicio en sus valores).

### 13.6 Quirks PowerShell nuevos (suman a §4/§8)
- `(pipeline)[0]` con UN solo resultado indexa el **primer carácter** (PowerShell desenrolla el string) → envolver en `@()`.
- El proceso elevado por UAC falló enumerando subárboles con acentos (`Computación en Acción`) por redirección/vista →
  usar `[Microsoft.Win32.RegistryKey]::OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64)`.
- Escritura de valores bajo `HKLM\SOFTWARE\WOW6432Node\…\Temp` permitida **sin elevación** (ACL del valor).

### 13.7 Artefactos nuevos (memory/)
- `trap_jump.py` (variantes a/b del parche), `trap_jump2.py` (parche + DR0 write-hwbp + intento de exec-hwbp),
  `stack_trap.py` (dump de pila 0xF0 B + hilos en la trampa), `obs_run.py` (run limpio de observación con auto-pausa y
  lectura de 0x403E70).
- `.ps1`: `ak_dump.ps1`/`ak_dump2.ps1` (dump del árbol de registro), `ak_dbg.ps1` (localización/lectura/escritura de la
  clave Temp vía Registry64), `ak_rename.ps1`/`ak_rename2.ps1`/`ak_rename3.ps1` (renombrado del sufijo de 17 dígitos;
  versión final con `@()` + `\d{17}`), `ak_svc.ps1` (restart elevado de los servicios AppKey).
- Memoria privada `debuggerjpp-mcp.md` reescrita con esta sesión y con la bala del mecanismo corregida (99 B /
  0x403ED3 / exit 0x4000001F) para mantener coherencia con estos hallazgos.

### 13.8 Estado al cierre y siguientes pasos (decisión pendiente del usuario)
- Registro restaurado al estado original (sufijo `20251024103558302`); servicios AppKey Running; binarios intactos
  (los parches solo vivieron en memoria de procesos ya muertos); target `exited` (requiere `restart`).
- Opciones en mesa (elegir una): (a) **retroceder el reloj de Windows** a ~2025-11-01 (NTP off) para que la validación
  pase y AppKeyX restaure los 99 B → captura del OEP desde un run que validó OK (requiere autorización explícita);
  (b) análisis estático de AppKeyX ord1 (conciliar `0x5E058C4` [doc] vs `0x5DF58C4` [anotación en memoria privada])
  buscando la rama validar→restaurar y qué datos lee; (c) parar y documentar.
- Pendientes heredados sin cambios: redocumentar el MCP (§11.1), ruta real del "csrss" 37836 (§11.3), revisar la
  salida completa de `akscan.py` (§11.4).
''')

if not t.endswith(NL):
    t += NL
t += NL + sec13 + NL

# Verificación final
assert t.count('## 13. Anexo') == 1, 'anexo 13 duplicado'
open(P, 'wb').write(t.encode('utf-8'))
print('OK  [escritura final]')

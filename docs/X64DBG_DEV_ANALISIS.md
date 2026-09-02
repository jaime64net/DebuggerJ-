# x64dbg para developers — análisis y propuesta para DebuggerJ++

Documento de referencia: qué ofrece x64dbg a los desarrolladores de plugins/scripts, y
cómo **replicarlo y mejorarlo** en DebuggerJ++ (Dear ImGui + Zydis + Windows Debug API,
con servidor MCP/JSON por TCP, panel de IA con tool-calling, y `PluginManager` JSON/DLL).

Fuentes: `help.x64dbg.com/en/latest/developers/` (plugins, callbacks, bridge, funciones
`Dbg*`/`Gui*`), `commands/`, `commands/script/`, `Expression-functions`.

---

## 1. Cómo se extiende x64dbg (4 vías)

1. **Scripts nativos** — lenguaje propio, línea a línea, desde la ventana Script o el prompt.
2. **`scriptdll` / `dllscript`** — un script empaquetado como DLL.
3. **Lenguajes aportados por plugins** — un plugin registra un intérprete completo (`GuiRegisterScriptLanguage`).
4. **Plugins nativos** — DLL con SDK C/C++ (lo más potente).

Arquitectura: **GUI (Qt)** ↔ **motor DBG**, comunicados por un **bridge**. Todo string es **UTF-8**.

## 2. Plugins nativos (SDK C/C++)

**Ciclo de vida (exports con nombre fijo):**
- `bool pluginit(PLUG_INITSTRUCT*)` — obligatorio; registra comandos, callbacks y funciones de expresión.
- `void plugsetup(PLUG_SETUPSTRUCT*)` — único sitio válido para crear **menús** (ya hay handles de GUI).
- `bool plugstop()` — desregistra todo y libera.

**Estructuras:** `PLUG_INITSTRUCT` (`pluginHandle`, `sdkVersion`, `pluginVersion`, `pluginName`),
`PLUG_SETUPSTRUCT` (`hwndDlg`, `hMenu`, `hMenuDisasm`, `hMenuDump`, `hMenuStack`).

**API `_plugin_*` que el plugin llama:**
- Comandos: `_plugin_registercommand` / `_plugin_unregistercommand` (callback `CBPLUGINCOMMAND(int argc, char** argv)->bool`).
- Callbacks: `_plugin_registercallback` / `_plugin_unregistercallback`.
- Expresiones: `_plugin_registerexprfunction(ex)` (devuelven número) y `_plugin_registerformatfunction` (para `{...}`).
- Menús: `_plugin_menuadd`, `_plugin_menuaddentry`, `_plugin_menuaddseparator`, `_plugin_menuseticon`, `_plugin_menuentrysetchecked`.
- Log/control: `_plugin_logprintf`, `_plugin_logputs`, `_plugin_debugpause`, `_plugin_waituntilpaused`, `_plugin_startscript`.

**Eventos `CB_*` (24):** `INITDEBUG`, `STOPDEBUG`, `CREATEPROCESS`, `EXITPROCESS`,
`CREATETHREAD`, `EXITTHREAD`, `SYSTEMBREAKPOINT`, `LOADDLL`, `UNLOADDLL`,
`OUTPUTDEBUGSTRING`, `EXCEPTION`, `BREAKPOINT`, `PAUSEDEBUG`, `RESUMEDEBUG`, `STEPPED`,
`ATTACH`, `DETACH`, `DEBUGEVENT`, `MENUENTRY`, `WINEVENT`, `WINEVENTGLOBAL`, `LOADSAVEDB`,
`FILTERSYMBOL`, `TRACEEXECUTE`. Firma `void CB(CBTYPE, void* info)`; `info` nunca NULL pero
sus miembros sí. **Regla de oro: nada pesado dentro de un callback; exporta solo los que uses.**

## 3. Bridge y familias de API

- `Bridge*` — interno (memoria que cruza el bridge `BridgeAlloc/Free`, settings `ini` `BridgeSetting*`). No se llama desde terceros.
- **`Dbg*`** (motor) y **`Gui*`** (interfaz) — lo que sí usan los plugins.

**`Dbg*` clave:** `DbgCmdExec` (async) / `DbgCmdExecDirect` (sync con resultado);
`DbgMemRead/Write/Map/IsValidReadPtr`; `DbgGetRegDump`; **`DbgValFromString`** (evalúa
expresión→valor, núcleo del motor de expresiones); `DbgIsValidExpression`;
`DbgDisasmAt/DbgDisasmFastAt/DbgAssembleAt`; `DbgGetBpList`; anotaciones
`DbgSet/GetCommentAt`, `DbgSet/GetLabelAt`, `DbgSet/GetBookmarkAt`.

**`Gui*` clave:** `GuiAddLogMessage(Html)`; `GuiDisasmAt`, `GuiDumpAt`, `GuiUpdateAllViews`,
`GuiFocusView`; **`GuiExecuteOnGuiThread(Ex)`** (marshalling al hilo de UI);
**`GuiReference*`** (tabla de resultados: `Initialize/AddColumn/SetRowCount/SetCellContent`);
**`GuiAddQWidgetTab`** (widget propio del plugin); scripting `GuiRegisterScriptLanguage`,
`GuiScriptAdd/SetIp/Error/Message`.

## 4. Comandos, scripting y expresiones

- **Comandos:** `cmd arg1, arg2` (coma separa args; `;` separa comandos; **hex por defecto**;
  `{expr}` interpola dentro de comillas). Todo en x64dbg es un comando de texto con un
  único intérprete compartido por GUI, scripts, plugins y prompt.
- **Scripting:** labels + saltos `Jxx/IFxx` (por flags de comparación), variables `$i`,
  `scriptload/run/exec`, `msg/msgyn/log`, `scriptdll`.
- **Expresiones:** `categoria.funcion(args)` — `byte(a)`, `dword(a)`, `ptr(a)`, `mod.base(a)`,
  `mod.fromname("ntdll.dll")`, `dis.len(a)`, `dis.mnemonic(a)`, `strlen(s)`, `utf8(a[,n])`.

---

## 5. Propuesta de implementación para DebuggerJ++

La lección de arquitectura de x64dbg: **una sola superficie de comandos + un motor de
expresiones**, y todo lo demás (GUI, scripts, plugins, tool-calling de IA) solo construye
strings. DebuggerJ++ ya tiene la pieza equivalente a medias: `handleMcpCommand()` es un
intérprete `{cmd,args}` que **IA y MCP ya comparten** vía `execDbgCommand()`. La propuesta
extiende ese eje.

### Fase 1 — Capa única de comandos (base de todo)
Consolidar `execDbgCommand(json)` como el `DbgCmdExec`/`DbgCmdExecDirect` del proyecto:
- `ExecCommand(line)` async (ya existe: encola en `mcpQueue_`, corre en hilo UI).
- `ExecCommandDirect(line)->result` sync (ya existe de facto en el helper con `future`).
- **Mejora sobre x64dbg:** mantener args en **JSON** (no parseo de comas frágil) y, opcional,
  un front-end de texto `cmd arg1, arg2` encima para el prompt/scripts.
- Beneficio inmediato: IA, MCP y plugins comparten **exactamente** las 50 tools `dbg_*`.

### Fase 2 — Motor de expresiones extensible (lo que más rinde para IA/BPs)
`EvalExpression(str)->uint64` con funciones `cat.func(args)` sobre Zydis y el motor:
- `byte/word/dword/qword/ptr(addr)`, `mod.base/size/fromname`, `dis.len/mnemonic/isbranch`,
  `reg.rax`…, `strlen/utf8`.
- Alimenta: **breakpoints condicionales**, argumentos de comando, e interpolación `{expr}`.
- Registro extensible: un plugin —o la IA— puede añadir primitivas (equivalente a
  `_plugin_registerexprfunction`). Con Zydis, `dis.*` sale superior a x64dbg.
- Nueva tool MCP `dbg_eval` y uso directo en la condición de BP (ya hay evaluador chico en BPs).

### Fase 3 — Bus de eventos `CB_*` con despacho no bloqueante
El bucle de `Debugger` ya recibe `DEBUG_EVENT`. Mapear 1:1 a un enum `DbgEvent::{InitDebug,
CreateProcess, LoadDll, Exception, Breakpoint, Stepped, ExitProcess, TraceExecute, LoadSaveDb,
MenuEntry,…}` y publicarlo a **tres** consumidores: plugins DLL, panel de IA y servidor MCP.
- Heredar la disciplina: **nada pesado en el callback**; despachar a worker; no bloquear el
  debug loop.
- Cobertura pendiente detectada por la checklist de x64dbg: `LOADSAVEDB` (ya hay cache de
  análisis → emitir evento al guardar/cargar), `TRACEEXECUTE` (ya hay run-trace → hook por
  instrucción), `MENUENTRY`.
- Mejora: los eventos también viajan por MCP (push/stream) para que un agente reaccione a
  `LoadDll`/`Exception` en vivo.

### Fase 4 — Plugins declarativos (evolución de PluginManager)
x64dbg acopla por **nombre de símbolo exportado**; DebuggerJ++ puede hacerlo **declarativo por
JSON** (ya hay manifest):
- El manifest declara: comandos que aporta, **eventos que consume** (para no invocar plugins
  en el hot path), funciones de expresión, y entradas de menú/panel.
- Un SDK C mínimo (`INITSTRUCT` con handle+versión+nombre) para plugins DLL, con callbacks de:
  `register_command`, `on_event(type, info_json)`, `expr_function`, `render_imgui(panel)`.
- Registro dinámico de comandos/expr-funcs desde el plugin, resueltos contra la capa de Fase 1/2.

### Fase 5 — UI de plugin: pestaña ImGui + tabla de referencias
Con ImGui esto es trivial y es mejora directa sobre `GuiAddQWidgetTab`/`GuiReference*`:
- Callback de **render ImGui por plugin** → su propia ventana/pestaña.
- **Tabla de resultados** reutilizable (equivalente a `GuiReference*`) para volcar xrefs,
  strings, "intermodular calls", hallazgos de la IA. (La ventana "Search results" recién
  añadida es el primer ladrillo de esto.)
- Disciplina `Gui*` vs `Dbg*`: todo lo que toque estado ImGui pasa por la cola del hilo UI
  (equivalente a `GuiExecuteOnGuiThread`), que ya es como `drainMcpQueue()` funciona.

### Fase 6 (opcional) — Scripting
Menos prioritario: IA + MCP ya cubren automatización de forma superior. Si se quiere,
un "script nativo" = secuencia de comandos JSON/MCP; un "lenguaje externo" (Python/Lua) =
plugin que llama `ExecCommandDirect`.

### Orden sugerido
1. Capa de comandos `ExecCommand/Direct` como eje único (IA/MCP/plugins).
2. Evaluador de expresiones extensible (+ `dbg_eval`, condiciones de BP).
3. Bus de eventos `CB_*` no bloqueante → plugins/IA/MCP.
4. Registro declarativo (JSON) de comandos/eventos/expr-funcs por plugin.
5. UI: pestañas ImGui y tabla de referencias por plugin.

### Dónde DebuggerJ++ ya supera a x64dbg
- **IA integrada con tool-calling** sobre la misma superficie de comandos (x64dbg no tiene).
- **MCP/JSON por TCP**: automatización remota multiproceso lista (x64dbg depende de plugins).
- **Args JSON** en vez de parseo de comas; **single-process ImGui** sin IPC de bridge.
- **Zydis** para `dis.*` más rico que el motor de x64dbg.

---

## 6. Mejoras adicionales (ronda 2)

Idea rectora: **usar la IA+MCP como multiplicador** de cada primitiva de x64dbg, y **cerrar
gaps** que `ARQUITECTURA.md` ya admite (symbol server, procesos hijos, watch, .udd).

### M1 — Command bar híbrida (texto + lenguaje natural)
x64dbg tiene una barra de comandos siempre visible. DebuggerJ++ puede ir más allá: un prompt
que acepta **comando de texto** (`bp 401000`, `dump esp`) resuelto por la capa de Fase 1, y si
la línea no parsea como comando, la manda a la **IA** que la traduce a una secuencia de tools
`dbg_*`. Un solo cuadro para "poner un bp donde llame a CreateFileW y córrelo".
- Encaje: reusa `execDbgCommand` + `runAgent`. Bajo esfuerzo, alto impacto de UX.

### M2 — Watch window con expresiones (Fase 2 aplicada)
Panel "Watch" que evalúa una lista de **expresiones extensibles** en cada pausa
(`dword(esp+4)`, `[eax]`, `mod.base("ntdll")`), como x64dbg. Con el evaluador de la Fase 2 es
casi gratis y da valor inmediato al depurar. Editable en vivo, persistido en la DB (M6).

### M3 — Breakpoints "inteligentes" con acción (supera a x64dbg)
x64dbg permite en un BP: condición, texto de log, comando a ejecutar y hit-count. Añadir un
tipo más: **al golpear, ejecutar una tool o preguntar a la IA**. Ej. "en este BP, vuelca 64
bytes de [esp], pásalos a la IA y decide si continuar" (`ai.should_continue(...)`). Convierte
un BP condicional en un mini-agente. Reusa el bus de eventos (Fase 3) + `runAgent`.

### M4 — Trace guiado + resumen por IA (evento `TRACEEXECUTE`)
Ya hay run-trace. Añadir: **trace condicional** (parar cuando una expresión sea cierta),
trace-into/over con límite, y un botón "Resumir traza con IA" que toma el log (o su muestra) y
explica el flujo, detecta bucles de descifrado, APIs tocadas, etc. Emitir `PLUG_CB_TRACEEXECUTE`
equivalente para que un plugin filtre por instrucción.

### M5 — Symbol server (PDB por HTTP)
Gap reconocido en `ARQUITECTURA.md`. Añadir soporte `symsrv`/`_NT_SYMBOL_PATH`
(`srv*C:\sym*https://msdl.microsoft.com/download/symbols`) vía DbgHelp `SymSetOptions`+
`SymInitialize` con path de servidor. Mejora call stack, `symbol` y el análisis. Tool
`dbg_symsrv_config`.

### M6 — Base de datos de análisis portable (evento `LOADSAVEDB`)
x64dbg guarda comentarios/labels/bookmarks/BPs/análisis en una DB por binario (por hash).
DebuggerJ++ ya cachea anotaciones; formalizarlo en **un `.dbj` JSON versionado** indexado por
hash del PE (no por ruta), que incluya comentarios, labels, bookmarks, breakpoints (con sus
condiciones/acciones), funciones/xrefs/loops analizados y watches. Emitir evento al guardar/
cargar (para plugins). Portable y **versionable en git**; la IA puede leerla como contexto.

### M7 — Seguir procesos hijos (child process following)
Gap reconocido. Muchos malware se relanzan o inyectan en un hijo. Opción "seguir hijos":
`DEBUG_PROCESS` (en vez de `DEBUG_ONLY_THIS_PROCESS`) + gestionar múltiples
`CREATE_PROCESS_DEBUG_EVENT`, con un selector de target activo en la GUI. Alto valor para
análisis de malware; es donde más se pierde visibilidad hoy.

### M8 — Struct/type viewer
x64dbg tiene visualización de estructuras. Definir tipos (C-like o JSON) y **aplicarlos a una
dirección** para ver campos con nombre en el dump. La IA puede **inferir la struct** desde el
uso (offsets accedidos) y proponerla. Tool `dbg_apply_struct`.

### M9 — IA como función de expresión/formato (novedad total)
Registrar la IA como primitiva del evaluador (Fase 2): `ai.classify(addr)`, `ai.name(addr)`
(sugiere nombre de función), `ai.decode(addr)`. Usable en watches, condiciones de BP y `{expr}`.
Es el equivalente a `_plugin_registerexprfunction` pero con un LLM detrás — algo que x64dbg
no puede hacer.

### M10 — Modo headless / batch (pipeline de análisis)
Correr DebuggerJ++ **sin ventana**, dirigido solo por MCP/script, para automatizar: abrir →
detectar packer → `antidebug` → `find_oep` → `dump` → `fix_iat` → volcar informe, sobre una
carpeta de muestras. Aprovecha que la capa de comandos (Fase 1) ya es headless-friendly. Ideal
para triage masivo de malware. Flag `--headless --script run.jsonl`.

### M11 — Hot-reload de plugins
x64dbg suele requerir reinicio para recargar un plugin. DebuggerJ++ puede **recargar en
caliente** un plugin DLL/JSON al detectar cambio en disco (útil mientras se desarrolla el
plugin): `plugstop` → `FreeLibrary` → `LoadLibrary` → `pluginit`. Watcher de archivos sobre
`plugins/`.

### Priorización sugerida (ronda 2)
Rápidas y de alto impacto primero: **M1** (command bar híbrida), **M2** (watch), **M6** (DB
portable). Luego las que cierran gaps de malware: **M5** (symbols), **M7** (hijos), **M4**
(trace+IA). Las diferenciadoras: **M3**, **M9** (IA en BPs y expresiones), **M10** (headless).
**M8** y **M11** como pulido.

---

## 7. Estado de implementación (2026-09-02)

**HECHO y funcional (compila + LINK OK):**
- Fase 2 — Motor de expresiones `core/ExprEval` (hex por defecto, `byte/word/dword/qword/ptr`,
  registros, `mod.base/size/fromname`, `dis.len`, `[mem]`, operadores). Tool MCP `dbg_eval`.
- M1 — Command bar híbrida (ventana **Command**): `?expr`, `cmd {args}`, JSON crudo, o IA en NL.
- M2 — **Watch** window (evalúa expresiones en cada pausa).
- M8 — **Struct** viewer (aplica campos a una base y lee memoria).
- M4 — Resumen de run-trace con IA (botón en Run trace).
- M5 — Symbol server (`Debugger::setSymbolSearchPath`, Options→Símbolos, tool `dbg_symsrv`,
  persist `symsrv.txt`).
- M9 — IA como función de expresión (`ai.classify(addr)`).
- M3 — Breakpoints con **acción al golpear** (`ai:`/`cmd {args}`/JSON), UI en menú CPU y
  `set_bp` con `action` por MCP.
- M11 — **Hot-reload** de plugins (watcher de `plugins/`).
- M10 — Modo **headless** (`--headless` oculta la ventana; MCP sigue activo).
- Fase 3 (parcial) — Bus de eventos `onEvent` (load_dll/unload_dll/exit_process + hijos) al log.
- MCP **Bypass** sin token (checkbox y `--noauth`) para uso local.
- Search for (All commands / All intermodular calls / Binary string), MCP Log cache/Load/Copy,
  Attach/Detach en menú Archivo, fix "sesión activa", Cerrar, Recientes.

**PARCIAL / roadmap:**
- M7 — Procesos hijos: se **detectan y reportan** (evento `create_process_child`, no cuelga la
  sesión) con `Depurar → Seguir procesos hijos` y `DEBUG_PROCESS`; falta el *following* completo
  (adoptar el hijo como target activo con su propio `hProcess`/mapa de memoria).
- Fase 1 — Capa de comandos: IA/MCP/plugins ya comparten `dbg_*`; falta un front-end de texto
  completo tipo x64dbg (`cmd arg1, arg2` con parser propio).
- Fase 3 — Falta exponer el bus de eventos a plugins/IA y como **streaming push** por MCP.

**PENDIENTE:**
- scriptdll / lenguaje de script (M6 scripting); struct viewer con **inferencia por IA**;
  comparación de dumps; M6 DB portable formalizada por hash (hoy la cache es por ruta).

# Arquitectura de DebuggerJ++

## Módulos

```
src/
  main.cpp              Bootstrap Win32 + D3D11 + bucle ImGui
  gui/
    App.{h,cpp}         Estado global + todos los paneles ImGui
  core/
    PeFile.{h,cpp}      Parser PE (headers, secciones, imports/exports, entropía)
    Disassembler.{h,cpp}Envoltura de Zydis (buffer -> instrucciones)
    Debugger.{h,cpp}    Motor de depuración (Windows Debug API) en hilo propio
    PackerDetect.{h,cpp}Firmas EP + heurística de packers
    StringScan.{h,cpp}  Cadenas ASCII/UTF-16 + búsqueda hex/texto
  ai/
    AiClient.{h,cpp}    Cliente WinHTTP de chat (estilos Anthropic y OpenAI-compatible)
    AiConfig.{h,cpp}    Catalogo de agentes (Tools -> Options -> AI), presets y ai_config.json
signatures/userdb.txt   Firmas de packers estilo PEiD (opcional)
```

## Modelo de hilos

- **Hilo UI**: dibuja ImGui cada frame y sondea `debugger_.state()`. Nunca toca la
  Debug API directamente; solo emite comandos (`go/pause/stepInto/stepOver/stop`).
- **Hilo del debugger**: es el *dueño* del proceso depurado. Crea el proceso con
  `DEBUG_ONLY_THIS_PROCESS` y es el único que llama a `WaitForDebugEvent` /
  `ContinueDebugEvent`. Cuando debe pausar la UI, cambia el estado a `Paused` y espera
  el siguiente comando antes de continuar.
- **Hilo de IA**: cada consulta al agente de IA corre en su propio `std::thread` para no
  congelar la interfaz.

La comunicación UI → debugger es por variables atómicas (`pending_`, `resumeSignaled_`).
El estado compartido (breakpoints, módulos) va protegido con mutex.

## Breakpoints (software 0xCC)

1. Al instalar: se lee el byte original y se escribe `0xCC`.
2. Al golpear (`EXCEPTION_BREAKPOINT`): se restaura el byte original y se retrocede
   `RIP/EIP` al inicio del opcode; la UI se pausa.
3. Al continuar: si el opcode debe volver a tener el breakpoint, se activa el
   *trap flag* (single-step); tras ejecutar la instrucción original se reinserta `0xCC`.
4. **Step Over**: si la instrucción es `call`, se coloca un breakpoint temporal
   (*one-shot*) en la dirección de retorno y se continúa; si no, es un single-step normal.

La lectura de memoria enmascara los `0xCC` de nuestros breakpoints para que el
desensamblado y el volcado hex muestren los bytes reales.

## Contexto de registros 32/64

- Target de 64 bits: `GetThreadContext` / `SetThreadContext` con `CONTEXT`.
- Target de 32 bits (WOW64 sobre Windows x64): `Wow64GetThreadContext` /
  `Wow64SetThreadContext` con `WOW64_CONTEXT`. La arquitectura se detecta con
  `IsWow64Process` en el evento `CREATE_PROCESS_DEBUG_EVENT`.

## Detección de packers

- **Firmas EP**: patrones de bytes (con comodín `??`) comparados contra los primeros
  bytes del entrypoint. Set embebido + `signatures/userdb.txt`.
- **Heurística**: entropía global/por sección > 7.2, pocos imports, secciones con
  nombres conocidos (`UPX0`, `.aspack`, `.vmp`...), y sección de código escribible.

## Capacidades implementadas y límites

- Los breakpoints de software admiten contador de impactos, condición y acción de
  solo-log. La condición es un evaluador seguro y pequeño: registros, `hit`/`hits`,
  números decimales o `0xHEX`, `&`, `|` y `== != >= <= > <`. No ejecuta código del
  objetivo ni permite dereferencias, llamadas, paréntesis o scripts.
- Además de DR0–DR3 y excepciones, hay breakpoints de memoria `PAGE_GUARD` y de
  eventos de sistema. Los de memoria se rearman mediante Trap Flag, trabajan por
  páginas completas y no pueden colocarse en la página de pila actual o sobre un
  `PAGE_GUARD` ajeno.
- `StackWalk64` sustituye al recorrido ingenuo de `RBP/EBP`. DbgHelp resuelve símbolos
  y `archivo:línea` cuando un PDB local está disponible. No se configura todavía un
  symbol server, por lo que optimizaciones, stack pivoting o símbolos ausentes pueden
  dejar la pila incompleta.
- El proceso adjuntado puede desadjuntarse mediante `DebugActiveProcessStop` sin
  terminarlo. Las sesiones lanzadas por DebuggerJ++ sí se detienen con Stop. Aún no se
  siguen árboles de procesos hijos.
- MCP usa TCP local autenticado por token y tres niveles de permiso. Al pedir
  `tools/list`, `mcp/server.mjs` consulta los plugins y expone las acciones JSON/DLL
  como tools `dbg_plugin_<plugin>_<accion>`.
- Las sesiones guardan objetivo, argumentos, anotaciones, breakpoints de software
  (incluidas condiciones/acciones), hardware, excepción y la máscara de eventos. Los
  breakpoints de memoria no se persisten porque las páginas pertenecen a una ejecución
  concreta.
- `buildAnalysisReport()` centraliza el informe Markdown que muestra MCP mediante
  `dbg_report` o escribe `dbg_export_report`/Archivo → Exportar informe. Incluye solo
  datos ya analizados (no ejecuta el objetivo ni vuelve a escanearlo).
- La columna **Flow** de CPU preindexa las VAs de la vista actual y dibuja guías para
  saltos con destino conocido dentro de ella. `Jump To` recarga una ventana estática o
  viva desde ese destino si no estaba ya visible; no es todavía un grafo CFG completo.
- `Analyze this` conserva una función candidata (recorrido lineal hasta `ret`), xrefs
  de llamadas/saltos y loops por saltos hacia atrás. Esos artefactos, junto con los
  bookmarks, se guardan en la misma caché validada que comentarios y etiquetas; la
  ventana Analysis y las tools MCP `list_functions/xrefs/loops` los exponen.

Consulta Help → Roadmap dentro de la aplicación para la lista mantenida de trabajo
pendiente y sus prioridades.

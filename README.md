# DebuggerJ++

Debugger / desensamblador con GUI para **análisis de malware** en ejecutables de
**32 y 64 bits**, al estilo OllyDbg / x64dbg. Pensado para diseccionar virus y
malware con fines **defensivos**: crear firmas de antivirus/antimalware, entender
el comportamiento y limpiar equipos.

> ⚠️ Analiza muestras siempre en una **máquina virtual aislada / sandbox**, sin red,
> con snapshots. Lanzar un binario bajo el debugger **ejecuta su código**.

## Características (v0.1)

- **Abrir `.exe` / `.dll` / `.sys`** y parseo completo del PE (32/64 bits, entrypoint,
  secciones, imports, exports, entropía).
- **Ventana CPU**: desensamblado (Zydis) del código, con resaltado de `call`/`jmp`/`ret`,
  destino de saltos, y la instrucción actual cuando estás pausado.
- **Breakpoints** por software (`0xCC`): clic en la columna de la izquierda del CPU,
  panel dedicado, o BP directo en el EntryPoint.
- **Controles**: Play (lanzar / continuar), Pause, Step Into (F7), Step Over (F8),
  Rewind (navegación de historial) y Stop.
- **Registros** (x64: RAX..R15/RIP/EFLAGS; x86: EAX..EIP) al pausar.
- **Memoria**: volcado hex + mapa de regiones (`VirtualQueryEx`) con permisos, tipo y
  módulo; salto rápido a RSP.
- **Strings & búsqueda**: extracción de cadenas ASCII/UTF-16 y búsqueda de patrones
  **hex con comodines** (`48 8B ?? C3`) o texto, en archivo o en memoria viva.
- **Módulos & símbolos**: secciones, imports/exports del PE y DLLs cargadas en runtime.
- **Packers**: detección por firmas (set embebido + `signatures/userdb.txt` estilo PEiD)
  y heurística de entropía / secciones sospechosas.
- **Panel de IA (Claude)**: chat que puede recibir automáticamente el contexto
  (registros + desensamblado actual) para ayudarte a interpretar el ASM o la memoria.

## Compilar (Windows)

Solo compila en **Windows con MSVC** porque usa la Windows Debug API, DbgHelp,
Direct3D 11 y WinHTTP.

1. Instala **Visual Studio 2022** con *Desktop development with C++*, **CMake 3.20+** y **Git**.
2. Doble clic a `build.bat` (o desde un *x64 Native Tools Command Prompt*):

   ```bat
   build.bat
   ```

   CMake descargará solo (FetchContent) **Zydis**, **Dear ImGui** y **nlohmann/json**.
3. Ejecuta `build\Release\DebuggerJ++.exe` **como Administrador** (para poder depurar).

## Uso rápido

1. **Archivo → Abrir .exe**. Se llena el CPU, secciones, strings y el escaneo de packers.
2. Pon un **breakpoint en el EntryPoint** (panel Breakpoints) y pulsa **Play (lanzar)**.
3. El proceso se detiene en el breakpoint del loader; dale **Play** otra vez para llegar
   a tu breakpoint. Desde ahí usa **Step Into / Step Over**, inspecciona **Registros** y
   **Memoria**, busca strings, y pregúntale a **Claude** sobre el ASM.

### API key de Claude

El panel de IA toma la llave de la variable de entorno `ANTHROPIC_API_KEY`, o puedes
pegarla en el campo del panel. Modelo por defecto: `claude-opus-5`.

## Arquitectura

Ver `docs/ARQUITECTURA.md`.

## Estado / pendientes

Es una base funcional. Lo próximo sensato: hardware breakpoints (DR0-DR7), memory
breakpoints, resolución de símbolos con DbgHelp/PDB, seguimiento de la pila de llamadas,
dump + reconstrucción de IAT para unpacking, y guardado de sesión.

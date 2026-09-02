# DebuggerJ++

Debugger / desensamblador con GUI para **análisis de malware** en ejecutables de
**32 y 64 bits**, al estilo OllyDbg / x64dbg. Pensado para diseccionar virus y
malware con fines **defensivos**: crear firmas de antivirus/antimalware, entender
el comportamiento y limpiar equipos.

> ⚠️ Analiza muestras siempre en una **máquina virtual aislada / sandbox**, sin red,
> con snapshots. Lanzar un binario bajo el debugger **ejecuta su código**.

## Características (v0.2)

- **Abrir `.exe` / `.dll` / `.sys`** y parseo completo del PE (32/64 bits, entrypoint,
  secciones, imports, exports, entropía).
- **Ventana CPU**: desensamblado (Zydis) del código, con resaltado de `call`/`jmp`/`ret`,
  destino de saltos, guías visuales de flujo para `jmp`/`jz`/`jnz`/etc. y la instrucción
  actual cuando estás pausado. El menú contextual **Jump To** abre el destino del salto.
- **Breakpoints** de software (`0xCC`), hardware (DR0–DR3, ejecución/escritura/lectura-escritura),
  por excepción y de memoria mediante `PAGE_GUARD` (acceso, escritura o ejecución). Incluye lista,
  etiquetas, activación/desactivación, condiciones de registros/hits, acciones de solo log y
  breakpoints de eventos (hilos/DLL). Los de memoria se configuran pausado y trabajan por páginas,
  igual que la técnica usada por OllyDbg.
- **Controles**: Play (lanzar / continuar), Pause, Step Into (F7), Step Over (F8),
  Step To Ret, Rewind (navegación de historial), Stop y reinicio de la sesión.
- **Registros** (x64: RAX..R15/RIP/EFLAGS; x86: EAX..EIP) al pausar, con edición directa.
- **Memoria**: volcado hex + mapa de regiones (`VirtualQueryEx`) con permisos, tipo y
  módulo; salto rápido a RSP, lectura/escritura, ensamblado con Keystone y parcheo/NOP.
- **Strings & búsqueda**: extracción de cadenas ASCII/UTF-16 y búsqueda de patrones
  **hex con comodines** (`48 8B ?? C3`) o texto, en archivo o en memoria viva.
- **Módulos & símbolos**: secciones, imports/exports del PE, TLS callbacks, cadena SEH
  x86, DLLs cargadas en runtime, resolución de símbolos con DbgHelp y fuente/línea cuando hay PDB.
- **Navegación y trazas**: referencias a código/datos, pila de llamadas, *run trace*,
  funciones candidatas, xrefs/loops/bookmarks persistentes, anotaciones (comentarios/etiquetas)
  y saltos a una dirección o módulo/DLL.
  Un doble clic sobre un módulo abre su código en CPU.
- **Caché de análisis**: strings, detecciones de packer y anotaciones se guardan en
  `cache/` junto al debugger. Se reutilizan al reabrir un archivo y se invalidan si cambian
  su tamaño, fecha de modificación o el mínimo de longitud de strings.
- **Sesiones e informes**: sesiones `.dbgjsession` con anotaciones y breakpoints; exportación
  de informe Markdown con objetivo, secciones, detecciones, estado y breakpoints.
- **Packers**: detección por firmas (set embebido + `signatures/userdb.txt` estilo PEiD)
  y heurística de entropía / secciones sospechosas.
- **Unpacking asistido**: búsqueda de OEP, dump *memory-aligned*, resolución y
  reconstrucción experimental de IAT, y opciones anti-anti-debug para análisis controlado.
- **Panel de IA multiagente**: Anthropic/Claude, ChatGPT/OpenAI, DeepSeek, Gemini, Grok,
  Mistral, Groq, OpenRouter, Ollama y LM Studio. El chat puede incluir automáticamente
  registros, pila y desensamblado actual.
- **Tools para IA**: al habilitar `Permitir control del debugger (tools)`, el agente puede
  consultar o controlar la sesión: abrir/lanzar/reiniciar, continuar o pausar, hacer pasos,
  leer memoria y registros, desensamblar, buscar, poner breakpoints, navegar a DLLs,
  parchear y ejecutar las demás operaciones expuestas por el debugger.
- **Ventana Code**: transforma una rutina en pseudocódigo C++ explicativo usando el
  desensamblado, memoria, símbolos y módulos. Es una interpretación para análisis, no una
  recuperación literal del código fuente.
- **MCP**: servidor local compatible con herramientas MCP para que un agente externo
  controle DebuggerJ++. Consulta [`mcp/README.md`](mcp/README.md).
- **Plugins extensibles**: manifiestos JSON y DLLs nativas x64 opcionales en `plugins/`
  agregan acciones a la UI y tools dinámicas al MCP. Las DLL solo se cargan cuando el usuario
  activa expresamente la opción y deben ser de confianza. Consulta [`docs/PLUGINS.md`](docs/PLUGINS.md).
- **Interfaz configurable**: paneles separables, visibilidad persistente, mosaico y layouts
  personalizados estilo OllyDbg/x64dbg.

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
   **Memoria**, busca strings, y pregunta al agente de IA sobre el ASM.
4. En **Window → Code**, usa **Usar RIP** e **Interpretar como C++** para obtener una
   explicación de la rutina actual.

### Agentes de IA y API keys

Configura los agentes en **Tools → Options → AI**. El primer inicio detecta, si existen,
las variables `ANTHROPIC_API_KEY` y `OPENAI_API_KEY`; también puedes pegar una llave en el
formulario de un agente. ChatGPT/OpenAI se ofrece como el preset **ChatGPT (OpenAI)**.

Las credenciales se guardan únicamente en `ai_config.json` junto al ejecutable para el uso
local de la aplicación. No subas ese archivo ni archivos `.env` al repositorio: ya están
excluidos por `.gitignore`.

Para permitir que el agente actúe, selecciona un proveedor/modelo compatible con *function
calling* y habilita **Permitir control del debugger (tools)** en la ventana **IA**. La ventana
**Code** limita al agente a herramientas de consulta para no alterar el proceso.

## Arquitectura

Ver `docs/ARQUITECTURA.md`.

## Licencia

DebuggerJ++ se distribuye bajo la **GNU General Public License v3.0 o posterior**
([GPL-3.0-or-later](LICENSE)). Puedes usarlo, estudiarlo, modificarlo y redistribuirlo
bajo esos términos. Las dependencias de terceros conservan sus propios avisos y licencias.

## Limitaciones y siguientes mejoras

Es una base funcional para análisis defensivo. Áreas previstas para una siguiente versión:

- Condiciones avanzadas expresadas como reglas/expresiones para breakpoints.
- Adjuntar a procesos ya en ejecución, seguimiento de procesos hijos y mejor control de hilos.
- Símbolos PDB más completos, información de fuente y *stack walking* robusto cuando no hay
  frame pointers.
- Persistencia completa de sesiones, exportación de informes y una vista de grafo de flujo de
  control.
- Validaciones adicionales para operaciones de modificación y mejoras al reconstruir IAT.

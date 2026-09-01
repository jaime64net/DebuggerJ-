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

## Ideas para crecer

- Hardware breakpoints (registros de depuración DR0-DR7) y memory breakpoints (guard pages).
- Símbolos con DbgHelp + PDB, y resolución de nombres de API en el desensamblado.
- Call stack (walk de la pila) y "trace" de ejecución.
- Unpacking asistido: dump del proceso en el OEP + reconstrucción de la IAT.
- Persistencia de sesión (breakpoints, comentarios, etiquetas).
```

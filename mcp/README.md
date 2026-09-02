# DebuggerJ++ MCP

Servidor MCP para que **cualquier cliente MCP compatible** controle DebuggerJ++: abrir binarios,
poner breakpoints, step, leer registros/memoria, desensamblar, buscar el OEP, dumpear,
resolver la IAT, etc. Sin dependencias externas (JSON-RPC newline-delimited sobre stdio + net TCP).

## Como funciona

```
Cliente MCP  <--stdio(JSON-RPC)-->  mcp/server.mjs  <--TCP(JSON)-->  DebuggerJ++ (MCP Control)
```

1. En DebuggerJ++: panel **Plugins → MCP Control → Activar MCP** (puerto 8377).
2. Copia el **token de sesion** que aparece en ese panel. Se invalida al detener MCP
   (y al cerrar/reniciar el servicio). Cada activacion genera un token nuevo.
3. El servidor MCP (`server.mjs`) se conecta al servidor de control de la app.
4. El cliente MCP ve las tools `dbg_*` y maneja el debugger.

Variables de entorno:

| Variable | Defecto | Descripcion |
|---|---|---|
| `DBGJPP_HOST` | `127.0.0.1` | Host del servidor de control (IP del host Windows desde WSL). |
| `DBGJPP_PORT` | `8377` | Puerto del plugin "Claude MCP" / "MCP Control". |
| `DBGJPP_TOKEN` | *(obligatorio)* | Token de sesion mostrado por DebuggerJ++ al activar MCP. |

## Registro en clientes MCP

### Caso A — Mismo equipo (Windows nativo)
```bat
claude mcp add debuggerjpp ^
  --env DBGJPP_TOKEN=PEGA_AQUI_EL_TOKEN ^
  -- node "C:\Discos\Proyectos\NEXCODE\DebuggerJ++\mcp\server.mjs"
```
(no hace falta tocar el host; usa 127.0.0.1:8377)

### Caso B — Cliente en WSL, la app en Windows
En el plugin marca **Bind 0.0.0.0 (WSL/red)** y activa. Luego:
```bash
claude mcp add debuggerjpp \
  --env DBGJPP_HOST=172.24.16.1 \
  --env DBGJPP_PORT=8377 \
  --env DBGJPP_TOKEN=PEGA_AQUI_EL_TOKEN \
  -- node /mnt/c/Discos/Proyectos/NEXCODE/DebuggerJ++/mcp/server.mjs
```
`172.24.16.1` es la IP del host Windows vista desde WSL (gateway por defecto; si cambia,
sacala con `ip route | awk '/default/{print $3}'`).

> Si no conecta: el **Firewall de Windows** puede bloquear el puerto 8377 entrante.
> Permite el puerto o la app `DebuggerJ++.exe` en el firewall.

### Caso C — Cliente sin soporte de MCP servers por stdio (p. ej. DeepSeek CLI)
El backend de control responde **JSON-lines por TCP** directamente. No hace falta el
handshake MCP para probar o automatizar; basta conectar, enviar
`{"cmd":"status","args":{},"token":"<TOKEN>"}\n` y leer la primera linea JSON:

```bash
node -e '
const net=require("net");
const s=net.createConnection({host:"172.24.16.1",port:8377},()=>{
  s.write(JSON.stringify({cmd:"status",args:{},token:process.env.DBGJPP_TOKEN})+"\n");
});
let b="";s.on("data",d=>{b+=d;let i=b.indexOf("\n");if(i>=0){console.log(b.slice(0,i));process.exit(0)}});
s.on("error",e=>{console.error("no conecta:",e.message);process.exit(1)});
'  # requiere DBGJPP_TOKEN en el entorno
```

**Verificado en esta maquina (2026-09-01):** conexion OK a `172.24.16.1:8377` desde WSL;
`status` respondio con un objetivo x86 cargado (`contabilidad_i.exe`, imageBase `0x400000`,
state `exited`).

## Seguridad y permisos MCP

Cada activacion crea un token aleatorio que se debe pasar mediante `DBGJPP_TOKEN`.
No lo pongas en el repositorio, capturas de pantalla o logs. El servidor rechaza peticiones
sin token y limita cada linea JSON a 1 MiB. El token es **de sesion**: se invalida al
detener MCP o cerrar la app; si un cliente recibe `token MCP ausente o invalido`, pide al
usuario el token nuevo del panel y actualiza el entorno del cliente.

El panel permite elegir el alcance que recibe cualquier cliente conectado:

- **Solo lectura**: inspeccion, desensamblado, memoria, PE, strings y analisis local.
- **Control de sesion**: tambien permite lanzar, pausar, hacer pasos y administrar
  breakpoints.
- **Modificacion**: ademas permite registros/memoria/parches, dumps, anti-anti-debug y
  acciones de plugins. Usalo solo para una VM aislada y un cliente de confianza.

El modo de red (`0.0.0.0`) nunca sustituye el token. Limita el Firewall a WSL o a una red
privada; no expongas este puerto a Internet.

Verifica: `claude mcp list` y luego, en Claude, pide "usa dbg_status".

## Tools disponibles (`dbg_*`)

Control de sesion: `dbg_status, dbg_open, dbg_attach, dbg_detach, dbg_launch, dbg_restart,
dbg_go, dbg_pause, dbg_step_into, dbg_step_over, dbg_step_to_ret, dbg_stop, dbg_goto,
dbg_goto_entry, dbg_goto_module`
Sesiones/informes: `dbg_save_session, dbg_load_session, dbg_report, dbg_export_report`
Estado: `dbg_get_regs, dbg_set_reg, dbg_read_mem, dbg_write_mem, dbg_disasm, dbg_stack,
dbg_mem_map`
Breakpoints: `dbg_set_bp, dbg_del_bp, dbg_list_bp, dbg_set_hwbp, dbg_del_hwbp,
dbg_list_hwbp, dbg_set_membp, dbg_del_membp, dbg_list_membp, dbg_add_exc_bp, dbg_rm_exc_bp,
dbg_list_exc, dbg_get_event_breaks, dbg_set_event_breaks`
Info PE: `dbg_modules, dbg_sections, dbg_imports, dbg_exports, dbg_packers, dbg_search_hex,
dbg_tls, dbg_seh`
Simbolos/pila: `dbg_symbol, dbg_source, dbg_call_stack`
Analisis/annotaciones: `dbg_analyze_code, dbg_list_functions, dbg_list_xrefs, dbg_list_loops,
dbg_set_bookmark, dbg_del_bookmark, dbg_list_bookmarks, dbg_clear_analysis, dbg_set_comment,
dbg_set_label, dbg_list_annotations, dbg_find_refs, dbg_run_trace, dbg_get_trace`
Unpacking/parcheo: `dbg_find_oep, dbg_get_oep, dbg_dump, dbg_resolve_iat, dbg_fix_iat,
dbg_antidebug, dbg_assemble, dbg_patch, dbg_nop`
Plugins: `dbg_plugin_list, dbg_plugin_reload, dbg_plugin_sdk, dbg_plugin_run`

Al pedir `tools/list`, el servidor descubre tambien las acciones de plugins cargados y
las publica como `dbg_plugin_<plugin>_<accion>` con el `input_schema` declarado por el
plugin. Tras `dbg_plugin_reload`, el servidor emite `notifications/tools/list_changed`;
los clientes compatibles vuelven a listar las tools y ven las acciones nuevas sin
reiniciar el servidor MCP.

## Detalles por tool

`dbg_set_bp` admite `break_on_hit`: `0` detiene en cada impacto y `N` ignora los
primeros `N-1` impactos. Tambien admite `condition` (p. ej. `rax == 0`, `ecx & 1 != 0`,
`hit >= 5`) y `log_only` para registrar sin pausar. Se administra con `dbg_del_bp` y
`dbg_list_bp`.

`dbg_set_hwbp` usa los registros de hardware `DR0-DR3`: `type` `0`=exec, `1`=write,
`3`=read/write; `len` `1/2/4/8`. No persisten en `.dbgjsession` (limite de 4).

`dbg_set_membp` crea un breakpoint de memoria `PAGE_GUARD` y requiere que el proceso
este pausado. Recibe `addr` (hex), `size` (bytes), `type` (`0` acceso, `1` escritura,
`8` ejecucion) y `label` opcional. Windows protege paginas completas, por lo que el
resultado puede incluir accesos a bytes vecinos; no lo uses para la pila y no persiste
en archivos `.dbgjsession`. Usa `dbg_list_membp` para obtener su `id` e impactos, y
`dbg_del_membp` para quitarlo.

`dbg_analyze_code` analiza el flujo local desde `addr` (o la seleccion), detecta funciones
candidatas mediante recorrido lineal hasta un `ret`, y registra xrefs de `call`/`jump`
y loops (saltos hacia atras). Estos resultados se conservan en la cache de analisis;
`dbg_list_*` los entrega a la IA. No equivale a un CFG ni a un decompilador completo.
Los bookmarks se administran con `dbg_set_bookmark`, `dbg_del_bookmark` y
`dbg_list_bookmarks`. Las anotaciones (comentarios/etiquetas) con `dbg_set_comment`,
`dbg_set_label` y `dbg_list_annotations`.

`dbg_run_trace` inicia un run-trace (registra cada instruccion; requiere proceso pausado)
y `dbg_get_trace` devuelve el log. `dbg_find_refs` busca referencias code+data a una VA.

`dbg_assemble` ensambla texto x86/x64 (Keystone) y escribe el resultado en memoria;
`dbg_patch` escribe bytes hex en una direccion y `dbg_nop` rellena con `0x90`.

Consulta [`docs/PLUGINS.md`](../docs/PLUGINS.md) para crear manifiestos JSON de plugins.

## Ejemplo de sesion

> "Abre C:\muestras\bicho.exe, lanza, pon un breakpoint en el entrypoint, corre,
>  y cuando pare desensambla 20 instrucciones y dime que hace."

El cliente encadenara `dbg_open` → `dbg_launch` → `dbg_set_bp` → `dbg_go` →
`dbg_disasm` → analisis. Para un flujo de unpacking tipico:
`dbg_open` → `dbg_launch` → `dbg_find_oep` → `dbg_get_oep` → `dbg_dump` →
`dbg_resolve_iat` → `dbg_fix_iat` → `dbg_report`.

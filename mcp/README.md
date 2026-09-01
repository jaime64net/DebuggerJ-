# DebuggerJ++ MCP

Servidor MCP para que **Claude** (Claude Code CLI) controle DebuggerJ++: abrir binarios,
poner breakpoints, step, leer registros/memoria, desensamblar, buscar el OEP, dumpear,
resolver la IAT, etc.

## Como funciona

```
Claude CLI  <--stdio(JSON-RPC)-->  mcp/server.mjs  <--TCP(JSON)-->  DebuggerJ++ (plugin Claude MCP)
```

1. En DebuggerJ++: panel **Plugins → Claude MCP → Activar Claude MCP** (puerto 8377).
2. El servidor MCP (`server.mjs`) se conecta al servidor de control de la app.
3. Claude ve las tools `dbg_*` y maneja el debugger.

## Registro en Claude Code

### Caso A — Claude y la app en la MISMA maquina (Windows nativo)
```bat
claude mcp add debuggerjpp -- node "C:\Discos\Proyectos\NEXCODE\DebuggerJ++\mcp\server.mjs"
```
(no hace falta tocar el host; usa 127.0.0.1:8377)

### Caso B — Claude en WSL, la app en Windows (tu caso)
En el plugin marca **Bind 0.0.0.0 (WSL/red)** y activa. Luego:
```bash
claude mcp add debuggerjpp \
  --env DBGJPP_HOST=172.24.16.1 \
  --env DBGJPP_PORT=8377 \
  -- node /mnt/c/Discos/Proyectos/NEXCODE/DebuggerJ++/mcp/server.mjs
```
`172.24.16.1` es la IP del host Windows vista desde WSL (gateway por defecto; si cambia,
sacala con `ip route | awk '/default/{print $3}'`).

> Si no conecta: el **Firewall de Windows** puede bloquear el puerto 8377 entrante.
> Permite el puerto o la app `DebuggerJ++.exe` en el firewall.

Verifica: `claude mcp list` y luego, en Claude, pide "usa dbg_status".

## Tools disponibles (`dbg_*`)

control: `dbg_status, dbg_open, dbg_launch, dbg_go, dbg_pause, dbg_step_into,
dbg_step_over, dbg_step_to_ret, dbg_stop`
estado: `dbg_get_regs, dbg_set_reg, dbg_read_mem, dbg_write_mem, dbg_disasm, dbg_stack`
breakpoints: `dbg_set_bp, dbg_del_bp, dbg_list_bp, dbg_add_exc_bp, dbg_list_exc`
info PE: `dbg_modules, dbg_sections, dbg_imports, dbg_packers, dbg_search_hex`
unpacking: `dbg_find_oep, dbg_get_oep, dbg_dump, dbg_resolve_iat, dbg_fix_iat, dbg_antidebug`

## Ejemplo de sesion con Claude

> "Abre C:\muestras\bicho.exe, lanza, pon un breakpoint en el entrypoint, corre,
>  y cuando pare desensambla 20 instrucciones y dime que hace."

Claude encadenara `dbg_open` → `dbg_launch` → `dbg_set_bp` → `dbg_go` →
`dbg_disasm` → analisis.

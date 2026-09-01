#!/usr/bin/env node
// Servidor MCP para DebuggerJ++.
// Traduce las tools de Claude a comandos del servidor de control TCP de la app.
// Sin dependencias externas: JSON-RPC (newline-delimited) sobre stdio + net TCP.
//
//   Variables de entorno:
//     DBGJPP_HOST  (def 127.0.0.1)   host del servidor de control
//     DBGJPP_PORT  (def 8377)        puerto (el mismo del plugin "Claude MCP")
//
//   Desde WSL hacia la app en Windows: activa "Bind 0.0.0.0" en el plugin y
//   pon DBGJPP_HOST = IP del host Windows (ver mcp/README.md).

import net from "node:net";
import readline from "node:readline";

const HOST = process.env.DBGJPP_HOST || "127.0.0.1";
const PORT = parseInt(process.env.DBGJPP_PORT || "8377", 10);

// --- Envia un comando al servidor de control y espera una linea JSON ---
function sendCommand(cmd, args) {
  return new Promise((resolve) => {
    const sock = net.createConnection({ host: HOST, port: PORT }, () => {
      sock.write(JSON.stringify({ cmd, args: args || {} }) + "\n");
    });
    let buf = "";
    sock.setTimeout(35000);
    sock.on("data", (d) => {
      buf += d.toString("utf8");
      const nl = buf.indexOf("\n");
      if (nl >= 0) {
        sock.end();
        try { resolve(JSON.parse(buf.slice(0, nl))); }
        catch (e) { resolve({ ok: false, error: "respuesta no-JSON: " + buf.slice(0, 200) }); }
      }
    });
    sock.on("timeout", () => { sock.destroy(); resolve({ ok: false, error: "timeout de conexion" }); });
    sock.on("error", (e) => resolve({ ok: false, error: "no se pudo conectar a DebuggerJ++ (" + HOST + ":" + PORT + "): " + e.message }));
  });
}

// --- Definicion de tools (name = dbg_<cmd>) ---
const S = (props = {}, required = []) => ({ type: "object", properties: props, required });
const HEX = { type: "string", description: "hex (ej '401000' o '0x401000')" };
const TOOLS = [
  ["status",      "Estado del debugger (arch, imageBase, estado, RIP, OEP).", S()],
  ["open",        "Abre un .exe/.dll para analizar (parsea PE, desensambla).", S({ path: { type: "string" } }, ["path"])],
  ["launch",      "Lanza el archivo abierto bajo depuracion.", S()],
  ["restart",     "Detiene la sesion actual y reinicia el ejecutable abierto bajo depuracion.", S()],
  ["go",          "Continua la ejecucion (Play).", S()],
  ["pause",       "Pausa la ejecucion.", S()],
  ["step_into",   "Un paso, entrando a los call.", S()],
  ["step_over",   "Un paso, saltando los call.", S()],
  ["step_to_ret", "Ejecuta hasta el ret de la funcion actual.", S()],
  ["stop",        "Termina el proceso depurado.", S()],
  ["get_regs",    "Lee los registros (requiere pausado).", S()],
  ["set_reg",     "Escribe un registro. name=rax/eip/eflags..., value=hex.", S({ name: { type: "string" }, value: HEX }, ["name", "value"])],
  ["read_mem",    "Lee memoria. Devuelve hex.", S({ addr: HEX, len: { type: "integer" } }, ["addr"])],
  ["write_mem",   "Escribe memoria (hex).", S({ addr: HEX, hex: { type: "string" } }, ["addr", "hex"])],
  ["disasm",      "Desensambla en una direccion (o RIP). count=n instrucciones.", S({ addr: HEX, count: { type: "integer" } })],
  ["goto",        "Lleva la vista CPU a una direccion para inspeccionarla.", S({ addr: HEX }, ["addr"])],
  ["goto_module", "Lleva la vista CPU a la base de un modulo/DLL cargado. name acepta nombre parcial.", S({ name: { type: "string" } }, ["name"])],
  ["stack",       "Lee la pila desde RSP/ESP. count=n entradas.", S({ count: { type: "integer" } })],
  ["set_bp",      "Pone un breakpoint de software.", S({ addr: HEX, label: { type: "string" } }, ["addr"])],
  ["del_bp",      "Quita un breakpoint.", S({ addr: HEX }, ["addr"])],
  ["list_bp",     "Lista los breakpoints.", S()],
  ["set_hwbp",    "Hardware breakpoint (DR0-3). type=0 exec/1 write/3 rw, len=1/2/4/8.", S({ addr: HEX, type: { type: "integer" }, len: { type: "integer" } }, ["addr"])],
  ["del_hwbp",    "Quita un hardware breakpoint.", S({ addr: HEX }, ["addr"])],
  ["list_hwbp",   "Lista los hardware breakpoints.", S()],
  ["add_exc_bp",  "Breakpoint de excepcion. code=0 (cualquiera) o codigo hex.", S({ code: HEX, addr: HEX })],
  ["list_exc",    "Lista los breakpoints de excepcion.", S()],
  ["modules",     "Lista los modulos cargados.", S()],
  ["sections",    "Lista las secciones del PE (con entropia).", S()],
  ["imports",     "Lista los imports del PE.", S()],
  ["packers",     "Escanea packers/protectores.", S()],
  ["search_hex",  "Busca un patron hex (ej '48 8B ?? C3') en el archivo.", S({ pattern: { type: "string" } }, ["pattern"])],
  ["find_oep",    "Busca el OEP (traza saltando calls). Requiere pausado.", S()],
  ["get_oep",     "Devuelve el OEP encontrado.", S()],
  ["dump",        "Vuelca el proceso a disco (memory-aligned).", S({ path: { type: "string" } })],
  ["resolve_iat", "Resuelve la IAT contra los exports cargados.", S()],
  ["fix_iat",     "Reconstruye la IAT en el dump (experimental).", S()],
  ["antidebug",   "Aplica anti-anti-debug (parcha el PEB).", S()],
  ["assemble",    "Ensambla texto x86/x64 (Keystone) y lo escribe en memoria.", S({ addr: HEX, text: { type: "string" } }, ["addr", "text"])],
  ["patch",       "Escribe bytes hex en una direccion.", S({ addr: HEX, hex: { type: "string" } }, ["addr", "hex"])],
  ["nop",         "Rellena con NOP (0x90) en una direccion.", S({ addr: HEX, count: { type: "integer" } }, ["addr"])],
  ["symbol",      "Resuelve el simbolo (DbgHelp) de una direccion.", S({ addr: HEX }, ["addr"])],
  ["call_stack",  "Camina la pila de llamadas (frames + simbolos).", S()],
  ["tls",         "Lista los TLS callbacks del PE.", S()],
  ["seh",         "Lista la cadena SEH (x86).", S()],
  ["exports",     "Lista los exports del PE.", S()],
  ["mem_map",     "Lista el mapa de memoria (regiones/permisos/modulo).", S()],
  ["set_comment", "Pone/actualiza (o borra si vacio) un comentario en una VA.", S({ addr: HEX, text: { type: "string" } }, ["addr"])],
  ["set_label",   "Pone/actualiza (o borra si vacio) una etiqueta en una VA.", S({ addr: HEX, text: { type: "string" } }, ["addr"])],
  ["list_annotations", "Lista comentarios y etiquetas.", S()],
  ["find_refs",   "Busca referencias (code+data) a una direccion.", S({ addr: HEX }, ["addr"])],
  ["run_trace",   "Inicia run-trace (registra cada instruccion). Requiere pausado.", S()],
  ["get_trace",   "Devuelve el log del run-trace.", S()],
  ["rm_exc_bp",   "Quita un breakpoint de excepcion por id.", S({ id: { type: "integer" } }, ["id"])],
];

const toolDefs = TOOLS.map(([cmd, desc, schema]) => ({
  name: "dbg_" + cmd, description: desc, inputSchema: schema,
}));

// --- JSON-RPC sobre stdio ---
function send(msg) { process.stdout.write(JSON.stringify(msg) + "\n"); }

const rl = readline.createInterface({ input: process.stdin });
rl.on("line", async (line) => {
  line = line.trim();
  if (!line) return;
  let msg;
  try { msg = JSON.parse(line); } catch { return; }
  const { id, method, params } = msg;

  if (method === "initialize") {
    send({ jsonrpc: "2.0", id, result: {
      protocolVersion: "2024-11-05",
      capabilities: { tools: {} },
      serverInfo: { name: "debuggerjpp", version: "1.0.0" },
    }});
  } else if (method === "notifications/initialized") {
    // sin respuesta
  } else if (method === "ping") {
    send({ jsonrpc: "2.0", id, result: {} });
  } else if (method === "tools/list") {
    send({ jsonrpc: "2.0", id, result: { tools: toolDefs } });
  } else if (method === "tools/call") {
    const name = params?.name || "";
    const args = params?.arguments || {};
    const cmd = name.startsWith("dbg_") ? name.slice(4) : name;
    const result = await sendCommand(cmd, args);
    send({ jsonrpc: "2.0", id, result: {
      content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
      isError: result && result.ok === false,
    }});
  } else if (id !== undefined) {
    send({ jsonrpc: "2.0", id, error: { code: -32601, message: "metodo no soportado: " + method } });
  }
});

process.stderr.write(`DebuggerJ++ MCP listo (control ${HOST}:${PORT})\n`);

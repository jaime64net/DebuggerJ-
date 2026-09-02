# Plugins declarativos

DebuggerJ++ carga archivos `*.json` y, tras autorización explícita, `*.dll` desde el
directorio `plugins` junto al ejecutable. Los JSON son manifiestos declarativos; las DLL
pueden aportar lógica nativa y acciones nuevas. Cada acción queda visible en **Plugins**,
en el log y como tool MCP.

Las acciones `plugin_list`, `plugin_reload` y `plugin_run` están reservadas y no pueden ser
llamadas desde otro plugin. Una DLL es código nativo: actívala solo si confías en su origen.

## Manifiesto mínimo

```json
{
  "id": "mi_plugin",
  "name": "Mi plugin",
  "version": "1.0",
  "description": "Describe el flujo.",
  "enabled": true,
  "actions": [
    {
      "id": "ver_ep",
      "label": "Ir al EntryPoint",
      "description": "Navega al punto de entrada.",
      "command": "goto_entry",
      "args": {}
    }
  ]
}
```

`id` identifica de manera única al plugin y a cada acción. `command` es uno de los
comandos `dbg_*` sin el prefijo: por ejemplo `packers`, `disasm`, `set_bp`, `find_oep` o
`dump`. `args` contiene el mismo objeto JSON que usaría la herramienta MCP equivalente.

Tras agregar o modificar un manifiesto, usa **Plugins → Plugins externos (JSON) → Recargar**
o invoca `dbg_plugin_reload` desde MCP. El manifiesto incluido
`plugins/example-analysis.json` es una plantilla inicial.

## Plugin DLL y SDK

Incluye [`sdk/DebuggerJppPluginApi.h`](../sdk/DebuggerJppPluginApi.h) y compila la DLL x64.
Exporta `DebuggerJppPluginGetApiVersion`, `DebuggerJppPluginGetInfo` y
`DebuggerJppPluginRun`. La primera devuelve `DBGJPP_PLUGIN_API_VERSION` (actualmente 1),
la segunda devuelve el manifiesto JSON y la tercera recibe la acción, argumentos JSON, la
API de host y un buffer de salida JSON.

El host proporciona `execute_json` para invocar un comando del debugger y `log` para escribir
en el log. No cruces la frontera DLL con STL ni memoria que el host tenga que liberar. La DLL
declara `input_schema` por acción; MCP publica automáticamente cada acción como
`dbg_plugin_<plugin>_<accion>`, de modo que una IA puede descubrir la capacidad nueva.

Hay una plantilla compilable en [`examples/native-plugin`](../examples/native-plugin): su acción
`status_report` llama a `host.execute_json("status", "{}", ...)`. Para compilarla con MSVC:

```bat
cmake -S examples\native-plugin -B build-plugin
cmake --build build-plugin --config Release
```

Copia la DLL resultante a `plugins/`, habilita **Permitir plugins DLL nativos** y pulsa
**Recargar**. La nueva acción aparecerá en la UI y en MCP como
`dbg_plugin_example_native_status_report`.

## Uso desde MCP

1. `dbg_plugin_list` devuelve los plugins y sus acciones.
2. `dbg_plugin_run` recibe `plugin` y `action`.

Ejemplo conceptual:

```json
{ "plugin": "analysis_helpers", "action": "overview" }
```

El resultado del comando real se devuelve dentro de `result`.

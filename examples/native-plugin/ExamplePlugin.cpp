#include "../../sdk/DebuggerJppPluginApi.h"
#include <cstdio>
#include <cstring>

static const char* kInfo = R"json(
{
  "id":"example_native",
  "name":"Example native plugin",
  "version":"1.0",
  "description":"Plantilla DLL: consulta el estado del debugger mediante la API de host.",
  "actions":[{
    "id":"status_report",
    "label":"Status report",
    "description":"Obtiene dbg_status y lo devuelve como JSON.",
    "input_schema":{"type":"object","properties":{}}
  }]
}
)json";

DBGJPP_PLUGIN_EXPORT unsigned int DBGJPP_PLUGIN_CALL DebuggerJppPluginGetApiVersion() {
    return DBGJPP_PLUGIN_API_VERSION;
}
DBGJPP_PLUGIN_EXPORT const char* DBGJPP_PLUGIN_CALL DebuggerJppPluginGetInfo() { return kInfo; }
DBGJPP_PLUGIN_EXPORT int DBGJPP_PLUGIN_CALL DebuggerJppPluginRun(const char* action, const char*,
    const DbgPluginHostApi* host, char* output, size_t outputCapacity) {
    if (!action || !host || !host->execute_json || !output || !outputCapacity) return 1;
    if (std::strcmp(action, "status_report") != 0) { std::snprintf(output, outputCapacity, "{\"ok\":false,\"error\":\"accion desconocida\"}"); return 2; }
    return host->execute_json(host->context, "status", "{}", output, outputCapacity) ? 0 : 3;
}

#pragma once

// ABI C estable para plugins DLL de DebuggerJ++. No uses STL ni asignes memoria
// que el host tenga que liberar. Compila el plugin para la misma arquitectura
// (x64) que DebuggerJ++.
#include <stddef.h>

#ifdef _WIN32
#  define DBGJPP_PLUGIN_CALL __cdecl
#  define DBGJPP_PLUGIN_EXPORT extern "C" __declspec(dllexport)
#else
#  define DBGJPP_PLUGIN_CALL
#  define DBGJPP_PLUGIN_EXPORT extern "C"
#endif

#define DBGJPP_PLUGIN_API_VERSION 1u

typedef int (DBGJPP_PLUGIN_CALL *DbgPluginExecuteJsonFn)(void* context,
    const char* command, const char* args_json, char* output, size_t output_capacity);
typedef void (DBGJPP_PLUGIN_CALL *DbgPluginLogFn)(void* context, const char* message);

typedef struct DbgPluginHostApi {
    unsigned int abi_version;
    size_t struct_size;
    void* context;
    DbgPluginExecuteJsonFn execute_json; // ejecuta un comando dbg existente
    DbgPluginLogFn log;
} DbgPluginHostApi;

// Devuelve UTF-8 JSON sin memoria prestada. Esquema:
// {"id":"mi_plugin","name":"Mi plugin","version":"1.0","description":"...",
//  "actions":[{"id":"run","label":"Ejecutar","description":"...",
//              "input_schema":{"type":"object","properties":{...}}}]}
typedef const char* (DBGJPP_PLUGIN_CALL *DbgPluginGetInfoFn)(void);

// Debe escribir UTF-8/JSON en output. args_json contiene los argumentos de la
// acción invocada por UI/MCP. 0 = éxito; otro valor = error del plugin.
typedef int (DBGJPP_PLUGIN_CALL *DbgPluginRunFn)(const char* action_id, const char* args_json,
    const DbgPluginHostApi* host, char* output, size_t output_capacity);

// Exportaciones obligatorias de la DLL:
// unsigned int DebuggerJppPluginGetApiVersion();
// const char* DebuggerJppPluginGetInfo();
// int DebuggerJppPluginRun(const char*, const char*, const DbgPluginHostApi*, char*, size_t);

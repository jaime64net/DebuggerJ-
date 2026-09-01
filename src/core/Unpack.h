#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include "Debugger.h"
#include "PeFile.h"

// Herramientas de unpacking usadas por los plugins:
//  - anti-anti-debug (ocultar el debugger al proceso)
//  - dump del proceso a disco (memory-aligned)
//  - resolucion / reconstruccion de la IAT

namespace dbg {

struct AntiDbgOptions {
    bool beingDebugged = true;  // PEB->BeingDebugged = 0
    bool ntGlobalFlag  = true;  // limpiar FLG_HEAP_* de PEB->NtGlobalFlag
    bool heapFlags     = false; // limpiar Flags/ForceFlags del heap principal
};

// Parchea el PEB del proceso depurado para esconder el debugger. Requiere sesion
// activa (Paused/Running). Devuelve false si no hay proceso.
bool applyAntiAntiDebug(Debugger& d, bool is64, const AntiDbgOptions& opt, std::string& logout);

// Vuelca la imagen del proceso a disco (memory-aligned). Si oepVA != 0 lo fija como
// AddressOfEntryPoint. Devuelve false en error.
bool dumpProcess(Debugger& d, const PeFile& pe, uint64_t oepVA,
                 const std::wstring& outPath, std::string& logout);

struct IatEntry {
    uint64_t    iatVA = 0;   // direccion del slot en la IAT
    uint64_t    ptr = 0;     // valor (direccion de la API resuelta)
    std::string module;
    std::string func;
    bool        resolved = false;
};

// Recorre la import directory en memoria y resuelve cada puntero de la IAT contra
// las tablas de exports de los modulos cargados.
bool resolveIAT(Debugger& d, std::vector<IatEntry>& out, std::string& logout);

// Reconstruye una import table limpia (descriptores + INT + nombres) y la escribe
// en una seccion nueva del dump, parcheando los data directories. EXPERIMENTAL.
bool fixIATInDump(Debugger& d, const std::wstring& dumpPath, std::string& logout);

} // namespace dbg

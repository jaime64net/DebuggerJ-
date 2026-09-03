#pragma once
#include <string>
#include <vector>

// Cliente de Detect It Easy (DIE) - el sucesor de codigo abierto de PEiD (GPLv3).
// Ejecuta la consola 'diec' sobre el binario y parsea su salida JSON. Amplia la
// deteccion nativa de PackerDetect con la enorme base de firmas de DIE
// (compilador, linker, packer, protector, .NET, instaladores, librerias...).
//
// diec.exe NO se distribuye con el proyecto; se busca junto al ejecutable
// (<exe>\die\diec.exe o <exe>\diec.exe), en el PATH, o en una ruta indicada por
// el usuario. Descarga: https://github.com/horsicq/Detect-It-Easy (GPLv3).

namespace dbg {

struct DieDetect {
    std::string type;     // Compiler / Linker / Packer / Protector / Library / Installer ...
    std::string name;     // "UPX", "Microsoft Visual C/C++", ...
    std::string version;  // "3.96"
    std::string options;  // detalles extra ("NRV,best", ...)
    std::string string;   // linea cruda de DIE ("Packer: UPX(3.96)[...]")
};

struct DieResult {
    bool ok = false;
    std::string dieExe;    // ruta de diec.exe efectivamente usada
    std::string filetype;  // "PE64" / "PE32" / ...
    std::string error;     // mensaje si !ok
    std::string rawJson;   // salida cruda (diagnostico)
    std::vector<DieDetect> detects;
};

class DieClient {
public:
    // Ubica diec.exe. Prioridad: override (si existe) -> <exe>\die\diec.exe ->
    // <exe>\diec.exe -> PATH. Devuelve "" (wide) si no se encuentra.
    static std::wstring locate(const std::wstring& override_);

    // Ejecuta 'diec -j <target>' y parsea el JSON. Sincrono, con timeout.
    static DieResult analyze(const std::wstring& diecExe, const std::wstring& targetPath);
};

} // namespace dbg

#pragma once
#include <string>
#include <vector>
#include "PeFile.h"

// Deteccion de empacadores/protectores. Combina:
//  1) Firmas de bytes en el entrypoint (estilo PEiD userdb.txt).
//  2) Heuristicas: entropia alta, secciones con nombres conocidos (UPX0, .aspack...),
//     pocos imports, seccion de codigo escribible, etc.

namespace dbg {

struct PackerMatch {
    std::string name;      // "UPX 3.x", "ASPack", ...
    std::string source;    // "firma EP" | "heuristica" | "nombre seccion"
    int         confidence = 0; // 0..100
};

struct PackerSignature {
    std::string name;
    std::vector<int> pattern; // bytes 0..255, o -1 como comodin (??)
    bool epOnly = true;
};

class PackerDetect {
public:
    // Carga firmas desde un archivo estilo PEiD (userdb.txt). Devuelve cuantas cargo.
    size_t loadSignatures(const std::string& path);
    // Ademas trae un set minimo embebido para funcionar sin archivo externo.
    void loadBuiltin();

    std::vector<PackerMatch> analyze(const PeFile& pe) const;

private:
    std::vector<PackerSignature> sigs_;
};

} // namespace dbg

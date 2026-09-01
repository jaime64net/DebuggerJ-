#pragma once
#include <cstdint>
#include <string>
#include <vector>

// Parser de PE (Portable Executable) para archivos de 32 y 64 bits.
// Lee el archivo en crudo desde disco; no necesita cargarlo en memoria.

namespace dbg {

struct PeSection {
    std::string name;
    uint32_t    virtualAddress = 0;   // RVA
    uint32_t    virtualSize    = 0;
    uint32_t    rawOffset      = 0;    // offset dentro del archivo
    uint32_t    rawSize        = 0;
    uint32_t    characteristics = 0;
    bool executable() const { return (characteristics & 0x20000000) != 0; } // IMAGE_SCN_MEM_EXECUTE
    bool readable()   const { return (characteristics & 0x40000000) != 0; }
    bool writable()   const { return (characteristics & 0x80000000) != 0; }
    double entropy = 0.0;              // 0..8, util para detectar packers
};

struct PeImport {
    std::string dll;
    std::string name;   // vacio si se importa por ordinal
    uint16_t    ordinal = 0;
    uint64_t    iatRva  = 0;
};

struct PeExport {
    std::string name;
    uint16_t    ordinal = 0;
    uint32_t    rva     = 0;
};

class PeFile {
public:
    bool load(const std::wstring& path, std::string& err);

    bool  isValid()  const { return valid_; }
    bool  is64Bit()  const { return is64_; }
    const std::wstring& path() const { return path_; }

    uint64_t imageBase()  const { return imageBase_; }
    uint32_t entryPoint() const { return entryRva_; }          // RVA
    uint64_t entryPointVA() const { return imageBase_ + entryRva_; }
    uint16_t machine()    const { return machine_; }
    uint32_t sizeOfImage() const { return sizeOfImage_; }
    uint32_t timeDateStamp() const { return timeDateStamp_; }

    const std::vector<PeSection>& sections() const { return sections_; }
    const std::vector<PeImport>&  imports()  const { return imports_; }
    const std::vector<PeExport>&  exports()  const { return exports_; }
    const std::vector<uint64_t>&  tlsCallbacks() const { return tlsCallbacks_; }
    const std::vector<uint8_t>&   raw()      const { return raw_; }

    // Convierte una RVA a offset en el archivo. Devuelve false si no cae en ninguna seccion.
    bool rvaToOffset(uint32_t rva, uint32_t& offset) const;
    // Copia hasta 'len' bytes a partir de una RVA. Devuelve cuantos copio.
    size_t readAtRva(uint32_t rva, uint8_t* out, size_t len) const;

    // Entropia global del archivo (heuristica de empaquetado).
    double overallEntropy() const { return overallEntropy_; }

private:
    void parseSections(const uint8_t* nt, bool pe64);
    void parseImports(const uint8_t* nt, bool pe64);
    void parseExports(const uint8_t* nt, bool pe64);
    void parseTls(const uint8_t* nt, bool pe64);
    static double entropyOf(const uint8_t* data, size_t len);

    std::wstring          path_;
    std::vector<uint8_t>  raw_;
    std::vector<PeSection> sections_;
    std::vector<PeImport>  imports_;
    std::vector<PeExport>  exports_;
    std::vector<uint64_t>  tlsCallbacks_;

    bool     valid_ = false;
    bool     is64_  = false;
    uint16_t machine_ = 0;
    uint64_t imageBase_ = 0;
    uint32_t entryRva_ = 0;
    uint32_t sizeOfImage_ = 0;
    uint32_t timeDateStamp_ = 0;
    double   overallEntropy_ = 0.0;
};

} // namespace dbg

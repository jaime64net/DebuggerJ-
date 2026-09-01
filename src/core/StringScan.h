#pragma once
#include <cstdint>
#include <string>
#include <vector>

// Extraccion de cadenas ASCII/UTF-16 y busqueda de patrones hex en un buffer
// (sirve tanto para el archivo en disco como para volcados de memoria del proceso).

namespace dbg {

enum class StrKind { Ascii, Utf16 };

struct FoundString {
    uint64_t address = 0;   // VA o offset segun el contexto
    StrKind  kind = StrKind::Ascii;
    std::string text;
};

// Extrae cadenas imprimibles de longitud >= minLen.
std::vector<FoundString> scanStrings(const uint8_t* data, size_t len,
                                     uint64_t baseAddress, size_t minLen = 4);

// Busca un patron hex ("48 8B ?? C3", ?? = comodin). Devuelve VAs/offsets encontrados.
std::vector<uint64_t> searchHex(const uint8_t* data, size_t len,
                                uint64_t baseAddress, const std::string& hexPattern,
                                std::string& parseErr, size_t maxHits = 1000);

// Busca un texto literal (ASCII y opcionalmente UTF-16).
std::vector<uint64_t> searchText(const uint8_t* data, size_t len, uint64_t baseAddress,
                                 const std::string& needle, bool utf16, size_t maxHits = 1000);

} // namespace dbg

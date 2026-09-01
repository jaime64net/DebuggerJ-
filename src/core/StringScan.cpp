#include "StringScan.h"
#include <cctype>
#include <cstring>
#include <sstream>

namespace dbg {

static bool printable(uint8_t c) { return c >= 0x20 && c < 0x7F; }

std::vector<FoundString> scanStrings(const uint8_t* data, size_t len,
                                     uint64_t baseAddress, size_t minLen) {
    std::vector<FoundString> out;
    if (!data || len == 0) return out;

    // ASCII
    size_t start = 0, run = 0;
    for (size_t i = 0; i < len; ++i) {
        if (printable(data[i])) { if (run == 0) start = i; run++; }
        else {
            if (run >= minLen) {
                FoundString s; s.kind = StrKind::Ascii; s.address = baseAddress + start;
                s.text.assign(reinterpret_cast<const char*>(data + start), run);
                out.push_back(std::move(s));
            }
            run = 0;
        }
    }
    if (run >= minLen) {
        FoundString s; s.kind = StrKind::Ascii; s.address = baseAddress + start;
        s.text.assign(reinterpret_cast<const char*>(data + start), run);
        out.push_back(std::move(s));
    }

    // UTF-16LE: byte imprimible seguido de 0x00
    run = 0; start = 0;
    for (size_t i = 0; i + 1 < len; i += 2) {
        if (printable(data[i]) && data[i + 1] == 0x00) { if (run == 0) start = i; run++; }
        else {
            if (run >= minLen) {
                FoundString s; s.kind = StrKind::Utf16; s.address = baseAddress + start;
                for (size_t k = 0; k < run; ++k) s.text.push_back((char)data[start + k * 2]);
                out.push_back(std::move(s));
            }
            run = 0;
        }
    }
    if (run >= minLen) {
        FoundString s; s.kind = StrKind::Utf16; s.address = baseAddress + start;
        for (size_t k = 0; k < run; ++k) s.text.push_back((char)data[start + k * 2]);
        out.push_back(std::move(s));
    }
    return out;
}

static bool parseHexPattern(const std::string& in, std::vector<int>& pat, std::string& err) {
    std::istringstream ss(in);
    std::string tok;
    while (ss >> tok) {
        if (tok == "??" || tok == "?") { pat.push_back(-1); continue; }
        if (tok.size() == 2 && tok[1] == '?') { // "4?" no soportado -> comodin
            pat.push_back(-1); continue;
        }
        try {
            size_t used = 0;
            int v = std::stoi(tok, &used, 16);
            if (used != tok.size() || v < 0 || v > 255) { err = "Byte invalido: " + tok; return false; }
            pat.push_back(v);
        } catch (...) { err = "Byte invalido: " + tok; return false; }
    }
    if (pat.empty()) { err = "Patron vacio."; return false; }
    return true;
}

std::vector<uint64_t> searchHex(const uint8_t* data, size_t len, uint64_t baseAddress,
                                const std::string& hexPattern, std::string& parseErr, size_t maxHits) {
    std::vector<uint64_t> out;
    std::vector<int> pat;
    if (!parseHexPattern(hexPattern, pat, parseErr)) return out;
    if (pat.size() > len) return out;
    for (size_t i = 0; i + pat.size() <= len; ++i) {
        bool ok = true;
        for (size_t j = 0; j < pat.size(); ++j) {
            if (pat[j] < 0) continue;
            if (data[i + j] != (uint8_t)pat[j]) { ok = false; break; }
        }
        if (ok) { out.push_back(baseAddress + i); if (out.size() >= maxHits) break; }
    }
    return out;
}

std::vector<uint64_t> searchText(const uint8_t* data, size_t len, uint64_t baseAddress,
                                 const std::string& needle, bool utf16, size_t maxHits) {
    std::vector<uint64_t> out;
    if (needle.empty()) return out;
    std::vector<uint8_t> pat;
    if (utf16) { for (char c : needle) { pat.push_back((uint8_t)c); pat.push_back(0); } }
    else       { for (char c : needle) pat.push_back((uint8_t)c); }
    if (pat.size() > len) return out;
    for (size_t i = 0; i + pat.size() <= len; ++i) {
        if (memcmp(data + i, pat.data(), pat.size()) == 0) {
            out.push_back(baseAddress + i);
            if (out.size() >= maxHits) break;
        }
    }
    return out;
}

} // namespace dbg

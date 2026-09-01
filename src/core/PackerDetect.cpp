#include "PackerDetect.h"
#include <algorithm>
#include <cctype>
#include <fstream>
#include <sstream>

namespace dbg {

void PackerDetect::loadBuiltin() {
    auto add = [&](const char* name, std::vector<int> p) {
        sigs_.push_back({name, std::move(p), true});
    };
    // Firmas minimas comunes (EP). -1 = comodin.
    add("UPX 2.x/3.x",      {0x60,0xBE,-1,-1,-1,-1,0x8D,0xBE});                 // pushad; mov esi
    add("UPX (variante)",   {0x60,0xBE,-1,-1,-1,-1,0x8D,0xBE,-1,-1,-1,-1,0x57});
    add("ASPack 2.12",      {0x60,0xE8,0x03,0x00,0x00,0x00,-1,0xE9});
    add("FSG 2.0",          {0x87,0x25,-1,-1,-1,-1,0x61,0x94});
    add("PECompact 2.x",    {0xB8,-1,-1,-1,-1,0x50,0x64,0xFF,0x35});
    add("MEW 11",           {0xE9,-1,-1,-1,-1,-1,-1,0x00,0x00});
    add("Petite",           {0xB8,-1,-1,-1,-1,0x66,0x9C,0x60,0x50});
    add("tElock",           {0x60,0xE8,0x00,0x00,0x00,0x00,0x58,0x83,0xC0});
    add("Themida/WinLicense",{0xB8,-1,-1,-1,-1,0x60,0x0B,0xC0,0x74});
    add("Enigma Protector", {0x60,0xE8,0x00,0x00,0x00,0x00,0x5D,0x83,0xED});
    add("Visual Basic",     {0x68,-1,-1,-1,-1,0xE8,-1,-1,-1,-1,0x00,0x00});     // no packer, informativo
}

size_t PackerDetect::loadSignatures(const std::string& path) {
    std::ifstream f(path);
    if (!f) return 0;
    std::string line, curName; std::vector<int> pat; bool epOnly = true; size_t n = 0;
    auto flush = [&]() {
        if (!curName.empty() && !pat.empty()) { sigs_.push_back({curName, pat, epOnly}); n++; }
        curName.clear(); pat.clear(); epOnly = true;
    };
    while (std::getline(f, line)) {
        if (!line.empty() && line.front() == '[') { flush(); curName = line.substr(1, line.find(']')-1); }
        else if (line.rfind("signature", 0) == 0 || line.rfind("Signature", 0) == 0) {
            auto eq = line.find('='); if (eq == std::string::npos) continue;
            std::string val = line.substr(eq + 1);
            std::istringstream ss(val); std::string tok;
            while (ss >> tok) {
                if (tok == "??") pat.push_back(-1);
                else { try { pat.push_back((int)std::stoul(tok, nullptr, 16)); } catch (...) {} }
            }
        } else if (line.rfind("ep_only", 0) == 0 || line.rfind("EP_Only", 0) == 0) {
            epOnly = (line.find("true") != std::string::npos);
        }
    }
    flush();
    return n;
}

static bool matchAt(const uint8_t* data, size_t len, const std::vector<int>& pat) {
    if (pat.size() > len) return false;
    for (size_t i = 0; i < pat.size(); ++i) {
        if (pat[i] < 0) continue;
        if (data[i] != (uint8_t)pat[i]) return false;
    }
    return true;
}

std::vector<PackerMatch> PackerDetect::analyze(const PeFile& pe) const {
    std::vector<PackerMatch> out;
    if (!pe.isValid()) return out;

    // 1) Firmas en el entrypoint
    uint8_t ep[64] = {0};
    size_t got = pe.readAtRva(pe.entryPoint(), ep, sizeof(ep));
    for (const auto& s : sigs_) {
        if (matchAt(ep, got, s.pattern))
            out.push_back({s.name, "firma EP", 90});
    }

    // 2) Nombres de seccion tipicos de packers
    struct { const char* frag; const char* name; } known[] = {
        {"UPX", "UPX"}, {".aspack", "ASPack"}, {".adata", "ASPack"},
        {".nsp", "NsPack"}, {"FSG", "FSG"}, {".petite", "Petite"},
        {".themida", "Themida"}, {".vmp", "VMProtect"}, {".enigma", "Enigma"},
        {".mackt", "ImpREC-rebuilt"}, {".MPRESS", "MPRESS"}, {".pec", "PECompact"},
    };
    for (const auto& sec : pe.sections()) {
        std::string up = sec.name; std::transform(up.begin(), up.end(), up.begin(), ::toupper);
        for (auto& k : known) {
            std::string frag = k.frag; std::transform(frag.begin(), frag.end(), frag.begin(), ::toupper);
            if (up.find(frag) != std::string::npos)
                out.push_back({k.name, "nombre seccion", 75});
        }
    }

    // 3) Heuristicas de empaquetado
    int hiEntropySections = 0;
    bool codeWritable = false;
    for (const auto& sec : pe.sections()) {
        if (sec.entropy > 7.2 && sec.rawSize > 0) hiEntropySections++;
        if (sec.executable() && sec.writable()) codeWritable = true;
    }
    if (pe.overallEntropy() > 7.2)
        out.push_back({"Alta entropia global (probable empacado/cifrado)", "heuristica",
                       (int)std::min(95.0, (pe.overallEntropy() - 7.0) * 90)});
    if (hiEntropySections >= 1 && pe.imports().size() < 10)
        out.push_back({"Pocos imports + seccion de alta entropia", "heuristica", 70});
    if (codeWritable)
        out.push_back({"Seccion de codigo escribible (self-modifying / unpacker)", "heuristica", 65});

    // Deduplicar por nombre conservando la confianza mas alta
    std::sort(out.begin(), out.end(), [](auto& a, auto& b){ return a.confidence > b.confidence; });
    std::vector<PackerMatch> dedup;
    for (auto& m : out) {
        bool seen = false;
        for (auto& d : dedup) if (d.name == m.name) { seen = true; break; }
        if (!seen) dedup.push_back(m);
    }
    return dedup;
}

} // namespace dbg

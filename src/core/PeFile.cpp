#include "PeFile.h"
#include <algorithm>
#include <cmath>
#include <cstring>
#include <fstream>

namespace dbg {

// --- Estructuras PE minimas (sin depender de <windows.h> para el parseo puro) ---
#pragma pack(push, 1)
struct DosHeader   { uint16_t e_magic; uint8_t pad[58]; int32_t e_lfanew; };
struct FileHeader  { uint16_t machine; uint16_t numSections; uint32_t timeDateStamp;
                     uint32_t symPtr; uint32_t numSyms; uint16_t optHeaderSize; uint16_t characteristics; };
struct DataDir     { uint32_t rva; uint32_t size; };
struct Opt32 {
    uint16_t magic; uint8_t majLink, minLink; uint32_t codeSize, initData, uninitData;
    uint32_t entryPoint, baseOfCode, baseOfData; uint32_t imageBase;
    uint32_t sectAlign, fileAlign; uint16_t majOs, minOs, majImg, minImg, majSub, minSub;
    uint32_t win32Ver, sizeOfImage, sizeOfHeaders, checksum; uint16_t subsystem, dllChars;
    uint32_t stackRes, stackCommit, heapRes, heapCommit, loaderFlags, numRvaSizes;
    DataDir dir[16];
};
struct Opt64 {
    uint16_t magic; uint8_t majLink, minLink; uint32_t codeSize, initData, uninitData;
    uint32_t entryPoint, baseOfCode; uint64_t imageBase;
    uint32_t sectAlign, fileAlign; uint16_t majOs, minOs, majImg, minImg, majSub, minSub;
    uint32_t win32Ver, sizeOfImage, sizeOfHeaders, checksum; uint16_t subsystem, dllChars;
    uint64_t stackRes, stackCommit, heapRes, heapCommit; uint32_t loaderFlags, numRvaSizes;
    DataDir dir[16];
};
struct SectionRaw {
    char     name[8];
    uint32_t virtualSize, virtualAddress, rawSize, rawOffset;
    uint32_t relocPtr, lineNumPtr; uint16_t numReloc, numLine; uint32_t characteristics;
};
struct ImportDesc  { uint32_t origFirstThunk; uint32_t timeDateStamp; uint32_t forwarder; uint32_t nameRva; uint32_t firstThunk; };
struct ExportDir   { uint32_t flags, timeDateStamp; uint16_t majVer, minVer; uint32_t nameRva, base,
                     numFuncs, numNames, funcRva, namePtrRva, ordRva; };
#pragma pack(pop)

static const uint16_t kDosMagic = 0x5A4D; // 'MZ'
static const uint32_t kNtMagic  = 0x00004550; // 'PE\0\0'

double PeFile::entropyOf(const uint8_t* data, size_t len) {
    if (len == 0) return 0.0;
    size_t counts[256] = {0};
    for (size_t i = 0; i < len; ++i) counts[data[i]]++;
    double e = 0.0;
    for (int i = 0; i < 256; ++i) {
        if (!counts[i]) continue;
        double p = double(counts[i]) / double(len);
        e -= p * std::log2(p);
    }
    return e;
}

bool PeFile::rvaToOffset(uint32_t rva, uint32_t& offset) const {
    for (const auto& s : sections_) {
        if (rva >= s.virtualAddress && rva < s.virtualAddress + std::max(s.virtualSize, s.rawSize)) {
            offset = s.rawOffset + (rva - s.virtualAddress);
            return offset < raw_.size();
        }
    }
    // Puede caer en los headers
    if (rva < raw_.size()) { offset = rva; return true; }
    return false;
}

size_t PeFile::readAtRva(uint32_t rva, uint8_t* out, size_t len) const {
    uint32_t off = 0;
    if (!rvaToOffset(rva, off)) return 0;
    size_t avail = raw_.size() > off ? raw_.size() - off : 0;
    size_t n = len < avail ? len : avail;
    std::memcpy(out, raw_.data() + off, n);
    return n;
}

size_t PeFile::writeAtRva(uint32_t rva, const uint8_t* in, size_t len) {
    uint32_t off = 0;
    if (!rvaToOffset(rva, off)) return 0;
    size_t avail = raw_.size() > off ? raw_.size() - off : 0;
    size_t n = len < avail ? len : avail;
    std::memcpy(raw_.data() + off, in, n);
    return n;
}

bool PeFile::writeRawToFile(const std::wstring& path) const {
    std::ofstream f(path.c_str(), std::ios::binary | std::ios::trunc);
    if (!f) return false;
    if (!raw_.empty()) f.write(reinterpret_cast<const char*>(raw_.data()), (std::streamsize)raw_.size());
    return (bool)f;
}

template <typename T>
static const T* at(const std::vector<uint8_t>& b, size_t off) {
    if (off + sizeof(T) > b.size()) return nullptr;
    return reinterpret_cast<const T*>(b.data() + off);
}

bool PeFile::load(const std::wstring& path, std::string& err) {
    valid_ = false;
    path_ = path;
    std::ifstream f(std::string(path.begin(), path.end()), std::ios::binary | std::ios::ate);
    if (!f) { // reintento con ruta wide en Windows
        f.open(path.c_str(), std::ios::binary | std::ios::ate);
    }
    if (!f) { err = "No se pudo abrir el archivo."; return false; }
    std::streamsize size = f.tellg();
    if (size < (std::streamsize)sizeof(DosHeader)) { err = "Archivo demasiado pequeno."; return false; }
    f.seekg(0);
    raw_.resize((size_t)size);
    f.read(reinterpret_cast<char*>(raw_.data()), size);

    auto* dos = at<DosHeader>(raw_, 0);
    if (!dos || dos->e_magic != kDosMagic) { err = "Firma MZ invalida (no es un PE)."; return false; }
    size_t ntOff = (size_t)dos->e_lfanew;
    auto* ntSig = at<uint32_t>(raw_, ntOff);
    if (!ntSig || *ntSig != kNtMagic) { err = "Firma PE invalida."; return false; }

    auto* fh = at<FileHeader>(raw_, ntOff + 4);
    if (!fh) { err = "FileHeader truncado."; return false; }
    machine_ = fh->machine;
    timeDateStamp_ = fh->timeDateStamp;

    size_t optOff = ntOff + 4 + sizeof(FileHeader);
    auto* optMagic = at<uint16_t>(raw_, optOff);
    if (!optMagic) { err = "OptionalHeader truncado."; return false; }
    is64_ = (*optMagic == 0x20B); // PE32+

    if (is64_) {
        auto* o = at<Opt64>(raw_, optOff);
        if (!o) { err = "Opt64 truncado."; return false; }
        imageBase_    = o->imageBase;
        entryRva_     = o->entryPoint;
        sizeOfImage_  = o->sizeOfImage;
    } else {
        auto* o = at<Opt32>(raw_, optOff);
        if (!o) { err = "Opt32 truncado."; return false; }
        imageBase_    = o->imageBase;
        entryRva_     = o->entryPoint;
        sizeOfImage_  = o->sizeOfImage;
    }

    const uint8_t* nt = raw_.data() + ntOff;
    parseSections(nt, is64_);
    parseImports(nt, is64_);
    parseExports(nt, is64_);
    parseTls(nt, is64_);

    overallEntropy_ = entropyOf(raw_.data(), raw_.size());
    valid_ = true;
    return true;
}

void PeFile::parseSections(const uint8_t* nt, bool /*pe64*/) {
    auto* fh = reinterpret_cast<const FileHeader*>(nt + 4);
    size_t secOff = (nt - raw_.data()) + 4 + sizeof(FileHeader) + fh->optHeaderSize;
    for (uint16_t i = 0; i < fh->numSections; ++i) {
        auto* sr = at<SectionRaw>(raw_, secOff + i * sizeof(SectionRaw));
        if (!sr) break;
        PeSection s;
        s.name.assign(sr->name, strnlen(sr->name, 8));
        s.virtualAddress = sr->virtualAddress;
        s.virtualSize    = sr->virtualSize;
        s.rawOffset      = sr->rawOffset;
        s.rawSize        = sr->rawSize;
        s.characteristics = sr->characteristics;
        if (sr->rawOffset + sr->rawSize <= raw_.size() && sr->rawSize > 0)
            s.entropy = entropyOf(raw_.data() + sr->rawOffset, sr->rawSize);
        sections_.push_back(std::move(s));
    }
}

void PeFile::parseImports(const uint8_t* nt, bool pe64) {
    size_t optOff = (nt - raw_.data()) + 4 + sizeof(FileHeader);
    const DataDir* dir = pe64 ? at<Opt64>(raw_, optOff)->dir : at<Opt32>(raw_, optOff)->dir;
    uint32_t importRva = dir[1].rva; // IMAGE_DIRECTORY_ENTRY_IMPORT
    if (!importRva) return;

    uint32_t off = 0;
    if (!rvaToOffset(importRva, off)) return;
    for (size_t i = 0;; ++i) {
        auto* d = at<ImportDesc>(raw_, off + i * sizeof(ImportDesc));
        if (!d || (d->nameRva == 0 && d->firstThunk == 0)) break;
        uint32_t nameOff = 0;
        std::string dll;
        if (rvaToOffset(d->nameRva, nameOff) && nameOff < raw_.size())
            dll.assign(reinterpret_cast<const char*>(raw_.data() + nameOff),
                       strnlen(reinterpret_cast<const char*>(raw_.data() + nameOff), 256));

        uint32_t thunkRva = d->origFirstThunk ? d->origFirstThunk : d->firstThunk;
        uint32_t thunkOff = 0;
        if (!rvaToOffset(thunkRva, thunkOff)) continue;
        for (size_t k = 0;; ++k) {
            PeImport imp; imp.dll = dll; imp.iatRva = d->firstThunk + k * (pe64 ? 8 : 4);
            if (pe64) {
                auto* t = at<uint64_t>(raw_, thunkOff + k * 8);
                if (!t || *t == 0) break;
                if (*t & 0x8000000000000000ULL) { imp.ordinal = uint16_t(*t & 0xFFFF); }
                else {
                    uint32_t hn = 0;
                    if (rvaToOffset(uint32_t(*t), hn) && hn + 2 < raw_.size())
                        imp.name.assign(reinterpret_cast<const char*>(raw_.data() + hn + 2),
                                        strnlen(reinterpret_cast<const char*>(raw_.data() + hn + 2), 256));
                }
            } else {
                auto* t = at<uint32_t>(raw_, thunkOff + k * 4);
                if (!t || *t == 0) break;
                if (*t & 0x80000000U) { imp.ordinal = uint16_t(*t & 0xFFFF); }
                else {
                    uint32_t hn = 0;
                    if (rvaToOffset(*t, hn) && hn + 2 < raw_.size())
                        imp.name.assign(reinterpret_cast<const char*>(raw_.data() + hn + 2),
                                        strnlen(reinterpret_cast<const char*>(raw_.data() + hn + 2), 256));
                }
            }
            imports_.push_back(std::move(imp));
            if (imports_.size() > 65536) return; // guarda contra archivos corruptos
        }
    }
}

void PeFile::parseTls(const uint8_t* nt, bool pe64) {
    size_t optOff = (nt - raw_.data()) + 4 + sizeof(FileHeader);
    const DataDir* dir = pe64 ? at<Opt64>(raw_, optOff)->dir : at<Opt32>(raw_, optOff)->dir;
    uint32_t tlsRva = dir[9].rva; // IMAGE_DIRECTORY_ENTRY_TLS
    if (!tlsRva) return;
    uint32_t tlsOff = 0;
    if (!rvaToOffset(tlsRva, tlsOff)) return;
    // AddressOfCallBacks: offset 24 (PE64) / 12 (PE32), es una VA absoluta.
    uint64_t cbVA = 0;
    if (pe64) { auto* p = at<uint64_t>(raw_, tlsOff + 24); if (p) cbVA = *p; }
    else      { auto* p = at<uint32_t>(raw_, tlsOff + 12); if (p) cbVA = *p; }
    if (!cbVA || cbVA < imageBase_) return;
    uint32_t cbRva = (uint32_t)(cbVA - imageBase_);
    uint32_t cbOff = 0;
    if (!rvaToOffset(cbRva, cbOff)) return;
    for (int i = 0; i < 64; ++i) {
        uint64_t entry = 0;
        if (pe64) { auto* p = at<uint64_t>(raw_, cbOff + i * 8); if (!p || !*p) break; entry = *p; }
        else      { auto* p = at<uint32_t>(raw_, cbOff + i * 4); if (!p || !*p) break; entry = *p; }
        tlsCallbacks_.push_back(entry);
    }
}

void PeFile::parseExports(const uint8_t* nt, bool pe64) {
    size_t optOff = (nt - raw_.data()) + 4 + sizeof(FileHeader);
    const DataDir* dir = pe64 ? at<Opt64>(raw_, optOff)->dir : at<Opt32>(raw_, optOff)->dir;
    uint32_t expRva = dir[0].rva; // IMAGE_DIRECTORY_ENTRY_EXPORT
    if (!expRva) return;
    uint32_t off = 0;
    if (!rvaToOffset(expRva, off)) return;
    auto* ed = at<ExportDir>(raw_, off);
    if (!ed) return;

    uint32_t namePtrOff = 0, ordOff = 0, funcOff = 0;
    rvaToOffset(ed->namePtrRva, namePtrOff);
    rvaToOffset(ed->ordRva, ordOff);
    rvaToOffset(ed->funcRva, funcOff);

    for (uint32_t i = 0; i < ed->numNames && i < 65536; ++i) {
        auto* nameRvaP = at<uint32_t>(raw_, namePtrOff + i * 4);
        auto* ordP     = at<uint16_t>(raw_, ordOff + i * 2);
        if (!nameRvaP || !ordP) break;
        uint32_t nameStrOff = 0;
        PeExport e; e.ordinal = uint16_t(*ordP + ed->base);
        if (rvaToOffset(*nameRvaP, nameStrOff) && nameStrOff < raw_.size())
            e.name.assign(reinterpret_cast<const char*>(raw_.data() + nameStrOff),
                          strnlen(reinterpret_cast<const char*>(raw_.data() + nameStrOff), 256));
        auto* fp = at<uint32_t>(raw_, funcOff + (*ordP) * 4);
        if (fp) e.rva = *fp;
        exports_.push_back(std::move(e));
    }
}

} // namespace dbg

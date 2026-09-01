#include "Unpack.h"

#include <windows.h>
#include <winternl.h>
#include <algorithm>
#include <cstring>
#include <fstream>
#include <unordered_map>

namespace dbg {

static std::string ws2s(const std::wstring& w) { return std::string(w.begin(), w.end()); }

template <typename T> static bool rd(Debugger& d, uint64_t va, T& out) {
    return d.readMemory(va, &out, sizeof(T)) == sizeof(T);
}
static std::string readCStr(Debugger& d, uint64_t va, size_t maxLen = 256) {
    char buf[256]; size_t n = std::min(maxLen, sizeof(buf));
    size_t got = d.readMemory(va, buf, n);
    std::string s;
    for (size_t i = 0; i < got; ++i) { if (!buf[i]) break; s.push_back(buf[i]); }
    return s;
}

// ---------------------------------------------------------------------------
// 1) Anti-anti-debug: parchea el PEB para esconder el debugger.
// ---------------------------------------------------------------------------
bool applyAntiAntiDebug(Debugger& d, bool is64, const AntiDbgOptions& opt, std::string& logout) {
    HANDLE h = (HANDLE)d.processHandle();
    if (!h) { logout = "No hay proceso activo."; return false; }

    typedef LONG(NTAPI * NtQIP_t)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    auto NtQIP = (NtQIP_t)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess");
    if (!NtQIP) { logout = "No se encontro NtQueryInformationProcess."; return false; }

    // PEB de 64 bits (ProcessBasicInformation = 0)
    PROCESS_BASIC_INFORMATION pbi{};
    if (NtQIP(h, 0, &pbi, sizeof(pbi), nullptr) != 0 || !pbi.PebBaseAddress) {
        logout = "No se pudo obtener el PEB."; return false;
    }
    uint64_t peb = (uint64_t)pbi.PebBaseAddress;
    int patched = 0;
    if (opt.beingDebugged) {
        uint8_t z = 0;
        if (d.writeMemory(peb + 0x02, &z, 1)) patched++;
    }
    if (opt.ntGlobalFlag) {
        uint32_t ngf = 0; d.readMemory(peb + 0xBC, &ngf, 4);
        ngf &= ~0x70u; // FLG_HEAP_ENABLE_TAIL_CHECK|FREE_CHECK|VALIDATE_PARAMETERS
        if (d.writeMemory(peb + 0xBC, &ngf, 4)) patched++;
    }
    if (opt.heapFlags) {
        uint64_t heap = 0; d.readMemory(peb + 0x30, &heap, 8); // PEB->ProcessHeap (x64)
        if (heap) {
            uint32_t flags = 2, force = 0; // HEAP_GROWABLE
            d.writeMemory(heap + 0x70, &flags, 4);
            d.writeMemory(heap + 0x74, &force, 4);
            patched++;
        }
    }

    // PEB de 32 bits (WOW64) si el target es de 32 bits
    if (!is64) {
        ULONG_PTR peb32 = 0;
        if (NtQIP(h, 26 /*ProcessWow64Information*/, &peb32, sizeof(peb32), nullptr) == 0 && peb32) {
            if (opt.beingDebugged) { uint8_t z = 0; d.writeMemory((uint64_t)peb32 + 0x02, &z, 1); }
            if (opt.ntGlobalFlag)  { uint32_t g = 0; d.readMemory((uint64_t)peb32 + 0x68, &g, 4); g &= ~0x70u; d.writeMemory((uint64_t)peb32 + 0x68, &g, 4); }
            patched++;
        }
    }

    char b[128]; sprintf_s(b, "Anti-anti-debug aplicado (%d parches) sobre PEB 0x%llX", patched, (unsigned long long)peb);
    logout = b;
    return patched > 0;
}

// ---------------------------------------------------------------------------
// 2) Dump del proceso a disco (memory-aligned).
// ---------------------------------------------------------------------------
bool dumpProcess(Debugger& d, const PeFile& pe, uint64_t oepVA,
                 const std::wstring& outPath, std::string& logout) {
    uint64_t base = d.imageBase() ? d.imageBase() : pe.imageBase();
    uint32_t size = pe.sizeOfImage();
    if (!base || !size) { logout = "Sin imageBase/sizeOfImage."; return false; }

    std::vector<uint8_t> img(size, 0);
    for (uint32_t off = 0; off < size; off += 0x1000) {
        uint32_t chunk = std::min<uint32_t>(0x1000, size - off);
        d.readMemory(base + off, img.data() + off, chunk); // fallos -> quedan en 0
    }

    auto* dos = (IMAGE_DOS_HEADER*)img.data();
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) { logout = "MZ invalido en memoria."; return false; }
    uint32_t ntOff = dos->e_lfanew;
    if (ntOff + 4 + sizeof(IMAGE_FILE_HEADER) >= size) { logout = "Headers fuera de rango."; return false; }
    auto* fh = (IMAGE_FILE_HEADER*)(img.data() + ntOff + 4);
    uint16_t magic = *(uint16_t*)(img.data() + ntOff + 4 + sizeof(IMAGE_FILE_HEADER));
    bool is64 = (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);

    auto* sec = (IMAGE_SECTION_HEADER*)(img.data() + ntOff + 4 + sizeof(IMAGE_FILE_HEADER) + fh->SizeOfOptionalHeader);
    for (int i = 0; i < fh->NumberOfSections; ++i) {
        sec[i].PointerToRawData = sec[i].VirtualAddress;
        sec[i].SizeOfRawData    = sec[i].Misc.VirtualSize;
    }
    uint8_t* optP = img.data() + ntOff + 4 + sizeof(IMAGE_FILE_HEADER);
    if (is64) {
        auto* opt = (IMAGE_OPTIONAL_HEADER64*)optP;
        opt->FileAlignment = opt->SectionAlignment;
        if (oepVA) opt->AddressOfEntryPoint = (DWORD)(oepVA - base);
    } else {
        auto* opt = (IMAGE_OPTIONAL_HEADER32*)optP;
        opt->FileAlignment = opt->SectionAlignment;
        if (oepVA) opt->AddressOfEntryPoint = (DWORD)(oepVA - base);
    }

    std::ofstream f(outPath.c_str(), std::ios::binary);
    if (!f) { logout = "No se pudo crear " + ws2s(outPath); return false; }
    f.write((const char*)img.data(), img.size());
    char b[160]; sprintf_s(b, "Dump escrito: %s (%u bytes)%s",
                           ws2s(outPath).c_str(), size, oepVA ? ", OEP fijado" : "");
    logout = b;
    return true;
}

// ---------------------------------------------------------------------------
// 3) Resolucion de la IAT.
// ---------------------------------------------------------------------------
static void buildExportMap(Debugger& d, std::unordered_map<uint64_t, std::pair<std::string, std::string>>& emap) {
    for (auto& m : d.modules()) {
        IMAGE_DOS_HEADER dos;
        if (!rd(d, m.base, dos) || dos.e_magic != IMAGE_DOS_SIGNATURE) continue;
        uint64_t ntVA = m.base + dos.e_lfanew;
        uint16_t magic; if (!rd(d, ntVA + 4 + sizeof(IMAGE_FILE_HEADER), magic)) continue;
        uint32_t expRva = 0;
        if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
            IMAGE_OPTIONAL_HEADER64 opt; if (!rd(d, ntVA + 4 + sizeof(IMAGE_FILE_HEADER), opt)) continue;
            expRva = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        } else {
            IMAGE_OPTIONAL_HEADER32 opt; if (!rd(d, ntVA + 4 + sizeof(IMAGE_FILE_HEADER), opt)) continue;
            expRva = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        }
        if (!expRva) continue;
        IMAGE_EXPORT_DIRECTORY ed; if (!rd(d, m.base + expRva, ed)) continue;
        for (uint32_t i = 0; i < ed.NumberOfNames && i < 65536; ++i) {
            uint32_t nameRva = 0; d.readMemory(m.base + ed.AddressOfNames + i * 4, &nameRva, 4);
            uint16_t ord = 0;     d.readMemory(m.base + ed.AddressOfNameOrdinals + i * 2, &ord, 2);
            uint32_t funcRva = 0; d.readMemory(m.base + ed.AddressOfFunctions + ord * 4, &funcRva, 4);
            if (!funcRva) continue;
            std::string fn = readCStr(d, m.base + nameRva);
            emap[m.base + funcRva] = { m.name, fn };
        }
    }
}

static bool readImageDirs(Debugger& d, uint64_t base, bool& is64, uint32_t& importRva) {
    IMAGE_DOS_HEADER dos; if (!rd(d, base, dos) || dos.e_magic != IMAGE_DOS_SIGNATURE) return false;
    uint64_t ntVA = base + dos.e_lfanew;
    uint16_t magic; if (!rd(d, ntVA + 4 + sizeof(IMAGE_FILE_HEADER), magic)) return false;
    is64 = (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);
    if (is64) { IMAGE_OPTIONAL_HEADER64 opt; if (!rd(d, ntVA + 4 + sizeof(IMAGE_FILE_HEADER), opt)) return false;
                importRva = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress; }
    else      { IMAGE_OPTIONAL_HEADER32 opt; if (!rd(d, ntVA + 4 + sizeof(IMAGE_FILE_HEADER), opt)) return false;
                importRva = opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress; }
    return true;
}

bool resolveIAT(Debugger& d, std::vector<IatEntry>& out, std::string& logout) {
    uint64_t base = d.imageBase();
    if (!base) { logout = "Sin imageBase (lanza el proceso primero)."; return false; }
    bool is64 = d.is64(); uint32_t importRva = 0;
    if (!readImageDirs(d, base, is64, importRva)) { logout = "No se pudo leer el PE en memoria."; return false; }
    if (!importRva) { logout = "Import directory vacia (¿aun empacado? corre Find OEP primero)."; return false; }

    std::unordered_map<uint64_t, std::pair<std::string, std::string>> emap;
    buildExportMap(d, emap);

    size_t ptrSize = is64 ? 8 : 4;
    int resolved = 0, total = 0;
    for (int i = 0; i < 4096; ++i) {
        IMAGE_IMPORT_DESCRIPTOR desc;
        if (!rd(d, base + importRva + i * sizeof(desc), desc)) break;
        if (desc.Name == 0 && desc.FirstThunk == 0) break;
        std::string dll = readCStr(d, base + desc.Name);
        uint32_t thunk = desc.FirstThunk;
        for (int k = 0; k < 16384; ++k) {
            uint64_t slotVA = base + thunk + k * ptrSize;
            uint64_t val = 0;
            if (d.readMemory(slotVA, &val, ptrSize) != ptrSize) break;
            if (val == 0) break;
            IatEntry e; e.iatVA = slotVA; e.ptr = val; e.module = dll;
            auto it = emap.find(val);
            if (it != emap.end()) { e.module = it->second.first; e.func = it->second.second; e.resolved = true; resolved++; }
            out.push_back(e); total++;
            if (total > 100000) { logout = "Demasiadas entradas (posible corrupcion)."; return false; }
        }
    }
    char b[128]; sprintf_s(b, "IAT: %d entradas, %d resueltas, %d sin resolver.", total, resolved, total - resolved);
    logout = b;
    return true;
}

// ---------------------------------------------------------------------------
// 4) Reconstruccion de la IAT en el dump (EXPERIMENTAL).
// ---------------------------------------------------------------------------
static uint32_t alignUp(uint32_t v, uint32_t a) { return a ? ((v + a - 1) / a) * a : v; }

bool fixIATInDump(Debugger& d, const std::wstring& dumpPath, std::string& logout) {
    std::vector<IatEntry> iat; std::string rlog;
    if (!resolveIAT(d, iat, rlog)) { logout = "resolveIAT: " + rlog; return false; }

    // Reporte de imports junto al dump
    {
        std::ofstream rep((dumpPath + L".imports.txt").c_str());
        if (rep) for (auto& e : iat)
            rep << (e.resolved ? "" : "?? ") << e.module << "!" << (e.func.empty() ? "<sin nombre>" : e.func)
                << "  @IAT 0x" << std::hex << e.iatVA << "\n";
    }

    std::ifstream in(dumpPath.c_str(), std::ios::binary | std::ios::ate);
    if (!in) { logout = "No se pudo abrir el dump. Genera el Dump primero."; return false; }
    std::streamsize fsize = in.tellg(); in.seekg(0);
    std::vector<uint8_t> buf((size_t)fsize); in.read((char*)buf.data(), fsize); in.close();

    auto* dos = (IMAGE_DOS_HEADER*)buf.data();
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) { logout = "Dump con MZ invalido."; return false; }
    uint32_t ntOff = dos->e_lfanew;
    auto* fh = (IMAGE_FILE_HEADER*)(buf.data() + ntOff + 4);
    uint8_t* optP = buf.data() + ntOff + 4 + sizeof(IMAGE_FILE_HEADER);
    uint16_t magic = *(uint16_t*)optP;
    bool is64 = (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);
    uint64_t base = d.imageBase();
    size_t ptrSize = is64 ? 8 : 4;

    uint32_t secAlign = is64 ? ((IMAGE_OPTIONAL_HEADER64*)optP)->SectionAlignment
                             : ((IMAGE_OPTIONAL_HEADER32*)optP)->SectionAlignment;
    uint32_t sizeOfImage = is64 ? ((IMAGE_OPTIONAL_HEADER64*)optP)->SizeOfImage
                                : ((IMAGE_OPTIONAL_HEADER32*)optP)->SizeOfImage;

    // Agrupar entradas contiguas por modulo
    struct Grp { std::string dll; uint32_t firstThunkRva; std::vector<std::string> funcs; };
    std::vector<Grp> groups;
    for (auto& e : iat) {
        uint32_t rva = (uint32_t)(e.iatVA - base);
        std::string fn = e.func.empty() ? "" : e.func;
        if (!groups.empty() && groups.back().dll == e.module &&
            rva == groups.back().firstThunkRva + (uint32_t)(groups.back().funcs.size() * ptrSize)) {
            groups.back().funcs.push_back(fn);
        } else {
            Grp g; g.dll = e.module; g.firstThunkRva = rva; g.funcs.push_back(fn);
            groups.push_back(std::move(g));
        }
    }
    if (groups.empty()) { logout = "No hay entradas de IAT para reconstruir. (Reporte escrito.)"; return false; }

    // Construir el blob: [descriptores][INTs por grupo][strings]
    uint32_t descBytes = (uint32_t)((groups.size() + 1) * sizeof(IMAGE_IMPORT_DESCRIPTOR));
    uint32_t intBytes = 0;
    for (auto& g : groups) intBytes += (uint32_t)((g.funcs.size() + 1) * ptrSize);
    // strings
    uint32_t strBytes = 0;
    for (auto& g : groups) {
        strBytes += (uint32_t)g.dll.size() + 1;
        for (auto& fn : g.funcs) strBytes += 2 + (uint32_t)(fn.empty() ? 8 : fn.size()) + 1; // hint + nombre
    }
    uint32_t blobSize = descBytes + intBytes + strBytes;

    uint32_t newRva = alignUp(std::max<uint32_t>((uint32_t)buf.size(), sizeOfImage), secAlign);
    // como el dump es memory-aligned, offset de archivo == RVA
    buf.resize((size_t)newRva + alignUp(blobSize, secAlign), 0);
    uint8_t* blob = buf.data() + newRva;

    uint32_t intCursor = descBytes;
    uint32_t strCursor = descBytes + intBytes;
    auto* descs = (IMAGE_IMPORT_DESCRIPTOR*)blob;
    for (size_t gi = 0; gi < groups.size(); ++gi) {
        auto& g = groups[gi];
        uint32_t intRva = newRva + intCursor;
        descs[gi].OriginalFirstThunk = intRva;
        descs[gi].TimeDateStamp = 0;
        descs[gi].ForwarderChain = 0;
        descs[gi].FirstThunk = g.firstThunkRva;
        // nombre de la DLL
        uint32_t dllNameRva = newRva + strCursor;
        memcpy(buf.data() + newRva + strCursor, g.dll.c_str(), g.dll.size() + 1);
        strCursor += (uint32_t)g.dll.size() + 1;
        descs[gi].Name = dllNameRva;
        // INT + nombres de funciones
        for (size_t fi = 0; fi < g.funcs.size(); ++fi) {
            uint32_t ibnRva = newRva + strCursor;
            uint16_t hint = 0;
            memcpy(buf.data() + newRva + strCursor, &hint, 2); strCursor += 2;
            const std::string& fn = g.funcs[fi];
            std::string name = fn.empty() ? "Ordinal0" : fn;
            memcpy(buf.data() + newRva + strCursor, name.c_str(), name.size() + 1);
            strCursor += (uint32_t)name.size() + 1;
            if (is64) { uint64_t t = ibnRva; memcpy(buf.data() + intRva - newRva + newRva + fi * 8, &t, 8); }
            else      { uint32_t t = ibnRva; memcpy(buf.data() + intRva - newRva + newRva + fi * 4, &t, 4); }
        }
        // terminador del INT (0) ya esta por el resize a 0
        intCursor += (uint32_t)((g.funcs.size() + 1) * ptrSize);
    }
    // descriptor terminador (todo 0) ya esta

    // Nueva seccion en el header
    auto* secs = (IMAGE_SECTION_HEADER*)(buf.data() + ntOff + 4 + sizeof(IMAGE_FILE_HEADER) + fh->SizeOfOptionalHeader);
    int nsec = fh->NumberOfSections;
    IMAGE_SECTION_HEADER& ns = secs[nsec];
    memset(&ns, 0, sizeof(ns));
    memcpy(ns.Name, ".idata2", 7);
    ns.Misc.VirtualSize = blobSize;
    ns.VirtualAddress = newRva;
    ns.SizeOfRawData = alignUp(blobSize, secAlign);
    ns.PointerToRawData = newRva;
    ns.Characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_CNT_INITIALIZED_DATA;
    fh->NumberOfSections = (WORD)(nsec + 1);

    // Actualizar directorios y SizeOfImage
    uint32_t newSizeImg = alignUp(newRva + blobSize, secAlign);
    if (is64) {
        auto* opt = (IMAGE_OPTIONAL_HEADER64*)optP;
        opt->SizeOfImage = newSizeImg;
        opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = newRva;
        opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = descBytes;
        opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress = 0;
        opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size = 0;
    } else {
        auto* opt = (IMAGE_OPTIONAL_HEADER32*)optP;
        opt->SizeOfImage = newSizeImg;
        opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = newRva;
        opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = descBytes;
        opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress = 0;
        opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size = 0;
    }

    std::wstring fixedPath = dumpPath + L".fixed.exe";
    std::ofstream out(fixedPath.c_str(), std::ios::binary);
    if (!out) { logout = "No se pudo escribir el dump corregido."; return false; }
    out.write((const char*)buf.data(), buf.size());

    char b[220];
    sprintf_s(b, "IAT reconstruida [EXPERIMENTAL]: %zu grupos, %zu imports. Escrito %s + .imports.txt. Verifica el resultado.",
              groups.size(), iat.size(), ws2s(fixedPath).c_str());
    logout = b;
    return true;
}

} // namespace dbg

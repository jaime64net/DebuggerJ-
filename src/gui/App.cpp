#include "App.h"

#include <windows.h>
#include <bcrypt.h>
#include <commdlg.h>
#include <algorithm>
#include <array>
#include <cctype>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sstream>
#include <nlohmann/json.hpp>
#include <keystone/keystone.h>
#include "imgui.h"
#include "imgui_internal.h"   // FindWindowByName (captura de geometria)

using njson = nlohmann::json;

namespace dbg {

static std::string hex64(uint64_t v)  { char b[24]; std::snprintf(b, sizeof(b), "%016llX", (unsigned long long)v); return b; }
static std::string hex32(uint32_t v)  { char b[16]; std::snprintf(b, sizeof(b), "%08X", v); return b; }
static std::string vaStr(uint64_t v, bool is64) { char b[24]; std::snprintf(b, sizeof(b), is64 ? "%016llX" : "%08llX", (unsigned long long)v); return b; }
static std::string exeSiblingDir() {
    wchar_t exe[MAX_PATH] = {};
    GetModuleFileNameW(nullptr, exe, MAX_PATH);
    std::wstring p(exe); auto pos = p.find_last_of(L"\\/");
    std::wstring dir = pos == std::wstring::npos ? L"." : p.substr(0, pos);
    return std::string(dir.begin(), dir.end());
}

// La caché pertenece a la instalación del debugger, no al directorio de la
// muestra. Así no se escribe junto a un ejecutable potencialmente sospechoso.
// El nombre se deriva de la ruta completa y el contenido se invalida con el
// tamaño y la fecha de modificación del archivo de origen.
static std::wstring analysisCachePath(const std::wstring& target) {
    wchar_t exe[MAX_PATH] = {};
    GetModuleFileNameW(nullptr, exe, MAX_PATH);
    std::wstring exePath(exe);
    const auto pos = exePath.find_last_of(L"\\\\/");
    const std::wstring baseDir = pos == std::wstring::npos ? L"." : exePath.substr(0, pos);
    const std::wstring cacheDir = baseDir + L"\\cache";
    if (!CreateDirectoryW(cacheDir.c_str(), nullptr) && GetLastError() != ERROR_ALREADY_EXISTS)
        return {};

    uint64_t hash = 1469598103934665603ull; // FNV-1a: identificador estable, no secreto.
    for (wchar_t ch : target) {
        const wchar_t lower = (ch >= L'A' && ch <= L'Z') ? ch - L'A' + L'a' : ch;
        hash ^= static_cast<uint64_t>(lower);
        hash *= 1099511628211ull;
    }
    wchar_t filename[40] = {};
    _snwprintf_s(filename, _countof(filename), _TRUNCATE, L"%016llX.json",
                 static_cast<unsigned long long>(hash));
    return cacheDir + L"\\" + filename;
}

static bool analysisSourceStamp(const std::wstring& path, uint64_t& size, uint64_t& writeTime) {
    WIN32_FILE_ATTRIBUTE_DATA data = {};
    if (!GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &data)) return false;
    ULARGE_INTEGER fileSize = {};
    fileSize.LowPart = data.nFileSizeLow;
    fileSize.HighPart = data.nFileSizeHigh;
    ULARGE_INTEGER modified = {};
    modified.LowPart = data.ftLastWriteTime.dwLowDateTime;
    modified.HighPart = data.ftLastWriteTime.dwHighDateTime;
    size = fileSize.QuadPart;
    writeTime = modified.QuadPart;
    return true;
}

static std::string makeMcpToken() {
    std::array<unsigned char, 24> bytes{};
    if (BCryptGenRandom(nullptr, bytes.data(), static_cast<ULONG>(bytes.size()),
                        BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0)
        return {};
    static constexpr char hex[] = "0123456789abcdef";
    std::string token;
    token.reserve(bytes.size() * 2);
    for (unsigned char byte : bytes) {
        token.push_back(hex[byte >> 4]);
        token.push_back(hex[byte & 0x0F]);
    }
    return token;
}

static const char* exceptionName(uint32_t code) {
    switch (code) {
        case 0:          return "(cualquiera)";
        case 0xC0000005: return "ACCESS_VIOLATION";
        case 0x80000003: return "BREAKPOINT";
        case 0x80000004: return "SINGLE_STEP";
        case 0xC000001D: return "ILLEGAL_INSTRUCTION";
        case 0xC0000094: return "INT_DIVIDE_BY_ZERO";
        case 0xC0000095: return "INT_OVERFLOW";
        case 0xC00000FD: return "STACK_OVERFLOW";
        case 0xC0000096: return "PRIV_INSTRUCTION";
        case 0xC0000025: return "NONCONTINUABLE_EXCEPTION";
        case 0xC0000008: return "INVALID_HANDLE";
        case 0x40010006: return "DBG_PRINTEXCEPTION_C";
        default:         return "(otro)";
    }
}

App::App() {
    packerLoaded_ = false;
    // Callbacks del motor: solo para logging thread-safe.
    DbgCallbacks cb;
    cb.onLog    = [this](const std::string& m){ pushLog(m); };
    cb.onModule = [this](const LoadedModule& m){ pushLog("DLL: " + m.name + "  @0x" + hex64(m.base)); };
    // Fase 3: bus de eventos CB_*. Se publica al log (y queda disponible para
    // plugins/IA/MCP como punto de extension futuro).
    cb.onEvent  = [this](const std::string& type, uint64_t arg){
        pushLog("[evento] " + type + "  0x" + hex64(arg));
    };
    debugger_.setCallbacks(cb);

    aiConfig_.load();
    if (const AiAgent* a = aiConfig_.current()) ai_.setAgent(*a);
    loadExternalPlugins();
    loadRecent();
    loadSymPath();
    loadLayouts();
    loadVisibility();
    ensureVisibilityKeys();
}

App::~App() {
    mcp_.stop();
    // liberar cualquier peticion MCP pendiente
    { std::lock_guard<std::mutex> lk(mcpMutex_);
      for (auto* r : mcpQueue_) { r->resp.set_value("{\"ok\":false,\"error\":\"cerrando\"}"); delete r; }
      mcpQueue_.clear(); }
    if (aiThread_.joinable()) aiThread_.join();
    debugger_.detachAndStop();
}

void App::pushLog(const std::string& s) {
    std::lock_guard<std::mutex> lk(logMutex_);
    log_.push_back(s);
    while (log_.size() > 500) log_.pop_front();
}

// ---------------------------------------------------------------------------
// Carga de archivo
// ---------------------------------------------------------------------------
void App::openFile(const std::wstring& path) {
    openError_.clear();
    if (!pe_.load(path, openError_)) {
        fileLoaded_ = false;
        pushLog("Error abriendo: " + openError_);
        return;
    }
    loadedPath_ = path;
    fileLoaded_ = true;
    dis_.setMode(pe_.is64Bit());
    liveView_ = false;
    packerLoaded_ = false;
    packerMatches_.clear();
    comments_.clear(); labels_.clear(); refs_.clear(); bookmarks_.clear();
    analyzedFunctions_.clear(); analysisXrefs_.clear(); analysisLoops_.clear();
    analysisCacheLoaded_ = false;
    loadAnnotations();
    refreshDisassembly();
    if (!analysisCacheLoaded_) {
        refreshStaticStrings();
        runPackerScan();
        saveAnalysisCache();
    }
    addRecent(path);
    std::string p(path.begin(), path.end());
    pushLog("Abierto: " + p + (pe_.is64Bit() ? "  [x64]" : "  [x86]") +
            "  EntryPoint VA=0x" + hex64(pe_.entryPointVA()));
}

// ---------------------------------------------------------------------------
// Archivos recientes (persistidos en recent.txt, UTF-8, uno por linea)
// ---------------------------------------------------------------------------
static std::string recentFilePath() {
    wchar_t exe[MAX_PATH] = {0};
    GetModuleFileNameW(nullptr, exe, MAX_PATH);
    std::wstring w(exe);
    auto pos = w.find_last_of(L"\\/");
    std::wstring dir = (pos == std::wstring::npos) ? L"." : w.substr(0, pos);
    std::wstring path = dir + L"\\recent.txt";
    return std::string(path.begin(), path.end());
}
static std::string wToUtf8(const std::wstring& w) {
    if (w.empty()) return "";
    int len = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), nullptr, 0, nullptr, nullptr);
    std::string s(len, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), s.data(), len, nullptr, nullptr);
    return s;
}
static std::wstring utf8ToW(const std::string& s) {
    if (s.empty()) return L"";
    int len = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    std::wstring w(len, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), w.data(), len);
    return w;
}

void App::addRecent(const std::wstring& path) {
    // Quita duplicados (case-insensitive) y pone el archivo al frente.
    auto same = [&](const std::wstring& a){ return _wcsicmp(a.c_str(), path.c_str()) == 0; };
    recentFiles_.erase(std::remove_if(recentFiles_.begin(), recentFiles_.end(), same), recentFiles_.end());
    recentFiles_.insert(recentFiles_.begin(), path);
    if (recentFiles_.size() > 10) recentFiles_.resize(10);
    saveRecent();
}
void App::saveRecent() {
    std::ofstream f(recentFilePath(), std::ios::binary);
    if (!f) return;
    for (auto& w : recentFiles_) f << wToUtf8(w) << "\n";
}
void App::loadRecent() {
    recentFiles_.clear();
    std::ifstream f(recentFilePath(), std::ios::binary);
    if (!f) return;
    std::string line;
    while (std::getline(f, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (!line.empty() && recentFiles_.size() < 10) recentFiles_.push_back(utf8ToW(line));
    }
}

void App::refreshDisassembly() {
    insns_.clear();
    if (!fileLoaded_) return;
    // Desensamblar la primera seccion ejecutable (normalmente .text)
    for (const auto& s : pe_.sections()) {
        if (!s.executable()) continue;
        uint32_t off = 0;
        if (!pe_.rvaToOffset(s.virtualAddress, off)) continue;
        size_t len = s.rawSize ? s.rawSize : s.virtualSize;
        if (off + len > pe_.raw().size()) len = pe_.raw().size() - off;
        disBase_ = pe_.imageBase() + s.virtualAddress;
        insns_ = dis_.disassemble(pe_.raw().data() + off, len, disBase_, 20000);
        break;
    }
    // Seleccionar el entrypoint
    uint64_t epVA = pe_.entryPointVA();
    for (size_t i = 0; i < insns_.size(); ++i)
        if (insns_[i].address == epVA) { selectedInsn_ = (int)i; break; }
}

void App::refreshLiveDisassembly(uint64_t around) {
    insns_.clear();
    uint8_t buf[2048];
    uint64_t start = around;
    size_t got = debugger_.readMemory(start, buf, sizeof(buf));
    if (got == 0) return;
    disBase_ = start;
    dis_.setMode(debugger_.is64());
    insns_ = dis_.disassemble(buf, got, start, 400);
    liveView_ = true;
}

void App::refreshStaticStrings() {
    strings_.clear();
    if (!fileLoaded_) return;
    strings_ = scanStrings(pe_.raw().data(), pe_.raw().size(), pe_.imageBase(), minStrLen_);
    saveAnalysisCache();
}

void App::runPackerScan() {
    if (!packerLoaded_) {
        packer_.loadBuiltin();
        packer_.loadSignatures("signatures/userdb.txt"); // opcional
        packerLoaded_ = true;
    }
    if (fileLoaded_) {
        packerMatches_ = packer_.analyze(pe_);
        saveAnalysisCache();
    }
}

// Analisis local inspirado en "Analyse code" de OllyDbg: no ejecuta el binario.
// Recorre un bloque razonable, resuelve destinos call/jump y deja etiquetas y
// comentarios para que la CPU y la IA tengan nombres estables.
void App::analyzeCodeAt(uint64_t address) {
    if (!fileLoaded_) { pushLog("Analyze: abre un ejecutable primero."); return; }
    std::vector<uint8_t> bytes(0x4000); size_t got = 0;
    bool live = dbgState_ == DbgState::Paused;
    if (live) { got = debugger_.readMemory(address, bytes.data(), bytes.size()); dis_.setMode(debugger_.is64()); }
    else if (address >= pe_.imageBase()) { got = pe_.readAtRva((uint32_t)(address - pe_.imageBase()), bytes.data(), bytes.size()); dis_.setMode(pe_.is64Bit()); }
    if (!got) { pushLog("Analyze: no se pudo leer codigo en 0x" + hex64(address)); return; }
    auto code = dis_.disassemble(bytes.data(), got, address, 1024);
    std::string module = moduleNameAt(address); if (module.empty()) module = "modulo actual";
    if (!labels_.count(address)) labels_[address] = "sub_" + hex64(address);
    int calls = 0, branches = 0, symbols = 0, usedInstructions = 0;
    uint64_t functionEnd = address;
    for (const auto& in : code) {
        ++usedInstructions;
        functionEnd = in.address + (in.length ? in.length : 1);
        if (!in.hasBranchTarget) { if (in.isRet) break; continue; }
        std::string sym = live ? debugger_.symbolAt(in.branchTarget) : "";
        std::string dstModule = moduleNameAt(in.branchTarget);
        if (in.isCall) {
            ++calls;
            if (!sym.empty()) { comments_[in.address] = "call " + sym; ++symbols; }
            else if (dstModule == module && !labels_.count(in.branchTarget)) labels_[in.branchTarget] = "sub_" + hex64(in.branchTarget);
            else if (!dstModule.empty()) comments_[in.address] = "call " + dstModule + "+0x" + hex64(in.branchTarget);
        } else if (in.isJump) {
            ++branches;
            if (!labels_.count(in.branchTarget) && (dstModule == module || dstModule.empty())) labels_[in.branchTarget] = "loc_" + hex64(in.branchTarget);
            if (in.branchTarget >= address && in.branchTarget < in.address) {
                const auto exists = std::find_if(analysisLoops_.begin(), analysisLoops_.end(), [&](const AnalysisLoop& loop) {
                    return loop.start == in.branchTarget && loop.end == in.address && loop.function == address;
                });
                if (exists == analysisLoops_.end()) analysisLoops_.push_back({in.branchTarget, in.address, address});
            }
        }
        if (in.isRet) break; // limite lineal seguro para una funcion candidata
    }
    // Guardar xrefs y funcion como analisis persistente. Las duplicadas se
    // eliminan para que repetir Analyze this sea idempotente.
    for (int index = 0; index < usedInstructions && index < (int)code.size(); ++index) {
        const auto& in = code[index];
        if (!in.hasBranchTarget || (!in.isCall && !in.isJump)) continue;
        const std::string type = in.isCall ? "call" : "jump";
        const auto exists = std::find_if(analysisXrefs_.begin(), analysisXrefs_.end(), [&](const AnalysisXref& xref) {
            return xref.from == in.address && xref.to == in.branchTarget && xref.type == type;
        });
        if (exists == analysisXrefs_.end()) analysisXrefs_.push_back({in.address, in.branchTarget, type});
    }
    AnalyzedFunction function{address, functionEnd, static_cast<uint32_t>(usedInstructions), static_cast<uint32_t>(calls), static_cast<uint32_t>(branches), labels_[address]};
    auto known = std::find_if(analyzedFunctions_.begin(), analyzedFunctions_.end(), [&](const AnalyzedFunction& item) { return item.start == address; });
    if (known == analyzedFunctions_.end()) analyzedFunctions_.push_back(std::move(function)); else *known = std::move(function);
    comments_[address] = "Analyze: " + module + ", " + std::to_string(usedInstructions) + " instrucciones, " + std::to_string(calls) + " calls";
    saveAnnotations();
    pushLog("Analyze 0x" + hex64(address) + " [" + module + "]: " + std::to_string(usedInstructions) + " instrucciones, " + std::to_string(calls) + " calls, " + std::to_string(branches) + " saltos, " + std::to_string(symbols) + " simbolos.");
}

void App::clearAutoAnalysis() {
    analyzedFunctions_.clear(); analysisXrefs_.clear(); analysisLoops_.clear();
    for (auto it = labels_.begin(); it != labels_.end();) {
        if (it->second.rfind("sub_", 0) == 0 || it->second.rfind("loc_", 0) == 0) it = labels_.erase(it); else ++it;
    }
    for (auto it = comments_.begin(); it != comments_.end();) {
        if (it->second.rfind("Analyze: ", 0) == 0 || it->second.rfind("call ", 0) == 0) it = comments_.erase(it); else ++it;
    }
    saveAnnotations();
    pushLog("Analisis automatico (funciones, xrefs, loops y anotaciones auto) limpiado.");
}

void App::gotoAddress(uint64_t va) {
    if (dbgState_ == DbgState::Paused) {
        refreshLiveDisassembly(va);
        selectedInsn_ = 0;
        pendingScroll_ = 0;
    } else {
        for (size_t i = 0; i < insns_.size(); ++i) {
            if (insns_[i].address == va) { selectedInsn_ = (int)i; pendingScroll_ = (int)i; return; }
        }
        // El destino puede estar fuera de las primeras 20k instrucciones de la
        // seccion. Cargar una vista estatica desde la VA permite que Jump To
        // siempre llegue al destino conocido del salto.
        if (fileLoaded_ && va >= pe_.imageBase()) {
            uint32_t rawOffset = 0;
            const uint64_t rva64 = va - pe_.imageBase();
            if (rva64 <= UINT32_MAX && pe_.rvaToOffset(static_cast<uint32_t>(rva64), rawOffset) && rawOffset < pe_.raw().size()) {
                const size_t length = std::min<size_t>(0x4000, pe_.raw().size() - rawOffset);
                dis_.setMode(pe_.is64Bit());
                insns_ = dis_.disassemble(pe_.raw().data() + rawOffset, length, va, 1024);
                disBase_ = va; liveView_ = false;
                selectedInsn_ = 0; pendingScroll_ = 0;
                pushLog("Jump To -> 0x" + hex64(va));
            }
        }
    }
}

std::string App::moduleNameAt(uint64_t va) {
    for (auto& m : debugger_.modules()) {
        uint32_t e_lfanew = 0, sizeImg = 0; uint8_t hdr[2];
        if (debugger_.readMemory(m.base, hdr, 2) == 2 && hdr[0]=='M' && hdr[1]=='Z') {
            debugger_.readMemory(m.base + 0x3C, &e_lfanew, 4);
            debugger_.readMemory(m.base + e_lfanew + 24 + 0x38, &sizeImg, 4);
        }
        if (sizeImg && va >= m.base && va < m.base + sizeImg) return m.name;
    }
    // fallback: parte de modulo del simbolo (DbgHelp)
    std::string s = debugger_.symbolAt(va);
    auto p = s.find('!');
    if (p != std::string::npos) return s.substr(0, p);
    // fallback: imagen principal
    if (fileLoaded_ && va >= pe_.imageBase() && va < pe_.imageBase() + pe_.sizeOfImage()) {
        std::string pth(loadedPath_.begin(), loadedPath_.end());
        auto q = pth.find_last_of("\\/");
        return q == std::string::npos ? pth : pth.substr(q + 1);
    }
    return "";
}

void App::startDebugSession() {
    if (!fileLoaded_) { pushLog("Abre un .exe primero."); return; }
    // Una sesion anterior que ya termino queda en Exited: recogela (join + cierra
    // handles) para volver a Idle, si no nunca se podria relanzar.
    if (debugger_.state() == DbgState::Exited) debugger_.detachAndStop();
    if (debugger_.state() != DbgState::Idle) { pushLog("Ya hay una sesion activa."); return; }
    debugger_.setTargetImageLayout(pe_.imageBase(), pe_.sizeOfImage());
    std::string err;
    std::wstring args(strlen(launchArgs_) ? std::wstring(launchArgs_, launchArgs_ + strlen(launchArgs_)) : L"");
    if (!debugger_.launch(loadedPath_, args, err)) pushLog("No se pudo lanzar: " + err);
}

void App::attachToProcess(uint32_t pid) {
    if (!pid) { pushLog("Adjuntar: PID invalido."); return; }
    if (debugger_.state() == DbgState::Exited) debugger_.detachAndStop();
    if (debugger_.state() != DbgState::Idle) { pushLog("Adjuntar: ya hay una sesion activa."); return; }

    std::wstring targetPath;
    // Intentamos obtener el PE estatico para que CPU, imports y cache esten
    // disponibles. No cambiamos el archivo abierto si el attach finalmente falla.
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (process) {
        wchar_t path[MAX_PATH] = {};
        DWORD chars = MAX_PATH;
        if (QueryFullProcessImageNameW(process, 0, path, &chars)) targetPath = path;
        CloseHandle(process);
    }
    if (!targetPath.empty()) {
        PeFile staticTarget;
        std::string ignored;
        if (staticTarget.load(targetPath, ignored))
            debugger_.setTargetImageLayout(staticTarget.imageBase(), staticTarget.sizeOfImage());
        else debugger_.setTargetImageLayout(0, 0);
    }
    else debugger_.setTargetImageLayout(0, 0);
    std::string err;
    if (!debugger_.attach(pid, err)) pushLog("No se pudo adjuntar al PID " + std::to_string(pid) + ": " + err);
    else {
        if (!targetPath.empty()) openFile(targetPath);
        pushLog("Adjuntando al PID " + std::to_string(pid) + ".");
    }
}

bool App::saveSession(const std::wstring& path, std::string& error) {
    if (!fileLoaded_) { error = "abre un archivo antes de guardar una sesion"; return false; }
    try {
        njson session;
        session["schemaVersion"] = 1;
        session["target"] = std::string(loadedPath_.begin(), loadedPath_.end());
        session["launchArgs"] = launchArgs_;
        session["minStringLength"] = minStrLen_;
        session["eventBreakMask"] = debugger_.eventBreakMask();
        const uint64_t runtimeBase = debugger_.imageBase() ? debugger_.imageBase() : pe_.imageBase();
        const uint64_t runtimeEnd = runtimeBase + pe_.sizeOfImage();
        auto addressRef = [&](uint64_t address) {
            njson ref;
            if (address >= runtimeBase && address < runtimeEnd) ref["rva"] = address - runtimeBase;
            else ref["address"] = address;
            return ref;
        };
        for (const auto& bp : debugger_.breakpoints()) if (!bp.oneShot) {
            njson item = addressRef(bp.address);
            item["label"] = bp.label; item["enabled"] = bp.enabled;
            item["breakOnHit"] = bp.breakOnHit; item["condition"] = bp.condition;
            item["logOnly"] = bp.logOnly;
            session["breakpoints"].push_back(std::move(item));
        }
        for (const auto& bp : debugger_.hwBreakpoints()) {
            njson item = addressRef(bp.address);
            item["label"] = bp.label; item["type"] = bp.type; item["len"] = bp.len;
            session["hardwareBreakpoints"].push_back(std::move(item));
        }
        for (const auto& bp : debugger_.exceptionBreaks()) {
            njson item = addressRef(bp.address);
            item["code"] = bp.code; item["label"] = bp.label; item["enabled"] = bp.enabled;
            session["exceptionBreakpoints"].push_back(std::move(item));
        }
        for (const auto& [address, text] : labels_)
            session["labels"].push_back({{"address", address}, {"text", text}});
        for (const auto& [address, text] : comments_)
            session["comments"].push_back({{"address", address}, {"text", text}});

        std::ofstream file(path, std::ios::binary | std::ios::trunc);
        if (!file) { error = "no se pudo crear el archivo de sesion"; return false; }
        file << session.dump(1);
        return true;
    } catch (const std::exception& e) {
        error = e.what(); return false;
    }
}

bool App::loadSession(const std::wstring& path, std::string& error) {
    if (debugger_.state() != DbgState::Idle) { error = "deten la sesion activa antes de cargar otra"; return false; }
    try {
        std::ifstream file(path, std::ios::binary);
        if (!file) { error = "no se pudo abrir el archivo de sesion"; return false; }
        const njson session = njson::parse(file);
        if (session.value("schemaVersion", 0) != 1) { error = "formato de sesion incompatible"; return false; }
        const std::string target = session.value("target", "");
        if (target.empty()) { error = "la sesion no incluye archivo objetivo"; return false; }
        minStrLen_ = session.value("minStringLength", size_t{4});
        if (minStrLen_ < 2) minStrLen_ = 2;
        openFile(std::wstring(target.begin(), target.end()));
        if (!fileLoaded_) { error = openError_; return false; }
        std::snprintf(launchArgs_, sizeof(launchArgs_), "%s", session.value("launchArgs", "").c_str());
        debugger_.setEventBreakMask(session.value("eventBreakMask", uint32_t{0}));

        for (const auto& bp : debugger_.breakpoints()) debugger_.removeBreakpoint(bp.address);
        for (const auto& bp : debugger_.hwBreakpoints()) debugger_.removeHwBreakpoint(bp.address);
        for (const auto& bp : debugger_.exceptionBreaks()) debugger_.removeExceptionBreak(bp.id);
        auto restoreAddress = [&](const njson& item) -> uint64_t {
            return item.contains("rva") ? pe_.imageBase() + item.value("rva", uint64_t{0})
                                        : item.value("address", uint64_t{0});
        };
        for (const auto& item : session.value("breakpoints", njson::array())) {
            const uint64_t address = restoreAddress(item);
            if (!address) continue;
            debugger_.addBreakpoint(address, item.value("label", "session"));
            debugger_.toggleBreakpoint(address, item.value("enabled", true));
            debugger_.setBreakpointHitTarget(address, item.value("breakOnHit", uint64_t{0}));
            debugger_.setBreakpointCondition(address, item.value("condition", ""));
            debugger_.setBreakpointLogOnly(address, item.value("logOnly", false));
        }
        for (const auto& item : session.value("hardwareBreakpoints", njson::array())) {
            const uint64_t address = restoreAddress(item);
            if (address) debugger_.addHwBreakpoint(address, item.value("type", 0), item.value("len", 1), item.value("label", "session"));
        }
        for (const auto& item : session.value("exceptionBreakpoints", njson::array())) {
            const uint32_t id = debugger_.addExceptionBreak(item.value("code", uint32_t{0}),
                                                              restoreAddress(item), item.value("label", "session"));
            debugger_.toggleExceptionBreak(id, item.value("enabled", true));
        }
        labels_.clear(); comments_.clear();
        for (const auto& item : session.value("labels", njson::array())) labels_[item.value("address", uint64_t{0})] = item.value("text", "");
        for (const auto& item : session.value("comments", njson::array())) comments_[item.value("address", uint64_t{0})] = item.value("text", "");
        saveAnnotations();
        return true;
    } catch (const std::exception& e) {
        error = e.what(); return false;
    }
}

std::string App::buildAnalysisReport() {
    std::ostringstream out;
    out << "# Informe de analisis - DebuggerJ++\n\n";
    out << "## Objetivo\n\n";
    out << "- Ruta: `" << std::string(loadedPath_.begin(), loadedPath_.end()) << "`\n";
    out << "- Arquitectura: " << (pe_.is64Bit() ? "x64" : "x86") << "\n";
    out << "- Image base preferida: `0x" << hex64(pe_.imageBase()) << "`\n";
    out << "- EntryPoint: `0x" << hex64(pe_.entryPointVA()) << "`\n";
    out << "- Entropia global: " << pe_.overallEntropy() << " / 8.0\n\n";
    out << "## Estado de depuracion\n\n";
    const char* state = dbgState_ == DbgState::Paused ? "pausado" : dbgState_ == DbgState::Running ? "ejecutando" :
                        dbgState_ == DbgState::Launching ? "lanzando" : dbgState_ == DbgState::Exited ? "terminado" : "inactivo";
    out << "- Estado: " << state << "\n";
    out << "- Eventos configurados: mascara `" << debugger_.eventBreakMask() << "` (1=hilo nuevo, 2=fin hilo, 4=carga DLL, 8=descarga DLL)\n";
    if (dbgState_ == DbgState::Paused) {
        const Registers r = debugger_.registers();
        out << "- IP: `0x" << hex64(r.rip) << "`  Stack: `0x" << hex64(r.rsp) << "`\n";
    }
    out << "\n## Secciones\n\n|Nombre|RVA|Tamano virtual|Entropia|Permisos|\n|---|---:|---:|---:|---|\n";
    for (const auto& section : pe_.sections())
        out << "|" << section.name << "|0x" << std::hex << section.virtualAddress << std::dec << "|0x" << std::hex
            << section.virtualSize << std::dec << "|" << section.entropy << "|" << (section.executable() ? "X" : "")
            << (section.writable() ? "W" : "R") << "|\n";
    out << "\n## Detecciones de packer/proteccion\n\n";
    if (packerMatches_.empty()) out << "Sin detecciones activas.\n";
    else for (const auto& item : packerMatches_) out << "- " << item.name << " (" << item.confidence << "%, " << item.source << ")\n";
    out << "\n## Breakpoints\n\n";
    for (const auto& bp : debugger_.breakpoints()) if (!bp.oneShot)
        out << "- Software `0x" << hex64(bp.address) << "` hits=" << bp.hits << " parar_en=" << bp.breakOnHit
            << (bp.condition.empty() ? "" : " condicion=`" + bp.condition + "`")
            << (bp.logOnly ? " solo-log" : "") << "\n";
    for (const auto& bp : debugger_.memoryBreakpoints())
        out << "- Memoria `0x" << hex64(bp.address) << "` size=0x" << std::hex << bp.size << std::dec
            << " tipo=" << bp.type << " hits=" << bp.hits << "\n";
    out << "\n## Notas\n\n";
    out << "Este informe describe la sesion y no prueba por si solo comportamiento malicioso. "
           "Ejecuta muestras exclusivamente en una VM aislada.\n";
    return out.str();
}

bool App::saveAnalysisReport(const std::wstring& path, std::string& error) {
    if (!fileLoaded_) { error = "abre un archivo antes de exportar el informe"; return false; }
    std::ofstream file(path, std::ios::binary | std::ios::trunc);
    if (!file) { error = "no se pudo crear el informe"; return false; }
    file << buildAnalysisReport();
    if (!file) { error = "no se pudo escribir el informe completo"; return false; }
    return true;
}

void App::saveSessionDialog() {
    wchar_t path[MAX_PATH] = L"analysis.dbgjsession";
    OPENFILENAMEW ofn{}; ofn.lStructSize = sizeof(ofn); ofn.lpstrFile = path; ofn.nMaxFile = MAX_PATH;
    ofn.lpstrFilter = L"DebuggerJ++ Session\0*.dbgjsession\0Todos\0*.*\0";
    ofn.lpstrDefExt = L"dbgjsession"; ofn.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST;
    if (!GetSaveFileNameW(&ofn)) return;
    std::string error;
    pushLog(saveSession(path, error) ? "Sesion guardada." : "No se pudo guardar sesion: " + error);
}

void App::loadSessionDialog() {
    wchar_t path[MAX_PATH] = {};
    OPENFILENAMEW ofn{}; ofn.lStructSize = sizeof(ofn); ofn.lpstrFile = path; ofn.nMaxFile = MAX_PATH;
    ofn.lpstrFilter = L"DebuggerJ++ Session\0*.dbgjsession\0Todos\0*.*\0";
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
    if (!GetOpenFileNameW(&ofn)) return;
    std::string error;
    pushLog(loadSession(path, error) ? "Sesion cargada." : "No se pudo cargar sesion: " + error);
}

void App::exportReportDialog() {
    wchar_t path[MAX_PATH] = L"analysis-report.md";
    OPENFILENAMEW ofn{}; ofn.lStructSize = sizeof(ofn); ofn.lpstrFile = path; ofn.nMaxFile = MAX_PATH;
    ofn.lpstrFilter = L"Markdown\0*.md\0Todos\0*.*\0";
    ofn.lpstrDefExt = L"md"; ofn.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST;
    if (GetSaveFileNameW(&ofn)) {
        std::string error;
        if (saveAnalysisReport(path, error)) pushLog("Informe exportado: " + std::string(path, path + wcslen(path)));
        else pushLog("Exportar informe: " + error);
    }
}

// ---------------------------------------------------------------------------
// Render principal
// ---------------------------------------------------------------------------
void App::render() {
    // Sincronizar estado del debugger (polling: evita tocar ImGui desde otro hilo)
    DbgState s = debugger_.state();
    if (s != dbgState_) {
        dbgState_ = s;
        if (s == DbgState::Paused) {
            regs_ = debugger_.registers();
            currentIp_ = regs_.ip();
            curModule_ = moduleNameAt(currentIp_);
            refreshLiveDisassembly(currentIp_);
            memMap_ = debugger_.memoryMap();
            if (debugger_.foundOEP()) pluginOEP_ = debugger_.foundOEP();
            refreshWatches();
            runBreakpointAction(currentIp_);   // M3: accion al golpear un BP
            // Re-aplicar anti-anti-debug si esta activado (el malware puede re-chequear)
            if (antiReapply_ && antiActive_) {
                std::string lg;
                applyAntiAntiDebug(debugger_, debugger_.is64(), antiOpt_, lg);
            }
        }
    }

    drainMcpQueue();

    // M11: hot-reload de plugins (cada ~120 frames si esta activado).
    if (pluginAutoReload_ && ++pluginCheckCounter_ >= 120) {
        pluginCheckCounter_ = 0;
        uint64_t now = pluginsDirStamp();
        if (now != pluginsStamp_) { loadExternalPlugins(); pushLog("Plugins recargados (cambio en disco)."); }
    }

    drawMenuBar();
    drawToolbar();
    if (visible("CPU"))                  drawCpuPanel();
    if (visible("Breakpoints"))          drawBreakpointsPanel();
    if (visible("Memoria"))              drawMemoryPanel();
    if (visible("Strings & Busqueda"))   drawStringsPanel();
    if (visible("Modulos & Simbolos"))   drawModulesPanel();
    if (visible("Packers / Proteccion")) drawPackerPanel();
    if (visible("Excepciones"))          drawExceptionsPanel();
    if (visible("Call stack"))           drawCallStackPanel();
    if (visible("Executable modules"))   drawExecModulesPanel();
    if (visible("Referencias"))          drawReferencesPanel();
    if (visible("Analysis"))             drawAnalysisPanel();
    if (visible("Run trace"))            drawTracePanel();
    if (visible("Plugins"))              drawPluginsPanel();
    if (visible("MCP Log"))              drawMcpLogPanel();
    if (visible("Log"))                  drawLogPanel();
    if (visible("IA"))                   drawAiPanel();
    if (visible("Code"))                 drawCodePanel();
    if (visible("Command"))              drawCommandBar();
    if (visible("Watch"))                drawWatchPanel();
    if (visible("Struct"))               drawStructPanel();
    if (showSearchResults_)              drawSearchResultsPanel();
    if (showOptions_)                    drawOptionsWindow();
    if (showHelp_)                       drawHelpWindow();
    if (showAttach_)                     drawAttachWindow();

    drawAddCustomPopup();
    drawStatusBar();

    applyMagneticSnap();   // imantacion de ventanas (al final, tras el update de movimiento)
}

// ---------------------------------------------------------------------------
// Gestion de ventanas: mosaico + layouts personalizados
// ---------------------------------------------------------------------------
std::vector<const char*> App::managedWindows() {
    return {
        "CPU",
        "Breakpoints", "Memoria", "Strings & Busqueda", "Modulos & Simbolos",
        "Call stack", "Executable modules", "Referencias", "Analysis", "Run trace",
        "Packers / Proteccion", "Excepciones", "Plugins", "MCP Log", "Log", "IA", "Code",
        "Command", "Watch", "Struct"
    };
}

static std::string layoutsFilePath() {
    wchar_t exe[MAX_PATH] = {0};
    GetModuleFileNameW(nullptr, exe, MAX_PATH);
    std::wstring w(exe);
    auto pos = w.find_last_of(L"\\/");
    std::wstring dir = (pos == std::wstring::npos) ? L"." : w.substr(0, pos);
    std::wstring path = dir + L"\\layouts.txt";
    return std::string(path.begin(), path.end());
}

void App::arrangeWindows() {
    const ImGuiViewport* vp = ImGui::GetMainViewport();
    float top   = vp->WorkPos.y + toolbarHeight_ + 4;
    float left  = vp->WorkPos.x;
    float availW = vp->WorkSize.x;
    float availH = vp->WorkSize.y - toolbarHeight_ - 4;

    auto names = managedWindows();
    int n = (int)names.size();
    int cols = (int)std::ceil(std::sqrt((double)n));
    if (cols < 1) cols = 1;
    int rows = (int)std::ceil((double)n / cols);
    float cw = availW / cols;
    float ch = availH / rows;

    for (int i = 0; i < n; ++i) {
        int r = i / cols, c = i % cols;
        ImGui::SetWindowCollapsed(names[i], false);
        ImGui::SetWindowPos(names[i], ImVec2(left + c * cw, top + r * ch));
        ImGui::SetWindowSize(names[i], ImVec2(cw - 4, ch - 4));
    }
}

// Snapping magnetico: mientras se arrastra una ventana, si un borde queda a pocos
// pixeles de otra ventana gestionada o del borde del area de trabajo, la "pega".
// Se aplica al final del frame (tras el update de movimiento de ImGui), asi que la
// ventana se ve imantada cada frame que el cursor este dentro del umbral.
void App::applyMagneticSnap() {
    if (!magneticSnap_) return;
    ImGuiContext* g = ImGui::GetCurrentContext();
    if (!g || !g->MovingWindow) return;
    if (!ImGui::IsMouseDown(ImGuiMouseButton_Left)) return;

    ImGuiWindow* mv = g->MovingWindow->RootWindow ? g->MovingWindow->RootWindow : g->MovingWindow;
    const float SNAP = 14.0f;   // umbral de imantacion en pixeles

    ImVec2 p = mv->Pos, s = mv->Size;
    float edgesX[2] = { p.x, p.x + s.x };   // izquierda, derecha
    float edgesY[2] = { p.y, p.y + s.y };   // arriba, abajo
    float bestDX = SNAP + 1.0f, bestDY = SNAP + 1.0f, offX = 0.0f, offY = 0.0f;

    auto consider = [](float mvEdge, float otherEdge, float& bestD, float& off) {
        float d = fabsf(mvEdge - otherEdge);
        if (d < bestD) { bestD = d; off = otherEdge - mvEdge; }
    };

    // Bordes del area de trabajo (para pegar a los bordes de la pantalla).
    const ImGuiViewport* vp = ImGui::GetMainViewport();
    float wsX[2] = { vp->WorkPos.x, vp->WorkPos.x + vp->WorkSize.x };
    float wsY[2] = { vp->WorkPos.y, vp->WorkPos.y + vp->WorkSize.y };
    for (float me : edgesX) for (float oe : wsX) consider(me, oe, bestDX, offX);
    for (float me : edgesY) for (float oe : wsY) consider(me, oe, bestDY, offY);

    // Bordes de las demas ventanas gestionadas visibles.
    for (auto nm : managedWindows()) {
        ImGuiWindow* w = ImGui::FindWindowByName(nm);
        if (!w || w == mv || !w->WasActive || w->Collapsed) continue;
        float wx[2] = { w->Pos.x, w->Pos.x + w->Size.x };
        float wy[2] = { w->Pos.y, w->Pos.y + w->Size.y };
        for (float me : edgesX) for (float oe : wx) consider(me, oe, bestDX, offX);
        for (float me : edgesY) for (float oe : wy) consider(me, oe, bestDY, offY);
    }

    ImVec2 np = p;
    if (bestDX <= SNAP) np.x = p.x + offX;
    if (bestDY <= SNAP) np.y = p.y + offY;
    if (np.x != p.x || np.y != p.y) mv->Pos = np;   // imanta esta ventana este frame
}

void App::captureLayout(const std::string& name) {
    WinLayout L; L.name = name;
    for (auto nm : managedWindows()) {
        ImGuiWindow* w = ImGui::FindWindowByName(nm);
        if (w) L.wins.push_back({nm, w->Pos.x, w->Pos.y, w->Size.x, w->Size.y});
    }
    for (auto& e : customLayouts_) if (e.name == name) { e = L; saveLayouts(); return; }
    customLayouts_.push_back(L);
    saveLayouts();
    pushLog("Layout guardado: " + name);
}

void App::applyLayout(const WinLayout& L) {
    for (auto& g : L.wins) {
        ImGui::SetWindowCollapsed(g.name.c_str(), false);
        ImGui::SetWindowPos(g.name.c_str(), ImVec2(g.x, g.y));
        ImGui::SetWindowSize(g.name.c_str(), ImVec2(g.w, g.h));
    }
}

void App::saveLayouts() {
    std::ofstream f(layoutsFilePath());
    if (!f) return;
    for (auto& L : customLayouts_) {
        f << "[" << L.name << "]\n";
        for (auto& g : L.wins)
            f << g.name << "|" << g.x << "|" << g.y << "|" << g.w << "|" << g.h << "\n";
    }
}

void App::loadLayouts() {
    customLayouts_.clear();
    std::ifstream f(layoutsFilePath());
    if (!f) return;
    std::string line;
    WinLayout cur; bool have = false;
    auto flush = [&]() { if (have && !cur.name.empty()) customLayouts_.push_back(cur); cur = WinLayout(); have = false; };
    while (std::getline(f, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty()) continue;
        if (line.front() == '[') { flush(); cur.name = line.substr(1, line.find(']') - 1); have = true; }
        else {
            std::stringstream ss(line); std::string tok; WinGeom g; int idx = 0;
            while (std::getline(ss, tok, '|')) {
                switch (idx) {
                    case 0: g.name = tok; break;
                    case 1: g.x = (float)atof(tok.c_str()); break;
                    case 2: g.y = (float)atof(tok.c_str()); break;
                    case 3: g.w = (float)atof(tok.c_str()); break;
                    case 4: g.h = (float)atof(tok.c_str()); break;
                }
                idx++;
            }
            if (idx >= 5) cur.wins.push_back(g);
        }
    }
    flush();
}

bool App::visible(const char* name) {
    auto it = winVisible_.find(name);
    return it == winVisible_.end() ? true : it->second;
}
void App::ensureVisibilityKeys() {
    for (auto nm : managedWindows())
        if (winVisible_.find(nm) == winVisible_.end()) winVisible_[nm] = true;
}
static std::string visFilePath() {
    wchar_t exe[MAX_PATH] = {0};
    GetModuleFileNameW(nullptr, exe, MAX_PATH);
    std::wstring w(exe);
    auto pos = w.find_last_of(L"\\/");
    std::wstring dir = (pos == std::wstring::npos) ? L"." : w.substr(0, pos);
    std::wstring path = dir + L"\\windows_visible.txt";
    return std::string(path.begin(), path.end());
}
void App::saveVisibility() {
    std::ofstream f(visFilePath());
    if (!f) return;
    for (auto& [name, v] : winVisible_) f << name << "|" << (v ? 1 : 0) << "\n";
}
void App::loadVisibility() {
    std::ifstream f(visFilePath());
    if (!f) return;
    std::string line;
    while (std::getline(f, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        auto bar = line.find_last_of('|');
        if (bar == std::string::npos) continue;
        std::string name = line.substr(0, bar);
        bool v = (line.substr(bar + 1) == "1");
        winVisible_[name] = v;
    }
}

void App::drawWindowMenu() {
    if (!ImGui::BeginMenu("Window")) return;

    if (ImGui::MenuItem("Arrange Windows")) arrangeWindows();
    ImGui::MenuItem("Snap magnetico", nullptr, &magneticSnap_);

    if (ImGui::BeginMenu("Show")) {
        ensureVisibilityKeys();
        for (auto nm : managedWindows()) {
            bool* p = &winVisible_[nm];
            if (ImGui::MenuItem(nm, nullptr, p)) saveVisibility();
        }
        ImGui::Separator();
        if (ImGui::MenuItem("Mostrar todas")) {
            for (auto& [k, v] : winVisible_) v = true;
            saveVisibility();
        }
        ImGui::EndMenu();
    }

    if (ImGui::BeginMenu("Custom")) {
        if (ImGui::MenuItem("Add to custom")) openAddCustom_ = true;
        ImGui::Separator();
        if (customLayouts_.empty()) {
            ImGui::TextDisabled("(sin layouts guardados)");
        } else {
            int deleteIdx = -1;
            for (int i = 0; i < (int)customLayouts_.size(); ++i) {
                ImGui::PushID(i);
                if (ImGui::MenuItem(customLayouts_[i].name.c_str())) applyLayout(customLayouts_[i]);
                if (ImGui::BeginPopupContextItem("##del")) {
                    ImGui::TextDisabled("%s", customLayouts_[i].name.c_str());
                    ImGui::Separator();
                    if (ImGui::MenuItem("Delete")) deleteIdx = i;
                    ImGui::EndPopup();
                }
                ImGui::PopID();
            }
            if (deleteIdx >= 0) {
                pushLog("Layout borrado: " + customLayouts_[deleteIdx].name);
                customLayouts_.erase(customLayouts_.begin() + deleteIdx);
                saveLayouts();
            }
        }
        ImGui::EndMenu();
    }
    ImGui::EndMenu();
}

void App::drawAddCustomPopup() {
    if (openAddCustom_) {
        ImGui::OpenPopup("Guardar layout");
        openAddCustom_ = false;
        newLayoutName_[0] = '\0';
    }
    // Centrar el modal
    ImVec2 center = ImGui::GetMainViewport()->GetCenter();
    ImGui::SetNextWindowPos(center, ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));
    if (ImGui::BeginPopupModal("Guardar layout", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
        ImGui::TextUnformatted("Nombre para esta configuracion de ventanas:");
        ImGui::SetNextItemWidth(260);
        bool enter = ImGui::InputText("##ln", newLayoutName_, sizeof(newLayoutName_),
                                      ImGuiInputTextFlags_EnterReturnsTrue);
        ImGui::Separator();
        bool ok = ImGui::Button("Guardar", ImVec2(120, 0)) || enter;
        if (ok && newLayoutName_[0]) { captureLayout(newLayoutName_); ImGui::CloseCurrentPopup(); }
        ImGui::SameLine();
        if (ImGui::Button("Cancelar", ImVec2(120, 0))) ImGui::CloseCurrentPopup();
        ImGui::EndPopup();
    }
}

void App::drawMenuBar() {
    if (ImGui::BeginMainMenuBar()) {
        if (ImGui::BeginMenu("Archivo")) {
            if (ImGui::MenuItem("Abrir .exe...")) {
                wchar_t file[MAX_PATH] = {0};
                OPENFILENAMEW ofn{}; ofn.lStructSize = sizeof(ofn);
                ofn.lpstrFilter = L"Ejecutables\0*.exe;*.dll;*.sys\0Todos\0*.*\0";
                ofn.lpstrFile = file; ofn.nMaxFile = MAX_PATH;
                ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
                if (GetOpenFileNameW(&ofn)) openFile(file);
            }
            if (ImGui::BeginMenu("Abrir reciente", !recentFiles_.empty())) {
                std::wstring pick;
                for (const auto& w : recentFiles_) {
                    std::string label = wToUtf8(w);
                    if (ImGui::MenuItem(label.c_str())) pick = w;
                }
                ImGui::Separator();
                if (ImGui::MenuItem("Limpiar lista")) { recentFiles_.clear(); saveRecent(); }
                ImGui::EndMenu();
                if (!pick.empty()) openFile(pick);
            }
            ImGui::Separator();
            if (ImGui::MenuItem("Attach a proceso (PID)...", nullptr, false, dbgState_ == DbgState::Idle)) showAttach_ = true;
            {
                bool canDetach = dbgState_ == DbgState::Running || dbgState_ == DbgState::Paused || dbgState_ == DbgState::Launching;
                if (ImGui::MenuItem("Detach (sin terminar)", nullptr, false, canDetach)) {
                    std::string error;
                    if (!debugger_.detach(error)) pushLog("Detach: " + error);
                    else pushLog("Detach solicitado; el proceso sigue ejecutando.");
                }
            }
            ImGui::Separator();
            if (ImGui::MenuItem("Guardar sesion...", nullptr, false, fileLoaded_)) saveSessionDialog();
            if (ImGui::MenuItem("Cargar sesion...", nullptr, false, dbgState_ == DbgState::Idle)) loadSessionDialog();
            if (ImGui::MenuItem("Exportar informe Markdown...", nullptr, false, fileLoaded_)) exportReportDialog();
            ImGui::Separator();
            if (ImGui::MenuItem("Cerrar", "Alt+F4")) {
                if (dbgState_ != DbgState::Idle) debugger_.detachAndStop();
                PostQuitMessage(0);
            }
            ImGui::EndMenu();
        }
        if (ImGui::BeginMenu("Depurar")) {
            if (ImGui::MenuItem("Lanzar bajo debug", "F9", false, fileLoaded_)) startDebugSession();
            if (ImGui::MenuItem("Adjuntar a PID...", nullptr, false, dbgState_ == DbgState::Idle)) showAttach_ = true;
            if (ImGui::MenuItem("Desadjuntar (sin terminar)", nullptr, false, dbgState_ == DbgState::Running || dbgState_ == DbgState::Paused || dbgState_ == DbgState::Launching)) {
                std::string error;
                if (!debugger_.detach(error)) pushLog("Desadjuntar: " + error);
            }
            if (ImGui::MenuItem("Detener", nullptr, false, dbgState_ != DbgState::Idle)) debugger_.stop();
            ImGui::Separator();
            bool follow = debugger_.followChildren();
            if (ImGui::MenuItem("Seguir procesos hijos", nullptr, follow, dbgState_ == DbgState::Idle))
                debugger_.setFollowChildren(!follow);
            ImGui::EndMenu();
        }
        if (ImGui::BeginMenu("Tools")) {
            if (ImGui::MenuItem("Options...")) {
                showOptions_ = true;
                optLoadDraft(aiConfig_.selected());
            }
            ImGui::EndMenu();
        }
        if (ImGui::BeginMenu("Help")) {
            if (ImGui::MenuItem("Basic")) { helpPage_ = 0; showHelp_ = true; }
            if (ImGui::MenuItem("MCP")) { helpPage_ = 1; showHelp_ = true; }
            if (ImGui::MenuItem("Plugins")) { helpPage_ = 2; showHelp_ = true; }
            if (ImGui::MenuItem("Roadmap")) { helpPage_ = 3; showHelp_ = true; }
            ImGui::EndMenu();
        }
        drawWindowMenu();
        // Estado a la derecha
        const char* st = "Idle";
        switch (dbgState_) {
            case DbgState::Launching: st = "Lanzando..."; break;
            case DbgState::Running:   st = "Ejecutando";  break;
            case DbgState::Paused:    st = "Pausado";     break;
            case DbgState::Exited:    st = "Terminado";   break;
            default: break;
        }
        ImGui::SameLine(ImGui::GetWindowWidth() - 340);
        ImGui::TextColored(dbgState_ == DbgState::Paused ? ImVec4(1,0.8f,0.2f,1) :
                           dbgState_ == DbgState::Running ? ImVec4(0.3f,1,0.3f,1) : ImVec4(0.7f,0.7f,0.7f,1),
                           "Estado: %s", st);
        if (fileLoaded_) { ImGui::SameLine(); ImGui::Text("| %s", pe_.is64Bit() ? "x64" : "x86"); }
        ImGui::EndMainMenuBar();
    }
}

void App::drawToolbar() {
    bool paused = (dbgState_ == DbgState::Paused);
    bool active = (dbgState_ != DbgState::Idle && dbgState_ != DbgState::Exited);

    // Toolbar fija anclada bajo la barra de menu, a todo lo ancho.
    const ImGuiViewport* vp = ImGui::GetMainViewport();
    ImGui::SetNextWindowPos(vp->WorkPos);
    ImGui::SetNextWindowSize(ImVec2(vp->WorkSize.x, 0));
    ImGuiWindowFlags flags = ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
                             ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoScrollbar |
                             ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoSavedSettings |
                             ImGuiWindowFlags_NoBringToFrontOnFocus;
    ImGui::Begin("##toolbar", nullptr, flags);

    // PLAY: lanzar si no hay sesion; continuar si esta pausado.
    ImGui::BeginDisabled(active && !paused);
    if (ImGui::Button(active ? "> Play" : "> Play (lanzar)", ImVec2(active ? 90 : 130, 30))) {
        if (!active) startDebugSession();
        else if (paused) debugger_.go();
    }
    ImGui::EndDisabled();
    if (ImGui::IsItemHovered()) ImGui::SetTooltip(active ? "Continuar (F9)" : "Lanzar bajo debug (F9)");

    ImGui::SameLine();
    ImGui::BeginDisabled(dbgState_ != DbgState::Running);
    if (ImGui::Button("|| Pause", ImVec2(90, 30))) debugger_.pause();
    ImGui::EndDisabled();

    ImGui::SameLine();
    ImGui::BeginDisabled(!active);
    if (ImGui::Button("[] Stop", ImVec2(80, 30))) debugger_.stop();
    ImGui::EndDisabled();

    ImGui::SameLine(); ImGui::TextUnformatted("|"); ImGui::SameLine();

    ImGui::BeginDisabled(!paused);
    if (ImGui::Button("-> Step Into", ImVec2(110, 30))) debugger_.stepInto();
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("Un paso, entrando a los call (F7)");
    ImGui::SameLine();
    if (ImGui::Button(">> Step Over", ImVec2(110, 30))) debugger_.stepOver();
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("Un paso, saltando los call (F8)");
    ImGui::SameLine();
    if (ImGui::Button("<- Step to Ret", ImVec2(120, 30))) debugger_.stepToRet();
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("Ejecuta hasta el 'ret' de la funcion actual (Ctrl+F9)");
    ImGui::EndDisabled();

    ImGui::SameLine(); ImGui::TextUnformatted("|"); ImGui::SameLine();
    ImGui::SetNextItemWidth(260);
    ImGui::InputTextWithHint("##args", "argumentos de linea de comandos", launchArgs_, sizeof(launchArgs_));

    // Atajos de teclado
    if (paused) {
        if (ImGui::IsKeyPressed(ImGuiKey_F7)) debugger_.stepInto();
        if (ImGui::IsKeyPressed(ImGuiKey_F8)) debugger_.stepOver();
        bool ctrl = ImGui::GetIO().KeyCtrl;
        if (ctrl && ImGui::IsKeyPressed(ImGuiKey_F9)) debugger_.stepToRet();
        else if (!ctrl && ImGui::IsKeyPressed(ImGuiKey_F9)) debugger_.go();
    }
    if (ImGui::IsKeyPressed(ImGuiKey_F9) && !active) startDebugSession();

    toolbarHeight_ = ImGui::GetWindowSize().y;
    ImGui::End();
}

void App::drawHelpWindow() {
    ImGui::SetNextWindowSize(ImVec2(760, 560), ImGuiCond_FirstUseEver);
    if (!ImGui::Begin("Help", &showHelp_)) { ImGui::End(); return; }
    if (ImGui::BeginTabBar("help_tabs")) {
        if (ImGui::BeginTabItem("Basic", nullptr, helpPage_ == 0 ? ImGuiTabItemFlags_SetSelected : 0)) {
            ImGui::TextWrapped("Guia basica de depuracion defensiva. Ejecuta muestras solo en una maquina virtual aislada, sin datos valiosos ni acceso a red.");
            ImGui::Separator();
            ImGui::TextUnformatted("Flujo recomendado");
            ImGui::BulletText("Archivo -> Abrir: analiza el PE estatico, secciones, imports, exports, strings y packers. La cache evita repetir esos escaneos.");
            ImGui::BulletText("CPU: navega con doble clic en calls, jumps, referencias y modulos. Las guias Flow a la izquierda de las direcciones muestran cada jmp/jz/jnz/etc. que cae dentro de la vista; punto = origen, flecha = destino, naranja = hacia abajo y azul = hacia arriba. Clic derecho sobre el jump -> Jump To abre su destino. El mismo menu permite agregar bookmarks.");
            ImGui::BulletText("Analyze this: analiza linealmente hasta un ret, guarda una funcion candidata, xrefs call/jump y loops por saltos hacia atras. Consulta Window -> Analysis para navegar esos resultados; se guardan en cache. No sustituye un CFG/decompilador completo.");
            ImGui::BulletText("Breakpoints: clic en la columna BP de CPU para software; usa el panel Breakpoints para hardware, excepciones y memoria. 'Parar en N' ignora los N-1 primeros hits.");
            ImGui::BulletText("Memory breakpoints: con el proceso pausado, elige acceso, escritura o ejecucion y un rango. Usan PAGE_GUARD como OllyDbg: Windows protege paginas completas (normalmente 4 KiB), asi que puede haber accesos vecinos. No se permiten sobre la pagina de pila actual ni sobre una pagina que ya use PAGE_GUARD.");
            ImGui::BulletText("Condiciones y acciones: un BP software acepta registros, hit/hits, &, | y comparadores; por ejemplo rax == 0, ecx & 1 != 0 o hit >= 5. Con 'solo log' registra la coincidencia y continua. Numeros en decimal o con prefijo 0x.");
            ImGui::BulletText("Excepciones incluye breakpoints de eventos: crear/terminar hilo y cargar/descargar DLL. Son utiles para observar carga dinamica e inyeccion.");
            ImGui::BulletText("Los breakpoints de la imagen principal se relocalizan automaticamente cuando ASLR cambia la base al lanzar o adjuntarse.");
            ImGui::BulletText("Play/F9 inicia o continua; F7 entra en calls; F8 los salta; Ctrl+F9 ejecuta hasta ret; Pause detiene una sesion activa.");
            ImGui::BulletText("Depurar -> Adjuntar a PID permite analizar un proceso existente. 'Desadjuntar' lo deja ejecutando sin DebuggerJ++; Detener finaliza la sesion. Requiere permisos suficientes y se recomienda usarlo solo en la VM de analisis.");
            ImGui::BulletText("Memoria, Stack y Dump muestran el proceso solo mientras esta pausado. Patch, NOP y Assemble modifican memoria viva.");
            ImGui::TextUnformatted("Paneles de analisis");
            ImGui::BulletText("Modulos & Simbolos: doble clic en una DLL o archivo para ver su desensamblado; consulta TLS, SEH, imports y exports.");
            ImGui::BulletText("Call stack usa StackWalk64/DbgHelp. Si Windows puede localizar un PDB, muestra simbolos y archivo:linea; de otro modo conserva las direcciones disponibles.");
            ImGui::BulletText("Strings y Busqueda: busca texto o hex con ?? como comodin. Packers muestra firmas y heuristicas.");
            ImGui::BulletText("Run trace registra ejecucion instruccion a instruccion; Call stack y Referencias ayudan a reconstruir el flujo. El boton 'Resumir con IA' envia una muestra de la traza al agente para que explique el flujo (bucles de descifrado, APIs tocadas).");
            ImGui::Separator();
            ImGui::TextColored(ImVec4(0.6f,0.85f,1,1), "Novedades (inspiradas en x64dbg)");
            ImGui::BulletText("Command (Window -> Command): barra de comandos hibrida. '?expr' evalua una expresion; 'cmd {args}' ejecuta una tool dbg_*; JSON crudo se envia tal cual. Marca 'Usar IA' para escribir en lenguaje natural y que el agente controle el debugger.");
            ImGui::BulletText("Watch (Window -> Watch): evalua expresiones en cada pausa. Ej: dword(esp+4), [eax], rip - mod.base(rip). Usa el motor de expresiones (hex por defecto; byte/word/dword/qword/ptr(a), registros, mod.base/size/fromname, dis.len, [mem], + - * / %% & | ^ ~ << >>).");
            ImGui::BulletText("Struct (Window -> Struct): aplica una definicion de campos (byte/word/dword/qword/ptr/string) a una direccion base (que admite expresiones) y muestra los valores leidos de memoria, con offsets automaticos.");
            ImGui::BulletText("CPU -> clic derecho -> Search for: 'All commands' busca una subcadena en todas las instrucciones; 'All intermodular calls' lista las llamadas a APIs de otros modulos (via IAT y thunks); 'Binary string' busca hex o texto. Resultados en la ventana Search results (doble clic para navegar, 'Copiar todo').");
            ImGui::BulletText("Archivo -> Attach a proceso / Detach: adjuntar por PID o desadjuntar dejando el proceso vivo (tambien en el menu Depurar y por MCP attach/detach).");
            ImGui::BulletText("Tools -> Options -> Simbolos: configura un symbol server (symsrv), ej 'srv*C:\\symbols*https://msdl.microsoft.com/download/symbols', para resolver nombres y mejorar el call stack. Se persiste y aplica en la proxima sesion.");
            ImGui::BulletText("MCP Log: cachea todo a mcp_log_cache.txt; botones Load cache, Copy to clipboard, y el texto es seleccionable (Ctrl+C).");
            ImGui::BulletText("Breakpoints inteligentes (M3): CPU -> clic derecho -> Breakpoints -> 'Accion al golpear'. La accion puede ser 'ai:<pregunta>' (consulta al agente), 'cmd {args}' (tool dbg_*) o JSON crudo; se ejecuta cada vez que el BP pausa. Tambien por MCP: set_bp con 'action'.");
            ImGui::BulletText("Depurar -> Seguir procesos hijos (M7): lanza con DEBUG_PROCESS; los procesos hijos se detectan y reportan (evento create_process_child) sin colgar la sesion. Util para malware que se relanza o inyecta. El following completo (cambiar de target) aun no esta.");
            ImGui::BulletText("Plugins -> Hot-reload (M11): recarga los plugins automaticamente al detectar cambios en la carpeta plugins/.");
            ImGui::BulletText("--headless (M10): oculta la ventana y deja el MCP corriendo para automatizacion/batch. --noauth arranca el MCP sin token.");
            ImGui::BulletText("Snap magnetico (Window -> Snap magnetico): al arrastrar una ventana cerca de otra o del borde de la pantalla, se pega por imantacion (umbral 14 px). Desactivable desde el menu.");
            ImGui::BulletText("Archivo -> Guardar/Cargar sesion conserva el objetivo, argumentos, anotaciones y breakpoints; las direcciones de la imagen principal se guardan como RVA. Los memory breakpoints no se guardan: dependen de paginas validas de la ejecucion actual.");
            ImGui::BulletText("Archivo -> Exportar informe Markdown genera un resumen reproducible de PE, secciones, detecciones, estado y breakpoints. Por MCP, report devuelve el texto y export_report lo guarda en una ruta indicada.");
            ImGui::TextDisabled("Las anotaciones se guardan en la cache de analisis. Consulta MCP y Plugins para automatizacion y extensiones.");
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("MCP", nullptr, helpPage_ == 1 ? ImGuiTabItemFlags_SetSelected : 0)) {
            ImGui::TextWrapped("Model Context Protocol (MCP) permite que Claude, ChatGPT/OpenAI u otro cliente compatible controle esta instancia del debugger mediante tools.");
            ImGui::Separator();
            ImGui::TextUnformatted("Inicio");
            ImGui::BulletText("Plugins -> MCP Control -> Activar MCP. Por defecto escucha en 127.0.0.1:8377 y crea un token aleatorio de sesion.");
            ImGui::BulletText("Copia el token a la variable DBGJPP_TOKEN del cliente MCP. Sin token, la app rechaza todo comando.");
            ImGui::BulletText("Bypass: la casilla 'aceptar comandos SIN token' (o --noauth por CLI) desactiva la autenticacion. Comodo para uso local, pero cualquiera que alcance el puerto controla el debugger: usar solo en 127.0.0.1 o red de confianza.");
            ImGui::BulletText("Elige permiso: Solo lectura, Control de sesion o Modificacion. Bind 0.0.0.0 solo para WSL/red de confianza.");
            ImGui::BulletText("Registra mcp/server.mjs en tu cliente MCP. Consulta mcp/README.md para comandos exactos.");
            ImGui::TextUnformatted("Tools principales");
            ImGui::BulletText("Sesion: status, open, attach, detach, launch, restart, go, pause, step_into, step_over, step_to_ret y stop. detach solo libera un Attach; stop termina el proceso.");
            ImGui::BulletText("Informe: report genera Markdown sin escribir disco; export_report guarda Markdown y por ello requiere nivel Modificacion.");
            ImGui::BulletText("Control: set_bp (break_on_hit, condition y log_only), set_hwbp, set_membp, breakpoints de excepcion y set_event_breaks requieren Control de sesion. set_membp requiere pausa; type=0 acceso, 1 escritura, 8 ejecucion.");
            ImGui::BulletText("Analisis: disasm, analyze_code, list_functions/xrefs/loops, bookmarks, modules, sections, imports, exports, symbol/source, stack, call_stack, mem_map y find_refs.");
            ImGui::BulletText("Estado: get_regs, read_mem, search_hex, packers, tls, seh, run_trace y get_trace.");
            ImGui::BulletText("Expresiones: eval evalua una expresion (hex por defecto; byte/dword/ptr(a), registros, mod.base/fromname, dis.len, [mem]). Solo lectura.");
            ImGui::BulletText("Simbolos: symsrv configura la ruta del symbol server (requiere nivel Modificacion). Ej path 'srv*C:\\symbols*https://msdl.microsoft.com/download/symbols'.");
            ImGui::BulletText("Modificacion: set_reg, write_mem, assemble, patch, nop, dump, anti-debug, sesiones y plugins. Requieren el nivel Modificacion.");
            ImGui::BulletText("Plugins: plugin_list, plugin_reload y plugin_run; las acciones DLL se publican como tools dinamicas dbg_plugin_<plugin>_<accion>.");
            ImGui::TextDisabled("Los nombres reales enviados por MCP llevan el prefijo dbg_. El log MCP muestra solicitudes y respuestas; no comparte el token.");
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Plugins", nullptr, helpPage_ == 2 ? ImGuiTabItemFlags_SetSelected : 0)) {
            ImGui::TextWrapped("Los plugins viven en la carpeta plugins junto al ejecutable. Los JSON orquestan comandos existentes; las DLL nativas pueden aportar logica nueva y tools MCP.");
            ImGui::Separator();
            ImGui::TextUnformatted("Plugin JSON");
            ImGui::TextWrapped("Define id, name, version, actions[]. Cada accion tiene id, label, command, args e input_schema opcional. El ejemplo esta en plugins/example-analysis.json.");
            ImGui::TextUnformatted("Plugin DLL");
            ImGui::TextWrapped("Incluye sdk/DebuggerJppPluginApi.h y exporta DebuggerJppPluginGetApiVersion, DebuggerJppPluginGetInfo y DebuggerJppPluginRun. GetInfo devuelve el manifiesto JSON; Run recibe accion, argumentos JSON y DbgPluginHostApi.");
            ImGui::BulletText("host.execute_json(command,args_json,...) llama a las funciones del debugger y devuelve JSON.");
            ImGui::BulletText("host.log(message) agrega una entrada al Log. No conserves punteros del host despues de Run.");
            ImGui::BulletText("Compila x64, usa ABI version 1 y no pases STL a traves de la frontera DLL.");
            ImGui::TextColored(ImVec4(1,0.7f,0.25f,1), "Seguridad: habilitar una DLL ejecuta codigo nativo con tus permisos. Activa solo DLLs confiables.");
            ImGui::TextDisabled("Plantilla y esquema completo: docs/PLUGINS.md. Recarga desde Plugins o con dbg_plugin_reload.");
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Roadmap", nullptr, helpPage_ == 3 ? ImGuiTabItemFlags_SetSelected : 0)) {
            ImGui::TextWrapped("Estado real del proyecto. Esta pagina distingue funciones implementadas de trabajo pendiente para que una IA o analista no asuma capacidades inexistentes.");
            ImGui::Separator();
            ImGui::TextUnformatted("Disponible ahora");
            ImGui::BulletText("Depuracion x86/x64: lanzar, adjuntar, desadjuntar sin terminar, pausar, continuar, step into/over/to-ret, registros, memoria, parches y ensamblado.");
            ImGui::BulletText("Breakpoints software con condicion/hits/solo-log, hardware DR0-DR3, excepciones, memoria PAGE_GUARD y eventos de hilos/DLL.");
            ImGui::BulletText("PE, strings, packers, imports/exports, TLS/SEH, funciones/xrefs/loops/bookmarks persistentes, trazas, modulos, StackWalk64, simbolos y fuente/linea PDB cuando DbgHelp los encuentra.");
            ImGui::BulletText("IA integrada y MCP autenticado por token/permisos; plugins JSON/DLL con acciones MCP dinamicas; cache y sesiones.");
            ImGui::Separator();
            ImGui::TextUnformatted("Pendiente / limites conocidos");
            ImGui::BulletText("Procesos hijos: la sesion depura solo el proceso objetivo. Seguir y separar arboles de procesos aun no esta implementado.");
            ImGui::BulletText("Condiciones: no son un lenguaje completo; no admiten dereferencias de memoria, llamadas, scripts ni parentesis. Usa read_mem/MCP para inspecciones complejas.");
            ImGui::BulletText("PDB: hay symbol server configurable (Tools -> Options -> Simbolos, o MCP symsrv) con soporte symsrv/HTTP; la descarga/cache la gestiona DbgHelp segun el path indicado.");
            ImGui::BulletText("Call stack: StackWalk64 mejora la cadena de frames, pero malware, optimizaciones, stack pivoting o simbolos ausentes pueden impedir una pila completa.");
            ImGui::BulletText("Unpacking/IAT: dump, OEP e IAT son asistidos/experimentales; faltan reconstruccion PE robusta, relocaciones y validacion automatica del ejecutable resultante.");
            ImGui::BulletText("Analisis visual: existe lista de funciones/xrefs/loops, pero aun falta grafo CFG interactivo, decompilador nativo y comparacion de memoria/dumps. Code es interpretacion por IA, no un decompilador.");
            ImGui::BulletText("Automatizacion: faltan scripts Python/JavaScript aislados e informes JSON/SARIF estructurados. Ya se exporta un informe Markdown; el servidor MCP avisa tools/list_changed tras dbg_plugin_reload, pero una recarga hecha solo desde la UI requiere que el cliente vuelva a pedir tools/list.");
            ImGui::TextDisabled("Prioridad recomendada: procesos hijos y simbolos -> CFG/referencias -> unpacking robusto -> scripts e informes.");
            ImGui::Separator();
            ImGui::TextColored(ImVec4(0.6f,0.85f,1,1), "Mejoras inspiradas en x64dbg (ver docs/X64DBG_DEV_ANALISIS.md)");
            ImGui::BulletText("HECHO: motor de expresiones extensible (eval/watch/struct), command bar hibrida, Watch, Struct viewer, Search for, symbol server, resumen de traza con IA, IA como funcion de expresion (ai.classify), breakpoints con accion al golpear (M3), hot-reload de plugins (M11), modo headless (M10), MCP bypass sin token.");
            ImGui::BulletText("PARCIAL: seguir procesos hijos (M7): detecta y reporta hijos, falta following completo (cambiar de target). Bus de eventos CB_* (Fase 3): publica load_dll/unload_dll/exit_process/hijos al log; falta exponerlo a plugins/IA/MCP como suscripcion. Capa unica de comandos: IA/MCP/plugins comparten dbg_*, falta front-end de texto completo.");
            ImGui::BulletText("PENDIENTE: streaming de eventos por MCP (push); scriptdll/lenguaje de script; struct viewer con inferencia por IA; comparacion de dumps.");
            ImGui::EndTabItem();
        }
        ImGui::EndTabBar();
    }
    ImGui::End();
}

void App::drawAttachWindow() {
    ImGui::SetNextWindowSize(ImVec2(390, 130), ImGuiCond_Appearing);
    if (!ImGui::Begin("Adjuntar a proceso", &showAttach_, ImGuiWindowFlags_NoResize)) { ImGui::End(); return; }
    ImGui::TextWrapped("Introduce el PID decimal de un proceso existente. DebuggerJ++ intentara abrir su ejecutable para el analisis estatico antes de adjuntarse.");
    bool enter = ImGui::InputTextWithHint("PID", "ej. 1234", attachPid_, sizeof(attachPid_), ImGuiInputTextFlags_EnterReturnsTrue);
    ImGui::SameLine();
    if ((ImGui::Button("Adjuntar") || enter) && attachPid_[0]) {
        attachToProcess(static_cast<uint32_t>(strtoul(attachPid_, nullptr, 10)));
        attachPid_[0] = '\0';
        showAttach_ = false;
    }
    ImGui::SameLine();
    if (ImGui::Button("Cancelar")) showAttach_ = false;
    ImGui::TextDisabled("El proceso puede rechazar el attach por permisos, arquitectura o protecciones del sistema.");
    ImGui::End();
}

// ---------------------------------------------------------------------------
// CPU / desensamblado
// ---------------------------------------------------------------------------
// Ventana CPU compuesta estilo OllyDbg: desensamblado + registros (arriba) y
// volcado hex + pila (abajo), todo en una sola ventana con 4 sub-regiones.
void App::drawCpuPanel() {
    std::string title = "CPU";
    if (dbgState_ == DbgState::Paused && !curModule_.empty()) title += " - " + curModule_;
    title += "###CPU"; // ID estable aunque cambie el titulo visible
    ImGui::Begin(title.c_str());
    ImVec2 avail = ImGui::GetContentRegionAvail();
    float topH = avail.y * 0.58f;
    float leftW = avail.x * 0.62f;

    ImGui::BeginChild("cpu_disasm", ImVec2(leftW, topH), true);
    drawCpuContent();
    ImGui::EndChild();
    ImGui::SameLine();
    ImGui::BeginChild("cpu_regs", ImVec2(0, topH), true);
    drawRegistersContent();
    ImGui::EndChild();

    ImGui::BeginChild("cpu_dump", ImVec2(leftW, 0), true);
    drawHexDumpContent();
    ImGui::EndChild();
    ImGui::SameLine();
    ImGui::BeginChild("cpu_stack", ImVec2(0, 0), true);
    drawStackContent();
    ImGui::EndChild();

    ImGui::End();
}

void App::drawCpuContent() {
    ImGui::Text("%s   base 0x%s   %zu instrucciones",
                liveView_ ? "[memoria viva]" : "[archivo estatico]",
                hex64(disBase_).c_str(), insns_.size());
    ImGui::Separator();

    if (ImGui::BeginTable("dis", 5,
            ImGuiTableFlags_ScrollY | ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerV | ImGuiTableFlags_Resizable)) {
        ImGui::TableSetupColumn("BP",  ImGuiTableColumnFlags_WidthFixed, 24);
        ImGui::TableSetupColumn("Flow", ImGuiTableColumnFlags_WidthFixed, 46);
        ImGui::TableSetupColumn("Direccion", ImGuiTableColumnFlags_WidthFixed, 140);
        ImGui::TableSetupColumn("Bytes", ImGuiTableColumnFlags_WidthFixed, 150);
        ImGui::TableSetupColumn("Instruccion", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableHeadersRow();

        auto bps = debugger_.breakpoints();
        auto hasBp = [&](uint64_t a){ for (auto& b : bps) if (b.address == a) return true; return false; };

        // Guias de flujo estilo Olly: cada jump cuyo destino esta en la vista
        // recibe un carril vertical a la izquierda de la direccion y una flecha
        // al llegar a la instruccion destino. Se limita a seis carriles para que
        // una rutina muy ramificada siga siendo legible.
        struct FlowGuide { int from = 0, to = 0, lane = 0; };
        std::map<uint64_t, int> indexByAddress;
        for (int i = 0; i < (int)insns_.size(); ++i) indexByAddress[insns_[i].address] = i;
        std::vector<FlowGuide> flowGuides;
        std::array<int, 6> laneEnds{}; laneEnds.fill(-1);
        for (int i = 0; i < (int)insns_.size(); ++i) {
            const auto& branch = insns_[i];
            if (!branch.isJump || !branch.hasBranchTarget) continue;
            const auto target = indexByAddress.find(branch.branchTarget);
            if (target == indexByAddress.end() || target->second == i) continue;
            int lane = 0;
            const int spanEnd = std::max(i, target->second);
            for (; lane < (int)laneEnds.size(); ++lane) if (laneEnds[lane] < i) break;
            if (lane == (int)laneEnds.size()) lane = lane % (int)laneEnds.size();
            laneEnds[lane] = std::max(laneEnds[lane], spanEnd);
            flowGuides.push_back({i, target->second, lane});
        }

        ImGuiListClipper clipper;
        clipper.Begin((int)insns_.size());
        if (pendingScroll_ >= 0 && pendingScroll_ < (int)insns_.size())
            clipper.IncludeItemsByIndex(pendingScroll_, pendingScroll_ + 1);
        while (clipper.Step()) {
            for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; ++i) {
                const auto& in = insns_[i];
                ImGui::TableNextRow();
                bool isCur = (dbgState_ == DbgState::Paused && in.address == currentIp_);
                if (isCur) ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0, ImGui::GetColorU32(ImVec4(0.35f,0.28f,0.05f,1)));

                // Col BP: click para poner/quitar breakpoint
                ImGui::TableSetColumnIndex(0);
                bool bp = hasBp(in.address);
                ImGui::PushID(i);
                if (ImGui::Selectable(bp ? "*" : " ", selectedInsn_ == i, ImGuiSelectableFlags_SpanAllColumns)) {
                    if (bp) debugger_.removeBreakpoint(in.address);
                    else    debugger_.addBreakpoint(in.address);
                    selectedInsn_ = i;
                }
                // Menu contextual (clic derecho sobre el renglon)
                if (ImGui::BeginPopupContextItem("cpuctx")) {
                    selectedInsn_ = i;
                    ImGui::TextDisabled("0x%s", vaStr(in.address, dbgState_==DbgState::Paused?debugger_.is64():pe_.is64Bit()).c_str());
                    ImGui::Separator();
                    if (ImGui::BeginMenu("Breakpoints")) {
                        if (ImGui::MenuItem(bp ? "Quitar breakpoint" : "Agregar breakpoint")) {
                            if (bp) debugger_.removeBreakpoint(in.address);
                            else    debugger_.addBreakpoint(in.address, "cpu");
                        }
                        if (ImGui::MenuItem("Add breakpoint exception"))
                            debugger_.addExceptionBreak(0xC0000005, in.address, "desde CPU");
                        ImGui::Separator();
                        if (ImGui::BeginMenu("Add breakpoint exception (codigo)")) {
                            const uint32_t codes[] = {0, 0xC0000005, 0xC000001D, 0xC0000094, 0xC00000FD, 0xC0000096, 0x80000003};
                            for (uint32_t c : codes) {
                                char lbl[64]; std::snprintf(lbl, sizeof(lbl), "%08X  %s", c, exceptionName(c));
                                if (ImGui::MenuItem(lbl)) debugger_.addExceptionBreak(c, in.address, "desde CPU");
                            }
                            ImGui::EndMenu();
                        }
                        if (ImGui::MenuItem("Hardware BP (ejecucion)"))
                            debugger_.addHwBreakpoint(in.address, 0, 1, "cpu-hw");
                        if (ImGui::MenuItem("Accion al golpear... (M3)")) {   // BP inteligente
                            bpActionAddr_ = in.address;
                            auto ai = bpActions_.find(in.address);
                            std::snprintf(bpActionBuf_, sizeof(bpActionBuf_), "%s", ai==bpActions_.end()?"":ai->second.c_str());
                            openBpAction_ = true;
                        }
                        ImGui::Separator();
                        ImGui::BeginDisabled(dbgState_ != DbgState::Paused);
                        auto addMemory = [&](int type, const char* label) {
                            std::string error;
                            if (!debugger_.addMemoryBreakpoint(in.address, in.length ? in.length : 1, type, label, error))
                                pushLog("Memory BP: " + error);
                        };
                        if (ImGui::MenuItem("Memory BP: acceso (pagina)")) addMemory(0, "cpu-access");
                        if (ImGui::MenuItem("Memory BP: escritura (pagina)")) addMemory(1, "cpu-write");
                        if (ImGui::MenuItem("Memory BP: ejecucion (pagina)")) addMemory(8, "cpu-execute");
                        ImGui::EndDisabled();
                        ImGui::EndMenu();
                    }
                    if (ImGui::BeginMenu("Analyze")) {
                        if (ImGui::MenuItem("Analyze this", "Ctrl+A")) analyzeCodeAt(in.address);
                        ImGui::EndMenu();
                    }
                    const bool bookmarked = bookmarks_.find(in.address) != bookmarks_.end();
                    if (ImGui::MenuItem(bookmarked ? "Quitar bookmark" : "Agregar bookmark")) {
                        if (bookmarked) bookmarks_.erase(in.address);
                        else bookmarks_[in.address] = labels_.count(in.address) ? labels_[in.address] : "CPU";
                        saveAnnotations();
                    }
                    if (ImGui::MenuItem("Comentario...")) {
                        annotAddr_ = in.address; annotIsLabel_ = false;
                        auto it = comments_.find(in.address);
                        std::snprintf(annotBuf_, sizeof(annotBuf_), "%s", it==comments_.end()?"":it->second.c_str());
                        openAnnot_ = true;
                    }
                    if (ImGui::MenuItem("Etiqueta...")) {
                        annotAddr_ = in.address; annotIsLabel_ = true;
                        auto it = labels_.find(in.address);
                        std::snprintf(annotBuf_, sizeof(annotBuf_), "%s", it==labels_.end()?"":it->second.c_str());
                        openAnnot_ = true;
                    }
                    if (ImGui::MenuItem("Buscar referencias")) findReferences(in.address);
                    if (ImGui::BeginMenu("Search for")) {
                        if (ImGui::MenuItem("All commands...")) { searchCmdBuf_[0] = '\0'; openSearchCmd_ = true; }
                        if (ImGui::MenuItem("All intermodular calls")) searchIntermodularCalls();
                        if (ImGui::MenuItem("Binary string...")) { searchBinBuf_[0] = '\0'; openSearchBin_ = true; }
                        ImGui::EndMenu();
                    }
                    if (ImGui::MenuItem("Ensamblar (texto)...", nullptr, false, dbgState_==DbgState::Paused)) {
                        asmAddr_ = in.address; asmBuf_[0] = '\0'; asmError_.clear(); openAsmText_ = true;
                    }
                    if (ImGui::MenuItem("Patch bytes (hex)...", nullptr, false, dbgState_==DbgState::Paused)) {
                        asmAddr_ = in.address; asmBuf_[0] = '\0'; asmError_.clear(); openAsm_ = true;
                    }
                    if (ImGui::MenuItem("NOP instruccion", nullptr, false, dbgState_==DbgState::Paused)) {
                        std::vector<uint8_t> nops(in.length ? in.length : 1, 0x90);
                        debugger_.writeMemory(in.address, nops.data(), nops.size());
                        refreshLiveDisassembly(currentIp_);
                        pushLog("NOP x" + std::to_string(nops.size()) + " en 0x" + hex64(in.address));
                    }
                    if (ImGui::MenuItem("Copiar direccion"))
                        ImGui::SetClipboardText(("0x" + hex64(in.address)).c_str());
                    if (in.isJump && in.hasBranchTarget && ImGui::MenuItem("Jump To"))
                        gotoAddress(in.branchTarget);
                    ImGui::EndPopup();
                }
                if (i == pendingScroll_) { ImGui::SetScrollHereY(0.35f); pendingScroll_ = -1; }
                ImGui::PopID();

                ImGui::TableSetColumnIndex(1);
                const ImVec2 flowOrigin = ImGui::GetCursorScreenPos();
                const float flowHeight = ImGui::GetTextLineHeight();
                const float flowMidY = flowOrigin.y + flowHeight * 0.5f;
                const float flowWidth = ImGui::GetColumnWidth();
                ImDrawList* draw = ImGui::GetWindowDrawList();
                for (const auto& guide : flowGuides) {
                    const int first = std::min(guide.from, guide.to), last = std::max(guide.from, guide.to);
                    if (i < first || i > last) continue;
                    const float x = flowOrigin.x + 6.0f + guide.lane * 6.5f;
                    const ImU32 color = ImGui::GetColorU32(guide.to > guide.from ? ImVec4(0.95f,0.70f,0.25f,0.9f)
                                                                                   : ImVec4(0.45f,0.78f,1.0f,0.9f));
                    draw->AddLine(ImVec2(x, flowOrigin.y), ImVec2(x, flowOrigin.y + flowHeight), color, 1.4f);
                    if (i == guide.from) draw->AddCircleFilled(ImVec2(x, flowMidY), 2.2f, color);
                    if (i == guide.to) {
                        if (guide.to > guide.from)
                            draw->AddTriangleFilled(ImVec2(x, flowOrigin.y + flowHeight), ImVec2(x - 3.0f, flowOrigin.y + flowHeight - 5.0f), ImVec2(x + 3.0f, flowOrigin.y + flowHeight - 5.0f), color);
                        else
                            draw->AddTriangleFilled(ImVec2(x, flowOrigin.y), ImVec2(x - 3.0f, flowOrigin.y + 5.0f), ImVec2(x + 3.0f, flowOrigin.y + 5.0f), color);
                    }
                }
                ImGui::Dummy(ImVec2(flowWidth, flowHeight));

                ImGui::TableSetColumnIndex(2);
                ImGui::TextColored(isCur ? ImVec4(1,0.9f,0.4f,1) : ImVec4(0.6f,0.8f,1,1),
                                   "%s", vaStr(in.address, dbgState_==DbgState::Paused ? debugger_.is64() : pe_.is64Bit()).c_str());
                ImGui::TableSetColumnIndex(3);
                ImGui::TextDisabled("%s", in.bytes.c_str());
                ImGui::TableSetColumnIndex(4);
                auto lbit = labels_.find(in.address);
                if (lbit != labels_.end()) {
                    ImGui::TextColored(ImVec4(0.5f,1,0.8f,1), "%s:", lbit->second.c_str());
                    ImGui::SameLine();
                }
                ImVec4 col(0.9f,0.9f,0.9f,1);
                if (in.isCall) col = ImVec4(0.6f,1,0.6f,1);
                else if (in.isJump) col = ImVec4(1,0.8f,0.5f,1);
                else if (in.isRet)  col = ImVec4(1,0.6f,0.6f,1);
                ImGui::TextColored(col, "%s", in.text.c_str());
                if (in.hasBranchTarget && ImGui::IsItemHovered())
                    ImGui::SetTooltip("-> 0x%s", hex64(in.branchTarget).c_str());
                auto cmit = comments_.find(in.address);
                if (cmit != comments_.end()) {
                    ImGui::SameLine();
                    ImGui::TextColored(ImVec4(0.5f,0.75f,0.5f,1), "; %s", cmit->second.c_str());
                }
            }
        }
        ImGui::EndTable();
    }
    if (selectedInsn_ >= 0 && selectedInsn_ < (int)insns_.size() && ImGui::GetIO().KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_A))
        analyzeCodeAt(insns_[selectedInsn_].address);

    // Popup de anotacion (comentario/etiqueta)
    if (openAnnot_) { ImGui::OpenPopup("annot"); openAnnot_ = false; }
    if (ImGui::BeginPopup("annot")) {
        ImGui::Text("%s en 0x%s", annotIsLabel_ ? "Etiqueta" : "Comentario", hex64(annotAddr_).c_str());
        ImGui::SetNextItemWidth(320);
        bool ok = ImGui::InputText("##annot", annotBuf_, sizeof(annotBuf_), ImGuiInputTextFlags_EnterReturnsTrue);
        if (ImGui::Button("Guardar") || ok) {
            auto& map = annotIsLabel_ ? labels_ : comments_;
            if (annotBuf_[0]) map[annotAddr_] = annotBuf_; else map.erase(annotAddr_);
            saveAnnotations();
            ImGui::CloseCurrentPopup();
        }
        ImGui::SameLine();
        if (ImGui::Button("Borrar")) { (annotIsLabel_ ? labels_ : comments_).erase(annotAddr_); saveAnnotations(); ImGui::CloseCurrentPopup(); }
        ImGui::SameLine();
        if (ImGui::Button("Cancelar")) ImGui::CloseCurrentPopup();
        ImGui::EndPopup();
    }

    // Popup "Accion al golpear" (M3)
    if (openBpAction_) { ImGui::OpenPopup("bpaction"); openBpAction_ = false; }
    if (ImGui::BeginPopup("bpaction")) {
        ImGui::Text("Accion al golpear el BP en 0x%s:", hex64(bpActionAddr_).c_str());
        ImGui::TextDisabled("ai:<pregunta>  |  cmd {args} (tool dbg_*)  |  {json crudo}. Vacio = quitar.");
        ImGui::SetNextItemWidth(380);
        bool ok = ImGui::InputTextWithHint("##bpact", "ej: ai:que hace esta funcion?  |  dump {\"path\":\"C:\\\\d.bin\"}",
                     bpActionBuf_, sizeof(bpActionBuf_), ImGuiInputTextFlags_EnterReturnsTrue);
        if (ImGui::Button("Guardar##bpa") || ok) {
            if (bpActionBuf_[0]) bpActions_[bpActionAddr_] = bpActionBuf_;
            else bpActions_.erase(bpActionAddr_);
            ImGui::CloseCurrentPopup();
        }
        ImGui::SameLine();
        if (ImGui::Button("Cancelar##bpa")) ImGui::CloseCurrentPopup();
        ImGui::EndPopup();
    }

    // Popup "Search for -> All commands"
    if (openSearchCmd_) { ImGui::OpenPopup("searchcmd"); openSearchCmd_ = false; }
    if (ImGui::BeginPopup("searchcmd")) {
        ImGui::TextUnformatted("Buscar en todas las instrucciones (subcadena):");
        ImGui::SetNextItemWidth(320);
        bool ok = ImGui::InputTextWithHint("##scmd", "ej: call  |  push ebp  |  int3",
                     searchCmdBuf_, sizeof(searchCmdBuf_), ImGuiInputTextFlags_EnterReturnsTrue);
        if ((ImGui::Button("Buscar") || ok) && searchCmdBuf_[0]) {
            searchAllCommands(searchCmdBuf_);
            ImGui::CloseCurrentPopup();
        }
        ImGui::SameLine();
        if (ImGui::Button("Cancelar##scmd")) ImGui::CloseCurrentPopup();
        ImGui::EndPopup();
    }

    // Popup "Search for -> Binary string"
    if (openSearchBin_) { ImGui::OpenPopup("searchbin"); openSearchBin_ = false; }
    if (ImGui::BeginPopup("searchbin")) {
        ImGui::TextUnformatted("Buscar patron binario:");
        ImGui::RadioButton("Hex", searchBinHex_); if (ImGui::IsItemClicked()) searchBinHex_ = true;
        ImGui::SameLine();
        ImGui::RadioButton("Texto", !searchBinHex_); if (ImGui::IsItemClicked()) searchBinHex_ = false;
        if (!searchBinHex_) { ImGui::SameLine(); ImGui::Checkbox("UTF-16", &searchBinUtf16_); }
        ImGui::SetNextItemWidth(320);
        const char* hint = searchBinHex_ ? "ej: 48 8B ?? C3" : "cadena literal";
        bool ok = ImGui::InputTextWithHint("##sbin", hint,
                     searchBinBuf_, sizeof(searchBinBuf_), ImGuiInputTextFlags_EnterReturnsTrue);
        if ((ImGui::Button("Buscar##sbin") || ok) && searchBinBuf_[0]) {
            searchBinaryString(searchBinBuf_, searchBinHex_, searchBinUtf16_);
            ImGui::CloseCurrentPopup();
        }
        ImGui::SameLine();
        if (ImGui::Button("Cancelar##sbin")) ImGui::CloseCurrentPopup();
        ImGui::EndPopup();
    }

    // Popup ensamblador (Keystone, texto -> bytes)
    if (openAsmText_) { ImGui::OpenPopup("asmtext"); openAsmText_ = false; }
    if (ImGui::BeginPopup("asmtext")) {
        ImGui::Text("Ensamblar en 0x%s (%s):", hex64(asmAddr_).c_str(), debugger_.is64() ? "x64" : "x86");
        ImGui::SetNextItemWidth(340);
        bool ok = ImGui::InputTextWithHint("##asmt", "ej: mov eax, 1  |  jmp 0x401000  |  nop",
                     asmBuf_, sizeof(asmBuf_), ImGuiInputTextFlags_EnterReturnsTrue);
        if (!asmError_.empty()) ImGui::TextColored(ImVec4(1,0.5f,0.5f,1), "%s", asmError_.c_str());
        if ((ImGui::Button("Ensamblar y escribir") || ok) && asmBuf_[0]) {
            ks_engine* ks = nullptr;
            if (ks_open(KS_ARCH_X86, debugger_.is64() ? KS_MODE_64 : KS_MODE_32, &ks) == KS_ERR_OK) {
                unsigned char* enc = nullptr; size_t sz = 0, cnt = 0;
                if (ks_asm(ks, asmBuf_, asmAddr_, &enc, &sz, &cnt) == 0 && sz > 0 && dbgState_ == DbgState::Paused) {
                    debugger_.writeMemory(asmAddr_, enc, sz);
                    ks_free(enc);
                    refreshLiveDisassembly(currentIp_);
                    pushLog("Ensamblado " + std::to_string(sz) + " byte(s) en 0x" + hex64(asmAddr_));
                    ImGui::CloseCurrentPopup();
                } else {
                    asmError_ = std::string("Error: ") + ks_strerror(ks_errno(ks));
                    if (enc) ks_free(enc);
                }
                ks_close(ks);
            } else asmError_ = "ks_open fallo";
        }
        ImGui::SameLine();
        if (ImGui::Button("Cancelar")) ImGui::CloseCurrentPopup();
        ImGui::EndPopup();
    }

    // Popup patch por bytes (hex)
    if (openAsm_) { ImGui::OpenPopup("patch"); openAsm_ = false; }
    if (ImGui::BeginPopup("patch")) {
        ImGui::Text("Patch en 0x%s (bytes hex):", hex64(asmAddr_).c_str());
        ImGui::SetNextItemWidth(340);
        bool ok = ImGui::InputTextWithHint("##patch", "ej: 90 90 90  o  B8 01 00 00 00", asmBuf_, sizeof(asmBuf_),
                     ImGuiInputTextFlags_EnterReturnsTrue);
        if (!asmError_.empty()) ImGui::TextColored(ImVec4(1,0.5f,0.5f,1), "%s", asmError_.c_str());
        if ((ImGui::Button("Escribir") || ok) && asmBuf_[0]) {
            std::vector<uint8_t> bytes;
            std::string s = asmBuf_;
            for (size_t i = 0; i < s.size();) {
                if (s[i] == ' ') { i++; continue; }
                if (i + 1 < s.size() && isxdigit((unsigned char)s[i]) && isxdigit((unsigned char)s[i+1])) {
                    bytes.push_back((uint8_t)strtoul(s.substr(i, 2).c_str(), nullptr, 16)); i += 2;
                } else i++;
            }
            if (!bytes.empty() && dbgState_ == DbgState::Paused) {
                debugger_.writeMemory(asmAddr_, bytes.data(), bytes.size());
                refreshLiveDisassembly(currentIp_);
                pushLog("Patch " + std::to_string(bytes.size()) + " byte(s) en 0x" + hex64(asmAddr_));
                ImGui::CloseCurrentPopup();
            } else asmError_ = "sin bytes validos o proceso no pausado";
        }
        ImGui::SameLine();
        if (ImGui::Button("Cancelar")) ImGui::CloseCurrentPopup();
        ImGui::EndPopup();
    }
}

void App::applyRegEdit(const char* name, uint64_t value) {
    debugger_.setRegister(name, value);
    regs_ = debugger_.registers();
    std::string n = name;
    if (n == "rip" || n == "eip") { currentIp_ = regs_.ip(); refreshLiveDisassembly(currentIp_); }
}

void App::drawRegistersContent() {
    if (dbgState_ != DbgState::Paused) {
        ImGui::TextDisabled("(disponible al pausar)"); return;
    }
    ImGui::TextDisabled("Doble clic = editar valor. Clic en un flag = alternarlo.");

    auto reg = [&](const char* n, uint64_t v){
        ImGui::TextUnformatted(n); ImGui::SameLine(56);
        ImGui::PushID(n);
        std::string val = vaStr(v, regs_.is64);
        ImGui::TextColored(ImVec4(0.6f,0.8f,1,1), "%s", val.c_str());
        if (ImGui::IsItemHovered() && ImGui::IsMouseDoubleClicked(0)) {
            std::string ln = n; while (!ln.empty() && ln.back()==' ') ln.pop_back();
            for (auto& c : ln) c = (char)tolower((unsigned char)c);
            std::snprintf(regEditName_, sizeof(regEditName_), "%s", ln.c_str());
            std::snprintf(regEditBuf_, sizeof(regEditBuf_), "%s", val.c_str());
            openRegEdit_ = true;
        }
        ImGui::PopID();
    };

    if (regs_.is64) {
        reg("RAX",regs_.rax); reg("RBX",regs_.rbx); reg("RCX",regs_.rcx); reg("RDX",regs_.rdx);
        reg("RSI",regs_.rsi); reg("RDI",regs_.rdi); reg("RBP",regs_.rbp); reg("RSP",regs_.rsp);
        reg("R8", regs_.r8);  reg("R9", regs_.r9);  reg("R10",regs_.r10); reg("R11",regs_.r11);
        reg("R12",regs_.r12); reg("R13",regs_.r13); reg("R14",regs_.r14); reg("R15",regs_.r15);
        reg("RIP",regs_.rip);
    } else {
        reg("EAX",regs_.rax); reg("EBX",regs_.rbx); reg("ECX",regs_.rcx); reg("EDX",regs_.rdx);
        reg("ESI",regs_.rsi); reg("EDI",regs_.rdi); reg("EBP",regs_.rbp); reg("ESP",regs_.rsp);
        reg("EIP",regs_.rip);
    }

    ImGui::Separator();
    ImGui::Text("EFLAGS 0x%s", hex32(regs_.eflags).c_str());

    struct FlagBit { const char* n; int bit; };
    static const FlagBit flags[] = {
        {"CF",0},{"PF",2},{"AF",4},{"ZF",6},{"SF",7},{"TF",8},{"IF",9},{"DF",10},{"OF",11}
    };
    for (int i = 0; i < 9; ++i) {
        bool set = ((regs_.eflags >> flags[i].bit) & 1) != 0;
        ImGui::PushID(i);
        ImGui::PushStyleColor(ImGuiCol_Button, set ? ImVec4(0.85f,0.65f,0.15f,1) : ImVec4(0.30f,0.30f,0.30f,1));
        char lbl[16]; std::snprintf(lbl, sizeof(lbl), "%s %d", flags[i].n, set ? 1 : 0);
        if (ImGui::Button(lbl, ImVec2(46, 0)))
            applyRegEdit("eflags", regs_.eflags ^ (1u << flags[i].bit));
        ImGui::PopStyleColor();
        ImGui::PopID();
        if (i % 5 != 4 && i != 8) ImGui::SameLine();
    }

    // Popup de edicion de registro
    if (openRegEdit_) { ImGui::OpenPopup("edit_reg"); openRegEdit_ = false; }
    if (ImGui::BeginPopup("edit_reg")) {
        ImGui::Text("Nuevo valor de %s (hex):", regEditName_);
        ImGui::SetNextItemWidth(180);
        bool ok = ImGui::InputText("##rv", regEditBuf_, sizeof(regEditBuf_),
                    ImGuiInputTextFlags_EnterReturnsTrue | ImGuiInputTextFlags_CharsHexadecimal);
        if (ImGui::Button("Aplicar") || ok) {
            applyRegEdit(regEditName_, strtoull(regEditBuf_, nullptr, 16));
            ImGui::CloseCurrentPopup();
        }
        ImGui::SameLine();
        if (ImGui::Button("Cancelar")) ImGui::CloseCurrentPopup();
        ImGui::EndPopup();
    }
}

void App::drawBreakpointsPanel() {
    ImGui::Begin("Breakpoints");
    static std::map<uint64_t, std::array<char, 160>> conditionEdits;
    auto bps = debugger_.breakpoints();
    ImGui::Text("%zu breakpoints", bps.size());
    ImGui::Separator();
    if (ImGui::BeginTable("bps", 6, ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders)) {
        ImGui::TableSetupColumn("On", ImGuiTableColumnFlags_WidthFixed, 30);
        ImGui::TableSetupColumn("Direccion", ImGuiTableColumnFlags_WidthFixed, 150);
        ImGui::TableSetupColumn("Etiqueta", ImGuiTableColumnFlags_WidthFixed, 115);
        ImGui::TableSetupColumn("Hits / parar en", ImGuiTableColumnFlags_WidthFixed, 145);
        ImGui::TableSetupColumn("Condicion / accion", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("", ImGuiTableColumnFlags_WidthFixed, 60);
        ImGui::TableHeadersRow();
        for (auto& b : bps) {
            if (b.oneShot) continue;
            ImGui::TableNextRow();
            ImGui::PushID((int)b.address);
            ImGui::TableSetColumnIndex(0);
            bool en = b.enabled;
            if (ImGui::Checkbox("##en", &en)) debugger_.toggleBreakpoint(b.address, en);
            ImGui::TableSetColumnIndex(1);
            ImGui::TextColored(ImVec4(1,0.6f,0.6f,1), "0x%s", hex64(b.address).c_str());
            ImGui::TableSetColumnIndex(2);
            ImGui::TextUnformatted(b.label.empty() ? "-" : b.label.c_str());
            ImGui::TableSetColumnIndex(3);
            ImGui::Text("%llu /", static_cast<unsigned long long>(b.hits));
            ImGui::SameLine();
            uint64_t breakOn = b.breakOnHit;
            ImGui::SetNextItemWidth(68);
            if (ImGui::InputScalar("##breakOn", ImGuiDataType_U64, &breakOn, nullptr, nullptr, "0=siempre"))
                debugger_.setBreakpointHitTarget(b.address, breakOn);
            ImGui::TableSetColumnIndex(4);
            auto [conditionIt, newCondition] = conditionEdits.try_emplace(b.address);
            if (newCondition)
                std::snprintf(conditionIt->second.data(), conditionIt->second.size(), "%s", b.condition.c_str());
            ImGui::SetNextItemWidth(-1);
            const bool conditionEnter = ImGui::InputText("##condition", conditionIt->second.data(), conditionIt->second.size(), ImGuiInputTextFlags_EnterReturnsTrue);
            if (conditionEnter || ImGui::IsItemDeactivatedAfterEdit())
                debugger_.setBreakpointCondition(b.address, conditionIt->second.data());
            bool logOnly = b.logOnly;
            if (ImGui::Checkbox("solo log##action", &logOnly)) debugger_.setBreakpointLogOnly(b.address, logOnly);
            ImGui::TableSetColumnIndex(5);
            if (ImGui::SmallButton("quitar")) debugger_.removeBreakpoint(b.address);
            ImGui::PopID();
        }
        ImGui::EndTable();
    }
    ImGui::Separator();
    static char bpAddr[24] = {0};
    ImGui::InputTextWithHint("##bpaddr", "VA hex (ej 401000)", bpAddr, sizeof(bpAddr));
    ImGui::SameLine();
    if (ImGui::Button("Agregar")) {
        uint64_t a = strtoull(bpAddr, nullptr, 16);
        if (a) debugger_.addBreakpoint(a, "manual");
    }
    ImGui::SameLine();
    if (ImGui::Button("BP en EntryPoint") && fileLoaded_)
        debugger_.addBreakpoint(pe_.entryPointVA(), "EntryPoint");
    ImGui::TextDisabled("Parar en: 0 = cada impacto; N = ignorar los N-1 primeros. Condicion: rax == 0, ecx & 1 != 0, hit >= 5. Numeros decimales o 0xHEX; 'solo log' continua tras registrar.");

    ImGui::Separator();
    ImGui::TextUnformatted("Hardware breakpoints (DR0-DR3):");
    static char hwAddr[24] = {0}; static int hwType = 0; static int hwLen = 0;
    ImGui::SetNextItemWidth(120);
    ImGui::InputTextWithHint("##hwaddr", "VA hex", hwAddr, sizeof(hwAddr));
    ImGui::SameLine(); ImGui::SetNextItemWidth(130);
    ImGui::Combo("##hwtype", &hwType, "Ejecucion\0" "Escritura\0" "Lectura/Escritura\0");
    ImGui::SameLine(); ImGui::SetNextItemWidth(50);
    ImGui::Combo("##hwlen", &hwLen, "1\0" "2\0" "4\0" "8\0");
    ImGui::SameLine();
    if (ImGui::Button("Add HW")) {
        uint64_t a = strtoull(hwAddr, nullptr, 16);
        const int typemap[] = {0, 1, 3}; const int lenmap[] = {1, 2, 4, 8};
        if (a && !debugger_.addHwBreakpoint(a, typemap[hwType], lenmap[hwLen], "hw"))
            pushLog("HW BP: sin slots libres (max 4) o duplicado.");
    }
    for (auto& h : debugger_.hwBreakpoints()) {
        ImGui::PushID((int)(h.address ^ (h.address >> 32)));
        ImGui::TextColored(ImVec4(0.9f,0.7f,1,1), "DR%d  0x%s  %s  len%d  hits %u",
            h.slot, hex64(h.address).c_str(),
            h.type==0?"exec":h.type==1?"write":"rw", h.len, h.hits);
        ImGui::SameLine();
        if (ImGui::SmallButton("quitar")) debugger_.removeHwBreakpoint(h.address);
        ImGui::PopID();
    }

    ImGui::Separator();
    ImGui::TextUnformatted("Memory breakpoints (PAGE_GUARD, paginas de 4 KiB):");
    static char memBpAddr[24] = {0}, memBpSize[24] = "1";
    static int memBpType = 0;
    static std::string memBpStatus;
    ImGui::SetNextItemWidth(120);
    ImGui::InputTextWithHint("##mbaddr", "VA hex", memBpAddr, sizeof(memBpAddr));
    ImGui::SameLine(); ImGui::SetNextItemWidth(80);
    ImGui::InputTextWithHint("##mbsize", "bytes hex", memBpSize, sizeof(memBpSize), ImGuiInputTextFlags_CharsHexadecimal);
    ImGui::SameLine(); ImGui::SetNextItemWidth(105);
    ImGui::Combo("##mbtype", &memBpType, "Acceso\0Escritura\0Ejecucion\0");
    ImGui::SameLine();
    ImGui::BeginDisabled(dbgState_ != DbgState::Paused);
    if (ImGui::Button("Add Memory BP")) {
        const int typeMap[] = {0, 1, 8};
        std::string error;
        if (debugger_.addMemoryBreakpoint(strtoull(memBpAddr, nullptr, 16), strtoull(memBpSize, nullptr, 16),
                                           typeMap[memBpType], "memory", error))
            memBpStatus = "Memory breakpoint agregado.";
        else memBpStatus = "Error: " + error;
    }
    ImGui::EndDisabled();
    ImGui::TextDisabled("Requiere pausa. El SO protege paginas completas: puede haber hits vecinos. No uses stack ni paginas PAGE_GUARD existentes.");
    if (!memBpStatus.empty()) ImGui::TextWrapped("%s", memBpStatus.c_str());
    for (const auto& bp : debugger_.memoryBreakpoints()) {
        ImGui::PushID(static_cast<int>(bp.id));
        const char* kind = bp.type == 1 ? "write" : bp.type == 8 ? "execute" : "access";
        ImGui::Text("#%u  0x%s  size 0x%llX  %s  hits %llu", bp.id, hex64(bp.address).c_str(),
                    static_cast<unsigned long long>(bp.size), kind, static_cast<unsigned long long>(bp.hits));
        ImGui::SameLine();
        if (ImGui::SmallButton("quitar")) debugger_.removeMemoryBreakpoint(bp.id);
        ImGui::PopID();
    }
    ImGui::End();
}

// ---------------------------------------------------------------------------
// Memoria (hex dump + mapa)
// ---------------------------------------------------------------------------
void App::drawMemoryPanel() {
    ImGui::Begin("Memoria");
    ImGui::InputTextWithHint("##goto", "ir a VA hex", memGotoBuf_, sizeof(memGotoBuf_));
    ImGui::SameLine();
    if (ImGui::Button("Ver")) {
        memBase_ = strtoull(memGotoBuf_, nullptr, 16);
        memBuf_.assign(0x200, 0);
        size_t got = debugger_.readMemory(memBase_, memBuf_.data(), memBuf_.size());
        memBuf_.resize(got);
    }
    ImGui::SameLine();
    if (dbgState_ == DbgState::Paused && ImGui::Button("Ver RSP")) {
        memBase_ = regs_.rsp; memBuf_.assign(0x200, 0);
        size_t got = debugger_.readMemory(memBase_, memBuf_.data(), memBuf_.size());
        memBuf_.resize(got);
    }

    if (!memBuf_.empty()) {
        ImGui::BeginChild("hex", ImVec2(0, 220), true, ImGuiWindowFlags_HorizontalScrollbar);
        for (size_t i = 0; i < memBuf_.size(); i += 16) {
            std::string line = hex64(memBase_ + i) + "  ";
            std::string ascii;
            for (size_t j = 0; j < 16; ++j) {
                if (i + j < memBuf_.size()) {
                    char b[4]; std::snprintf(b, sizeof(b), "%02X ", memBuf_[i + j]);
                    line += b;
                    uint8_t c = memBuf_[i + j];
                    ascii += (c >= 0x20 && c < 0x7F) ? (char)c : '.';
                } else line += "   ";
            }
            ImGui::TextUnformatted((line + "  " + ascii).c_str());
        }
        ImGui::EndChild();
    }

    ImGui::Separator();
    ImGui::Text("Mapa de memoria (%zu regiones)", memMap_.size());
    if (ImGui::Button("Refrescar mapa") && dbgState_ == DbgState::Paused) memMap_ = debugger_.memoryMap();
    if (ImGui::BeginTable("mm", 5, ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders | ImGuiTableFlags_ScrollY, ImVec2(0, 200))) {
        ImGui::TableSetupColumn("Base"); ImGui::TableSetupColumn("Tamano");
        ImGui::TableSetupColumn("Prot"); ImGui::TableSetupColumn("Tipo");
        ImGui::TableSetupColumn("Modulo");
        ImGui::TableHeadersRow();
        for (auto& r : memMap_) {
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            if (ImGui::Selectable(("0x" + hex64(r.base)).c_str(), false, ImGuiSelectableFlags_SpanAllColumns)) {
                memBase_ = r.base; memBuf_.assign(0x200, 0);
                size_t got = debugger_.readMemory(memBase_, memBuf_.data(), memBuf_.size());
                memBuf_.resize(got);
            }
            ImGui::TableSetColumnIndex(1); ImGui::Text("0x%llX", (unsigned long long)r.size);
            ImGui::TableSetColumnIndex(2); ImGui::TextUnformatted(r.protectStr.c_str());
            ImGui::TableSetColumnIndex(3); ImGui::TextUnformatted(r.typeStr.c_str());
            ImGui::TableSetColumnIndex(4); ImGui::TextUnformatted(r.moduleName.c_str());
        }
        ImGui::EndTable();
    }
    ImGui::End();
}

// ---------------------------------------------------------------------------
// Volcado Hex dedicado (Address | Hex dump | ASCII)  -- estilo pane de OllyDbg
// ---------------------------------------------------------------------------
void App::drawHexDumpContent() {
    ImGui::SetNextItemWidth(160);
    ImGui::InputTextWithHint("##dgoto", "ir a VA hex", dumpGotoBuf_, sizeof(dumpGotoBuf_));
    ImGui::SameLine();
    auto load = [&](uint64_t va){
        dumpBase_ = va; dumpBuf_.assign(0x200, 0);
        size_t got = debugger_.readMemory(dumpBase_, dumpBuf_.data(), dumpBuf_.size());
        dumpBuf_.resize(got);
        if (got == 0 && fileLoaded_ && dbgState_ == DbgState::Idle) {
            // sin proceso: leer del archivo estatico por RVA
            uint32_t rva = (uint32_t)(va - pe_.imageBase());
            dumpBuf_.assign(0x200, 0);
            size_t n = pe_.readAtRva(rva, dumpBuf_.data(), dumpBuf_.size());
            dumpBuf_.resize(n);
        }
    };
    if (ImGui::Button("Ver")) load(strtoull(dumpGotoBuf_, nullptr, 16));
    if (dbgState_ == DbgState::Paused) {
        ImGui::SameLine(); if (ImGui::Button("Seguir RIP")) load(currentIp_);
    }

    ImGui::Separator();
    if (dumpBuf_.empty()) { ImGui::TextDisabled("Escribe una direccion y pulsa Ver."); return; }

    ImGui::BeginChild("hd", ImVec2(0, 0), false, ImGuiWindowFlags_HorizontalScrollbar);
    for (size_t i = 0; i < dumpBuf_.size(); i += 16) {
        std::string line = hex64(dumpBase_ + i) + "  ";
        std::string ascii;
        for (size_t j = 0; j < 16; ++j) {
            if (i + j < dumpBuf_.size()) {
                char b[4]; std::snprintf(b, sizeof(b), "%02X ", dumpBuf_[i + j]);
                line += b;
                uint8_t c = dumpBuf_[i + j];
                ascii += (c >= 0x20 && c < 0x7F) ? (char)c : '.';
            } else line += "   ";
        }
        ImGui::TextUnformatted((line + "  " + ascii).c_str());
    }
    ImGui::EndChild();
}

// ---------------------------------------------------------------------------
// Pila (Address | Value)  -- sigue a RSP/ESP
// ---------------------------------------------------------------------------
void App::drawStackContent() {
    if (dbgState_ != DbgState::Paused) { ImGui::TextDisabled("(disponible al pausar)"); return; }

    uint64_t sp = regs_.rsp;
    size_t ptr = regs_.is64 ? 8 : 4;
    ImGui::Text("%s = 0x%s", regs_.is64 ? "RSP" : "ESP", hex64(sp).c_str());
    ImGui::Separator();

    if (ImGui::BeginTable("stk", 3, ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders | ImGuiTableFlags_ScrollY)) {
        ImGui::TableSetupColumn("Address", ImGuiTableColumnFlags_WidthFixed, 150);
        ImGui::TableSetupColumn("Value", ImGuiTableColumnFlags_WidthFixed, 150);
        ImGui::TableSetupColumn("Info", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableHeadersRow();

        auto mods = debugger_.modules();
        for (int i = 0; i < 64; ++i) {
            uint64_t addr = sp + i * ptr;
            uint64_t val = 0;
            if (debugger_.readMemory(addr, &val, ptr) != ptr) break;
            ImGui::TableNextRow();
            if (i == 0) ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0, ImGui::GetColorU32(ImVec4(0.30f,0.25f,0.05f,1)));
            ImGui::TableSetColumnIndex(0);
            ImGui::PushID(i);
            ImGui::TextColored(i == 0 ? ImVec4(1,0.9f,0.4f,1) : ImVec4(0.6f,0.8f,1,1), "%s", vaStr(addr, regs_.is64).c_str());
            ImGui::TableSetColumnIndex(1);
            if (ImGui::Selectable(vaStr(val, regs_.is64).c_str(), false, ImGuiSelectableFlags_AllowDoubleClick)) {
                if (ImGui::IsMouseDoubleClicked(0)) {
                    // seguir el valor en el volcado hex y en el CPU
                    std::snprintf(dumpGotoBuf_, sizeof(dumpGotoBuf_), "%llX", (unsigned long long)val);
                    dumpBase_ = val; dumpBuf_.assign(0x200, 0);
                    size_t g = debugger_.readMemory(val, dumpBuf_.data(), dumpBuf_.size());
                    dumpBuf_.resize(g);
                }
            }
            ImGui::TableSetColumnIndex(2);
            // Anotar si el valor cae dentro de un modulo cargado (posible retorno)
            const char* modn = "";
            for (auto& m : mods) if (val >= m.base && val < m.base + 0x2000000ull) { modn = m.name.c_str(); break; }
            if (modn[0]) ImGui::TextDisabled("-> %s", modn);
            ImGui::PopID();
        }
        ImGui::EndTable();
    }
}

// ---------------------------------------------------------------------------
// Strings / busqueda hex
// ---------------------------------------------------------------------------
void App::drawStringsPanel() {
    ImGui::Begin("Strings & Busqueda");

    if (ImGui::BeginTabBar("sb")) {
        if (ImGui::BeginTabItem("Strings (archivo)")) {
            ImGui::InputTextWithHint("filtro", "subcadena", strFilter_, sizeof(strFilter_));
            ImGui::SameLine();
            int ml = (int)minStrLen_;
            if (ImGui::InputInt("min", &ml)) { minStrLen_ = ml < 2 ? 2 : ml; refreshStaticStrings(); }
            ImGui::Separator();
            if (ImGui::BeginTable("str", 3, ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders | ImGuiTableFlags_ScrollY, ImVec2(0, 300))) {
                ImGui::TableSetupColumn("Direccion", ImGuiTableColumnFlags_WidthFixed, 150);
                ImGui::TableSetupColumn("Tipo", ImGuiTableColumnFlags_WidthFixed, 50);
                ImGui::TableSetupColumn("Texto", ImGuiTableColumnFlags_WidthStretch);
                ImGui::TableSetupScrollFreeze(0, 1);
                ImGui::TableHeadersRow();
                std::string filt = strFilter_;
                for (auto& s : strings_) {
                    if (!filt.empty() && s.text.find(filt) == std::string::npos) continue;
                    ImGui::TableNextRow();
                    ImGui::TableSetColumnIndex(0); ImGui::Text("0x%s", hex64(s.address).c_str());
                    ImGui::TableSetColumnIndex(1); ImGui::TextUnformatted(s.kind == StrKind::Ascii ? "A" : "W");
                    ImGui::TableSetColumnIndex(2); ImGui::TextUnformatted(s.text.c_str());
                }
                ImGui::EndTable();
            }
            ImGui::EndTabItem();
        }

        if (ImGui::BeginTabItem("Buscar hex / texto")) {
            ImGui::InputTextWithHint("hex", "patron: 48 8B ?? C3", hexPattern_, sizeof(hexPattern_));
            ImGui::SameLine();
            if (ImGui::Button("Buscar hex")) {
                searchHits_.clear(); searchStatus_.clear();
                const uint8_t* data; size_t len; uint64_t base;
                std::vector<uint8_t> live;
                if (dbgState_ == DbgState::Paused && memBase_ && !memBuf_.empty()) {
                    data = memBuf_.data(); len = memBuf_.size(); base = memBase_;
                } else if (fileLoaded_) {
                    data = pe_.raw().data(); len = pe_.raw().size(); base = pe_.imageBase();
                } else { data = nullptr; len = 0; base = 0; }
                if (data) {
                    std::string perr;
                    searchHits_ = searchHex(data, len, base, hexPattern_, perr);
                    searchStatus_ = perr.empty() ? (std::to_string(searchHits_.size()) + " coincidencias") : perr;
                }
            }
            ImGui::InputTextWithHint("texto", "cadena literal", textNeedle_, sizeof(textNeedle_));
            ImGui::SameLine();
            ImGui::Checkbox("UTF-16", &searchUtf16_);
            ImGui::SameLine();
            if (ImGui::Button("Buscar texto")) {
                searchHits_.clear(); searchStatus_.clear();
                const uint8_t* data = nullptr; size_t len = 0; uint64_t base = 0;
                if (fileLoaded_) { data = pe_.raw().data(); len = pe_.raw().size(); base = pe_.imageBase(); }
                if (data) {
                    searchHits_ = searchText(data, len, base, textNeedle_, searchUtf16_);
                    searchStatus_ = std::to_string(searchHits_.size()) + " coincidencias";
                }
            }
            ImGui::Separator();
            // Buscar entero / float en el archivo
            auto offToVA = [&](size_t off) -> uint64_t {
                for (auto& s : pe_.sections())
                    if (off >= s.rawOffset && off < (size_t)s.rawOffset + s.rawSize)
                        return pe_.imageBase() + s.virtualAddress + (off - s.rawOffset);
                return 0;
            };
            auto scanBytes = [&](const uint8_t* pat, int L, const char* tag) {
                searchHits_.clear(); searchStatus_.clear();
                if (!fileLoaded_) return;
                const auto& raw = pe_.raw();
                for (size_t i = 0; i + L <= raw.size(); ++i)
                    if (std::memcmp(raw.data()+i, pat, L)==0) {
                        uint64_t va = offToVA(i); if (va) searchHits_.push_back(va);
                        if (searchHits_.size() >= 2000) break;
                    }
                searchStatus_ = std::to_string(searchHits_.size()) + std::string(" (") + tag + ")";
            };
            static char intBuf[32] = ""; static int intSize = 2;
            ImGui::SetNextItemWidth(120);
            ImGui::InputTextWithHint("##int", "entero decimal", intBuf, sizeof(intBuf));
            ImGui::SameLine(); ImGui::SetNextItemWidth(50);
            ImGui::Combo("##isz", &intSize, "1\0" "2\0" "4\0" "8\0");
            ImGui::SameLine();
            if (ImGui::Button("Buscar entero")) {
                long long val = strtoll(intBuf, nullptr, 0);
                const int lenmap[] = {1,2,4,8}; int L = lenmap[intSize];
                uint8_t bytes[8]; for (int i=0;i<L;i++) bytes[i]=(uint8_t)((val>>(8*i))&0xFF);
                scanBytes(bytes, L, "entero");
            }
            static char fltBuf[32] = ""; static bool isDouble = false;
            ImGui::SetNextItemWidth(120);
            ImGui::InputTextWithHint("##flt", "float/double", fltBuf, sizeof(fltBuf));
            ImGui::SameLine(); ImGui::Checkbox("double", &isDouble);
            ImGui::SameLine();
            if (ImGui::Button("Buscar float")) {
                uint8_t bytes[8]; int L;
                if (isDouble) { double d = atof(fltBuf); std::memcpy(bytes,&d,8); L=8; }
                else { float fl = (float)atof(fltBuf); std::memcpy(bytes,&fl,4); L=4; }
                scanBytes(bytes, L, "float");
            }
            ImGui::Separator();
            ImGui::TextColored(ImVec4(0.7f,0.9f,1,1), "%s", searchStatus_.c_str());
            ImGui::BeginChild("hits", ImVec2(0, 250), true);
            for (auto a : searchHits_) {
                if (ImGui::Selectable(("0x" + hex64(a)).c_str())) {
                    std::snprintf(memGotoBuf_, sizeof(memGotoBuf_), "%llX", (unsigned long long)a);
                }
            }
            ImGui::EndChild();
            ImGui::EndTabItem();
        }
        ImGui::EndTabBar();
    }
    ImGui::End();
}

// ---------------------------------------------------------------------------
// Modulos, imports/exports, secciones (simbolos)
// ---------------------------------------------------------------------------
void App::drawModulesPanel() {
    ImGui::Begin("Modulos & Simbolos");
    if (ImGui::BeginTabBar("ms")) {
        if (ImGui::BeginTabItem("Secciones")) {
            if (ImGui::BeginTable("sec", 5, ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders)) {
                ImGui::TableSetupColumn("Nombre"); ImGui::TableSetupColumn("RVA");
                ImGui::TableSetupColumn("VSize"); ImGui::TableSetupColumn("Perm");
                ImGui::TableSetupColumn("Entropia");
                ImGui::TableHeadersRow();
                for (auto& s : pe_.sections()) {
                    ImGui::TableNextRow();
                    ImGui::TableSetColumnIndex(0); ImGui::TextUnformatted(s.name.c_str());
                    ImGui::TableSetColumnIndex(1); ImGui::Text("0x%X", s.virtualAddress);
                    ImGui::TableSetColumnIndex(2); ImGui::Text("0x%X", s.virtualSize);
                    ImGui::TableSetColumnIndex(3); ImGui::Text("%c%c%c",
                        s.readable()?'R':'-', s.writable()?'W':'-', s.executable()?'X':'-');
                    ImGui::TableSetColumnIndex(4);
                    ImVec4 c = s.entropy > 7.2 ? ImVec4(1,0.5f,0.5f,1) : ImVec4(0.8f,0.8f,0.8f,1);
                    ImGui::TextColored(c, "%.2f", s.entropy);
                }
                ImGui::EndTable();
            }
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Imports")) {
            ImGui::BeginChild("imp", ImVec2(0, 320), true);
            std::string curDll;
            for (auto& i : pe_.imports()) {
                if (i.dll != curDll) { curDll = i.dll; ImGui::TextColored(ImVec4(1,0.9f,0.5f,1), "%s", curDll.c_str()); }
                if (!i.name.empty()) ImGui::Text("   %s", i.name.c_str());
                else ImGui::Text("   ordinal %u", i.ordinal);
            }
            ImGui::EndChild();
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Exports")) {
            ImGui::BeginChild("exp", ImVec2(0, 320), true);
            for (auto& e : pe_.exports())
                ImGui::Text("%4u  0x%08X  %s", e.ordinal, e.rva, e.name.c_str());
            ImGui::EndChild();
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Modulos cargados")) {
            auto mods = debugger_.modules();
            ImGui::TextDisabled("Doble clic en un modulo para abrir su codigo desensamblado.");
            ImGui::BeginChild("mods", ImVec2(0, 320), true);
            if (mods.empty() && fileLoaded_) {
                std::string path(loadedPath_.begin(), loadedPath_.end());
                const auto slash = path.find_last_of("\\/");
                const std::string name = slash == std::string::npos ? path : path.substr(slash + 1);
                const std::string row = "0x" + hex64(pe_.imageBase()) + "  " + name + " (archivo abierto)";
                if (ImGui::Selectable(row.c_str(), false, ImGuiSelectableFlags_AllowDoubleClick) &&
                    ImGui::IsMouseDoubleClicked(0))
                    gotoAddress(pe_.imageBase());
            }
            for (auto& m : mods) {
                ImGui::PushID(static_cast<int>(m.base));
                const std::string row = "0x" + hex64(m.base) + "  " + m.name;
                if (ImGui::Selectable(row.c_str(), false, ImGuiSelectableFlags_AllowDoubleClick) &&
                    ImGui::IsMouseDoubleClicked(0)) {
                    gotoAddress(m.base);
                    pushLog("Modulo abierto en CPU: " + m.name + " @0x" + hex64(m.base));
                }
                ImGui::PopID();
            }
            ImGui::EndChild();
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("TLS / SEH")) {
            ImGui::TextColored(ImVec4(1,0.9f,0.5f,1), "TLS callbacks (%zu):", pe_.tlsCallbacks().size());
            if (pe_.tlsCallbacks().empty()) ImGui::TextDisabled("  (ninguno)");
            for (size_t i = 0; i < pe_.tlsCallbacks().size(); ++i) {
                ImGui::PushID((int)i);
                if (ImGui::Selectable(("  0x" + hex64(pe_.tlsCallbacks()[i])).c_str()))
                    gotoAddress(pe_.tlsCallbacks()[i]);
                ImGui::PopID();
            }
            ImGui::Separator();
            ImGui::TextColored(ImVec4(1,0.9f,0.5f,1), "Cadena SEH (FS:[0], x86):");
            if (dbgState_ != DbgState::Paused) ImGui::TextDisabled("  (pausa el proceso)");
            else if (debugger_.is64()) ImGui::TextDisabled("  (x64: SEH es table-based, no cadena FS)");
            else {
                auto chain = debugger_.sehChain();
                if (chain.empty()) ImGui::TextDisabled("  (vacia)");
                for (auto& e : chain) {
                    ImGui::Text("  record 0x%08llX -> handler ", (unsigned long long)e.first);
                    ImGui::SameLine();
                    ImGui::PushID((int)e.second);
                    if (ImGui::SmallButton(("0x" + hex64(e.second)).c_str())) gotoAddress(e.second);
                    ImGui::PopID();
                }
            }
            ImGui::EndTabItem();
        }
        ImGui::EndTabBar();
    }
    ImGui::End();
}

void App::drawPackerPanel() {
    ImGui::Begin("Packers / Proteccion");
    if (!fileLoaded_) { ImGui::TextDisabled("Abre un archivo."); ImGui::End(); return; }
    ImGui::Text("Entropia global: %.3f / 8.0", pe_.overallEntropy());
    if (pe_.overallEntropy() > 7.0)
        ImGui::TextColored(ImVec4(1,0.6f,0.3f,1), "Entropia alta: probable empacado o cifrado.");
    ImGui::SameLine();
    if (ImGui::Button("Re-escanear")) runPackerScan();
    ImGui::Separator();
    if (packerMatches_.empty()) {
        ImGui::TextColored(ImVec4(0.6f,1,0.6f,1), "Sin firmas de packer conocidas.");
    } else {
        if (ImGui::BeginTable("pk", 3, ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders)) {
            ImGui::TableSetupColumn("Deteccion"); ImGui::TableSetupColumn("Origen");
            ImGui::TableSetupColumn("Confianza");
            ImGui::TableHeadersRow();
            for (auto& m : packerMatches_) {
                ImGui::TableNextRow();
                ImGui::TableSetColumnIndex(0); ImGui::TextUnformatted(m.name.c_str());
                ImGui::TableSetColumnIndex(1); ImGui::TextDisabled("%s", m.source.c_str());
                ImGui::TableSetColumnIndex(2);
                ImVec4 c = m.confidence >= 80 ? ImVec4(1,0.5f,0.5f,1) : ImVec4(1,0.85f,0.4f,1);
                ImGui::TextColored(c, "%d%%", m.confidence);
            }
            ImGui::EndTable();
        }
    }
    ImGui::End();
}

void App::drawExceptionsPanel() {
    ImGui::Begin("Excepciones");
    auto excs = debugger_.exceptionBreaks();
    ImGui::Text("%zu breakpoints de excepcion", excs.size());
    ImGui::TextDisabled("Doble clic en una fila para ir a su direccion.");
    ImGui::Separator();

    if (ImGui::BeginTable("exc", 6, ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders | ImGuiTableFlags_ScrollY, ImVec2(0, 240))) {
        ImGui::TableSetupColumn("On",  ImGuiTableColumnFlags_WidthFixed, 30);
        ImGui::TableSetupColumn("Codigo", ImGuiTableColumnFlags_WidthFixed, 80);
        ImGui::TableSetupColumn("Excepcion", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("Direccion", ImGuiTableColumnFlags_WidthFixed, 150);
        ImGui::TableSetupColumn("Hits", ImGuiTableColumnFlags_WidthFixed, 45);
        ImGui::TableSetupColumn("", ImGuiTableColumnFlags_WidthFixed, 60);
        ImGui::TableHeadersRow();

        for (auto& e : excs) {
            ImGui::TableNextRow();
            ImGui::PushID((int)e.id);
            ImGui::TableSetColumnIndex(0);
            bool en = e.enabled;
            if (ImGui::Checkbox("##en", &en)) debugger_.toggleExceptionBreak(e.id, en);

            ImGui::TableSetColumnIndex(1);
            char code[16]; std::snprintf(code, sizeof(code), "%08X", e.code);
            if (ImGui::Selectable(code, false, ImGuiSelectableFlags_AllowDoubleClick)) {
                if (ImGui::IsMouseDoubleClicked(0) && e.address) gotoAddress(e.address);
            }
            ImGui::TableSetColumnIndex(2); ImGui::TextUnformatted(exceptionName(e.code));
            ImGui::TableSetColumnIndex(3);
            if (e.address) ImGui::TextColored(ImVec4(0.6f,0.8f,1,1), "0x%s", hex64(e.address).c_str());
            else ImGui::TextDisabled("-");
            ImGui::TableSetColumnIndex(4); ImGui::Text("%u", e.hits);
            ImGui::TableSetColumnIndex(5);
            if (ImGui::SmallButton("quitar")) debugger_.removeExceptionBreak(e.id);
            ImGui::PopID();
        }
        ImGui::EndTable();
    }

    ImGui::Separator();
    ImGui::TextUnformatted("Agregar manual:");
    ImGui::SetNextItemWidth(90);
    ImGui::InputTextWithHint("##ecode", "codigo hex", excCodeBuf_, sizeof(excCodeBuf_));
    ImGui::SameLine();
    ImGui::SetNextItemWidth(120);
    ImGui::InputTextWithHint("##eaddr", "VA (opcional)", excAddrBuf_, sizeof(excAddrBuf_));
    ImGui::SameLine();
    ImGui::SetNextItemWidth(120);
    ImGui::InputTextWithHint("##elabel", "etiqueta", excLabelBuf_, sizeof(excLabelBuf_));
    ImGui::SameLine();
    if (ImGui::Button("Agregar")) {
        uint32_t c = (uint32_t)strtoul(excCodeBuf_, nullptr, 16);
        uint64_t a = strtoull(excAddrBuf_, nullptr, 16);
        debugger_.addExceptionBreak(c, a, excLabelBuf_);
        excAddrBuf_[0] = '\0'; excLabelBuf_[0] = '\0';
    }
    ImGui::TextDisabled("Codigo 0 = cualquier excepcion. Ej: C0000005 = ACCESS_VIOLATION.");
    ImGui::Separator();
    ImGui::TextUnformatted("Breakpoints de eventos de sistema:");
    uint32_t eventMask = debugger_.eventBreakMask();
    auto eventToggle = [&](const char* label, uint32_t bit) {
        bool enabled = (eventMask & bit) != 0;
        if (ImGui::Checkbox(label, &enabled)) {
            if (enabled) eventMask |= bit; else eventMask &= ~bit;
            debugger_.setEventBreakMask(eventMask);
        }
    };
    eventToggle("Crear hilo##event", BreakOnThreadCreate); ImGui::SameLine();
    eventToggle("Terminar hilo##event", BreakOnThreadExit); ImGui::SameLine();
    eventToggle("Cargar DLL##event", BreakOnDllLoad); ImGui::SameLine();
    eventToggle("Descargar DLL##event", BreakOnDllUnload);
    ImGui::TextDisabled("Se detienen al recibir el evento de la Windows Debug API; utiles para observar inyeccion/carga dinamica.");
    ImGui::End();
}

void App::drawPluginsPanel() {
    ImGui::Begin("Plugins");
    bool active = (dbgState_ == DbgState::Running || dbgState_ == DbgState::Paused);
    bool paused = (dbgState_ == DbgState::Paused);

    if (!pluginStatus_.empty())
        ImGui::TextColored(ImVec4(0.7f,0.9f,1,1), "%s", pluginStatus_.c_str());
    ImGui::Separator();

    // ---- Plugin 0: MCP ----
    if (ImGui::CollapsingHeader("MCP Control", ImGuiTreeNodeFlags_DefaultOpen)) {
        ImGui::TextDisabled("Expone el debugger para clientes MCP. Cada sesion exige un token secreto.");
        ImGui::SetNextItemWidth(90);
        ImGui::InputInt("Puerto", &mcpPort_);
        if (mcpPort_ < 1) mcpPort_ = 1; if (mcpPort_ > 65535) mcpPort_ = 65535;
        ImGui::SameLine();
        ImGui::Checkbox("Bind 0.0.0.0 (WSL/red)", &mcpBindAll_);
        const char* accessNames[] = { "Solo lectura", "Control de sesion", "Modificacion" };
        if (ImGui::Combo("Permiso MCP", &mcpAccessLevel_, accessNames, IM_ARRAYSIZE(accessNames)))
            mcp_.setAccessLevel(mcpAccessLevel_);
        ImGui::TextDisabled("Lectura no ejecuta ni cambia proceso. Control permite play/step/breakpoints. Modificacion permite parches, dumps y plugins.");
        ImGui::Checkbox("Bypass (aceptar comandos SIN token)", &mcpNoAuth_);
        if (mcpNoAuth_) ImGui::TextColored(ImVec4(1,0.55f,0.3f,1), "ADVERTENCIA: cualquiera que alcance el puerto puede controlar el debugger. Usar solo en local/confianza.");
        if (!mcp_.running()) {
            if (ImGui::Button("Activar MCP")) startMcp();
        } else {
            if (ImGui::Button("Detener MCP")) stopMcp();
            ImGui::SameLine();
            ImGui::TextColored(ImVec4(0.5f,1,0.5f,1), "ACTIVO  puerto %d, %d cliente(s)", mcp_.port(), mcp_.clients());
            ImGui::TextWrapped("Token de sesion: %s", mcpToken_.c_str());
            ImGui::SameLine();
            if (ImGui::SmallButton("Copiar token")) ImGui::SetClipboardText(mcpToken_.c_str());
        }
        if (!mcpStatus_.empty()) ImGui::TextWrapped("%s", mcpStatus_.c_str());
        ImGui::TextDisabled("Consulta mcp/README.md para registrar el cliente MCP.");
    }

    // ---- Plugin 1: Anti-debug ----
    if (ImGui::CollapsingHeader("Activar anti-debug", ImGuiTreeNodeFlags_DefaultOpen)) {
        ImGui::TextDisabled("Oculta el debugger al proceso (anti-anti-debug).");
        ImGui::Checkbox("PEB->BeingDebugged = 0", &antiOpt_.beingDebugged);
        ImGui::Checkbox("PEB->NtGlobalFlag (limpiar FLG_HEAP_*)", &antiOpt_.ntGlobalFlag);
        ImGui::Checkbox("Heap Flags / ForceFlags", &antiOpt_.heapFlags);
        ImGui::Checkbox("Re-aplicar en cada pausa", &antiReapply_);
        ImGui::BeginDisabled(!active);
        if (ImGui::Button("Activar anti-debug")) {
            std::string lg;
            bool ok = applyAntiAntiDebug(debugger_, debugger_.is64(), antiOpt_, lg);
            antiActive_ = ok;
            pluginStatus_ = lg; pushLog(lg);
        }
        ImGui::EndDisabled();
        ImGui::SameLine();
        ImGui::TextColored(antiActive_ ? ImVec4(0.5f,1,0.5f,1) : ImVec4(0.7f,0.7f,0.7f,1),
                           antiActive_ ? "ACTIVO" : "inactivo");
        if (!active) ImGui::TextDisabled("(lanza el proceso primero)");
    }

    // ---- Plugin 2: Encontrar OEP ----
    if (ImGui::CollapsingHeader("Encontrar OEP", ImGuiTreeNodeFlags_DefaultOpen)) {
        ImGui::TextDisabled("Traza (saltando calls) hasta salir del stub del packer.");
        uint64_t oep = debugger_.foundOEP() ? debugger_.foundOEP() : pluginOEP_;
        if (oep) {
            ImGui::TextColored(ImVec4(0.5f,1,0.5f,1), "OEP: 0x%s", hex64(oep).c_str());
            ImGui::SameLine();
            if (ImGui::SmallButton("Ir")) gotoAddress(oep);
        } else {
            ImGui::TextDisabled("OEP: (no encontrado)");
        }
        ImGui::BeginDisabled(!paused);
        if (ImGui::Button("Buscar OEP")) {
            // Rango del stub = seccion que contiene el entrypoint
            uint64_t stubLo = pe_.imageBase(), stubHi = pe_.imageBase() + pe_.sizeOfImage();
            uint32_t ep = pe_.entryPoint();
            for (auto& s : pe_.sections()) {
                uint32_t hi = s.virtualAddress + (s.virtualSize ? s.virtualSize : s.rawSize);
                if (ep >= s.virtualAddress && ep < hi) {
                    stubLo = pe_.imageBase() + s.virtualAddress;
                    stubHi = pe_.imageBase() + hi;
                    break;
                }
            }
            uint64_t imgLo = pe_.imageBase(), imgHi = pe_.imageBase() + pe_.sizeOfImage();
            pushLog("Buscando OEP... (puede tardar; usa Pause para abortar)");
            debugger_.findOEP(stubLo, stubHi, imgLo, imgHi);
        }
        ImGui::EndDisabled();
        if (!paused) ImGui::TextDisabled("(pausa el proceso, idealmente en el EntryPoint)");
    }

    // ---- Plugin 3: Dump ----
    if (ImGui::CollapsingHeader("Dump", ImGuiTreeNodeFlags_DefaultOpen)) {
        ImGui::TextDisabled("Vuelca la imagen del proceso a disco (memory-aligned).");
        ImGui::BeginDisabled(!active);
        if (ImGui::Button("Dump a disco")) {
            std::wstring out = loadedPath_ + L"_dump.exe";
            uint64_t oep = debugger_.foundOEP() ? debugger_.foundOEP() : 0;
            std::string lg;
            if (dumpProcess(debugger_, pe_, oep, out, lg)) { lastDumpPath_ = out; }
            pluginStatus_ = lg; pushLog(lg);
        }
        ImGui::EndDisabled();
        if (!lastDumpPath_.empty())
            ImGui::TextWrapped("Ultimo dump: %s", std::string(lastDumpPath_.begin(), lastDumpPath_.end()).c_str());
        if (!active) ImGui::TextDisabled("(lanza el proceso primero)");
    }

    // ---- Plugin 4: Corregir IAT ----
    if (ImGui::CollapsingHeader("Corregir IAT", ImGuiTreeNodeFlags_DefaultOpen)) {
        ImGui::TextDisabled("Resuelve la IAT contra los exports de los modulos cargados.");
        ImGui::BeginDisabled(!active);
        if (ImGui::Button("Solo resolver (log)")) {
            std::vector<IatEntry> iat; std::string lg;
            resolveIAT(debugger_, iat, lg);
            pluginStatus_ = lg; pushLog(lg);
            int shown = 0;
            for (auto& e : iat) {
                pushLog((e.resolved ? "  " : "  ?? ") + e.module + "!" +
                        (e.func.empty() ? "<sin nombre>" : e.func));
                if (++shown >= 60) { pushLog("  ...(truncado)"); break; }
            }
        }
        ImGui::SameLine();
        ImGui::BeginDisabled(lastDumpPath_.empty());
        if (ImGui::Button("Reconstruir en el dump")) {
            std::string lg;
            fixIATInDump(debugger_, lastDumpPath_, lg);
            pluginStatus_ = lg; pushLog(lg);
        }
        ImGui::EndDisabled();
        ImGui::EndDisabled();
        if (lastDumpPath_.empty()) ImGui::TextDisabled("(genera un Dump antes de reconstruir)");
        ImGui::TextDisabled("Reconstruir es EXPERIMENTAL: verifica el .fixed.exe.");
    }

    ImGui::Separator();
    if (ImGui::CollapsingHeader("Plugins externos (JSON)", ImGuiTreeNodeFlags_DefaultOpen)) {
        ImGui::TextDisabled("Directorio: %s\\plugins", exeSiblingDir().c_str());
        if (ImGui::Checkbox("Permitir plugins DLL nativos (solo DLLs confiables)", &allowNativeDllPlugins_)) loadExternalPlugins();
        ImGui::SameLine();
        if (ImGui::SmallButton("Recargar")) loadExternalPlugins();
        ImGui::Checkbox("Hot-reload (recargar al detectar cambios en disco)", &pluginAutoReload_);
        const auto& plugins = externalPlugins_.plugins();
        if (plugins.empty()) ImGui::TextDisabled("No hay manifiestos JSON validos.");
        for (const auto& p : plugins) {
            ImGui::PushID(p.id.c_str());
            if (ImGui::TreeNode(p.name.c_str())) {
                ImGui::TextDisabled("%s  v%s  [%s]", p.id.c_str(), p.version.empty() ? "-" : p.version.c_str(), p.kind == PluginKind::NativeDll ? "DLL" : "JSON");
                if (!p.description.empty()) ImGui::TextWrapped("%s", p.description.c_str());
                for (const auto& a : p.actions) {
                    if (ImGui::Button(a.label.c_str())) {
                        pluginStatus_ = runExternalPluginAction(p.id, a.id);
                        pushLog("Plugin " + p.id + "/" + a.id + ": " + pluginStatus_);
                    }
                    if (!a.description.empty()) { ImGui::SameLine(); ImGui::TextDisabled("%s", a.description.c_str()); }
                }
                ImGui::TreePop();
            }
            ImGui::PopID();
        }
        for (const auto& e : externalPlugins_.errors())
            ImGui::TextColored(ImVec4(1,0.55f,0.4f,1), "%s", e.c_str());
    }

    ImGui::End();
}

// ---------------------------------------------------------------------------
// Anotaciones (comentarios/etiquetas) y referencias
// ---------------------------------------------------------------------------
void App::saveAnnotations() {
    saveAnalysisCache();
}

void App::saveAnalysisCache() {
    if (!fileLoaded_ || loadedPath_.empty()) return;
    const std::wstring path = analysisCachePath(loadedPath_);
    if (path.empty()) return;

    uint64_t sourceSize = 0, sourceWriteTime = 0;
    if (!analysisSourceStamp(loadedPath_, sourceSize, sourceWriteTime)) return;

    try {
        njson cache;
        cache["schemaVersion"] = 1;
        cache["sourcePath"] = std::string(loadedPath_.begin(), loadedPath_.end());
        cache["sourceSize"] = sourceSize;
        cache["sourceWriteTime"] = sourceWriteTime;
        cache["minStringLength"] = minStrLen_;
        cache["strings"] = njson::array();
        for (const auto& s : strings_)
            cache["strings"].push_back({
                {"address", s.address},
                {"kind", s.kind == StrKind::Utf16 ? "utf16" : "ascii"},
                {"text", s.text}
            });
        cache["packers"] = njson::array();
        for (const auto& p : packerMatches_)
            cache["packers"].push_back({
                {"name", p.name}, {"source", p.source}, {"confidence", p.confidence}
            });
        cache["labels"] = njson::array();
        for (const auto& [address, text] : labels_)
            cache["labels"].push_back({{"address", address}, {"text", text}});
        cache["comments"] = njson::array();
        for (const auto& [address, text] : comments_)
            cache["comments"].push_back({{"address", address}, {"text", text}});
        cache["bookmarks"] = njson::array();
        for (const auto& [address, text] : bookmarks_)
            cache["bookmarks"].push_back({{"address", address}, {"text", text}});
        cache["functions"] = njson::array();
        for (const auto& function : analyzedFunctions_)
            cache["functions"].push_back({{"start", function.start}, {"end", function.end}, {"instructions", function.instructions},
                                          {"calls", function.calls}, {"branches", function.branches}, {"name", function.name}});
        cache["xrefs"] = njson::array();
        for (const auto& xref : analysisXrefs_)
            cache["xrefs"].push_back({{"from", xref.from}, {"to", xref.to}, {"type", xref.type}});
        cache["loops"] = njson::array();
        for (const auto& loop : analysisLoops_)
            cache["loops"].push_back({{"start", loop.start}, {"end", loop.end}, {"function", loop.function}});

        std::ofstream file(path, std::ios::binary | std::ios::trunc);
        if (file) file << cache.dump(1);
    } catch (const std::exception& e) {
        pushLog(std::string("Cache de analisis: no se pudo guardar: ") + e.what());
    }
}

bool App::loadAnalysisCache() {
    if (!fileLoaded_ || loadedPath_.empty()) return false;
    const std::wstring path = analysisCachePath(loadedPath_);
    if (path.empty()) return false;

    uint64_t sourceSize = 0, sourceWriteTime = 0;
    if (!analysisSourceStamp(loadedPath_, sourceSize, sourceWriteTime)) return false;

    try {
        std::ifstream file(path, std::ios::binary);
        if (!file) return false;
        const njson cache = njson::parse(file);
        if (cache.value("schemaVersion", 0) != 1 ||
            cache.value("sourceSize", uint64_t{0}) != sourceSize ||
            cache.value("sourceWriteTime", uint64_t{0}) != sourceWriteTime ||
            cache.value("minStringLength", size_t{0}) != minStrLen_)
            return false;

        strings_.clear();
        packerMatches_.clear();
        labels_.clear();
        comments_.clear();
        bookmarks_.clear();
        analyzedFunctions_.clear(); analysisXrefs_.clear(); analysisLoops_.clear();
        for (const auto& item : cache.value("strings", njson::array())) {
            FoundString s;
            s.address = item.value("address", uint64_t{0});
            s.kind = item.value("kind", "ascii") == "utf16" ? StrKind::Utf16 : StrKind::Ascii;
            s.text = item.value("text", "");
            strings_.push_back(std::move(s));
        }
        for (const auto& item : cache.value("packers", njson::array())) {
            PackerMatch p;
            p.name = item.value("name", "");
            p.source = item.value("source", "");
            p.confidence = item.value("confidence", 0);
            packerMatches_.push_back(std::move(p));
        }
        for (const auto& item : cache.value("labels", njson::array()))
            labels_[item.value("address", uint64_t{0})] = item.value("text", "");
        for (const auto& item : cache.value("comments", njson::array()))
            comments_[item.value("address", uint64_t{0})] = item.value("text", "");
        for (const auto& item : cache.value("bookmarks", njson::array()))
            bookmarks_[item.value("address", uint64_t{0})] = item.value("text", "");
        for (const auto& item : cache.value("functions", njson::array()))
            analyzedFunctions_.push_back({item.value("start", uint64_t{0}), item.value("end", uint64_t{0}),
                                          item.value("instructions", uint32_t{0}), item.value("calls", uint32_t{0}),
                                          item.value("branches", uint32_t{0}), item.value("name", "")});
        for (const auto& item : cache.value("xrefs", njson::array()))
            analysisXrefs_.push_back({item.value("from", uint64_t{0}), item.value("to", uint64_t{0}), item.value("type", "")});
        for (const auto& item : cache.value("loops", njson::array()))
            analysisLoops_.push_back({item.value("start", uint64_t{0}), item.value("end", uint64_t{0}), item.value("function", uint64_t{0})});

        analysisCacheLoaded_ = true;
        pushLog("Cache de analisis cargada: strings, packers, anotaciones, funciones y xrefs restaurados.");
        return true;
    } catch (const std::exception& e) {
        pushLog(std::string("Cache de analisis ignorada: ") + e.what());
        return false;
    }
}

void App::loadAnnotations() {
    if (loadAnalysisCache()) return;

    // Migracion no destructiva del formato usado por versiones anteriores.
    // La proxima exploracion completa lo incorporara al JSON de cache.
    if (loadedPath_.empty()) return;
    std::ifstream file((loadedPath_ + L".annot.txt").c_str());
    if (!file) return;
    std::string line;
    while (std::getline(file, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        const size_t p1 = line.find('|'); if (p1 == std::string::npos) continue;
        const size_t p2 = line.find('|', p1 + 1); if (p2 == std::string::npos) continue;
        const uint64_t address = strtoull(line.substr(0, p1).c_str(), nullptr, 16);
        const std::string type = line.substr(p1 + 1, p2 - p1 - 1);
        const std::string text = line.substr(p2 + 1);
        if (type == "L") labels_[address] = text;
        else if (type == "C") comments_[address] = text;
    }
    if (!labels_.empty() || !comments_.empty())
        pushLog("Anotaciones antiguas migradas; se guardaran en la cache de analisis.");
}
void App::findReferences(uint64_t addr) {
    refs_.clear(); refTarget_ = addr;
    for (auto& in : insns_) if (in.hasBranchTarget && in.branchTarget == addr) refs_.push_back(in.address);
    for (const auto& xref : analysisXrefs_) if (xref.to == addr) refs_.push_back(xref.from);
    if (fileLoaded_) {
        size_t ptr = pe_.is64Bit() ? 8 : 4;
        const auto& raw = pe_.raw();
        for (size_t i = 0; i + ptr <= raw.size(); ++i) {
            uint64_t v = 0; std::memcpy(&v, raw.data() + i, ptr);
            if (v == addr) {
                for (auto& s : pe_.sections())
                    if (i >= s.rawOffset && i < (size_t)s.rawOffset + s.rawSize) {
                        refs_.push_back(pe_.imageBase() + s.virtualAddress + (i - s.rawOffset)); break;
                    }
            }
            if (refs_.size() > 5000) break;
        }
    }
    std::sort(refs_.begin(), refs_.end());
    refs_.erase(std::unique(refs_.begin(), refs_.end()), refs_.end());
    pushLog("Referencias a 0x" + hex64(addr) + ": " + std::to_string(refs_.size()));
    winVisible_["Referencias"] = true;
}
// M4: manda una muestra del run-trace a la IA para que explique el flujo.
void App::summarizeTraceWithAi() {
    if (aiBusy_) return;
    const AiAgent* ag = aiConfig_.current();
    if (!ag) { pushLog("No hay agente de IA configurado."); return; }
    ai_.setAgent(*ag);

    auto log = debugger_.traceLog();
    if (log.empty()) { pushLog("No hay traza que resumir."); return; }

    // Muestra: hasta 300 direcciones (con simbolo si esta pausado) para no saturar el contexto.
    std::string sample;
    size_t step = log.size() > 300 ? log.size() / 300 : 1;
    for (size_t i = 0; i < log.size(); i += step) {
        std::string sym = (dbgState_ == DbgState::Paused) ? debugger_.symbolAt(log[i]) : "";
        sample += "0x" + hex64(log[i]) + (sym.empty() ? "" : ("  " + sym)) + "\n";
    }
    std::string prompt = "Traza de ejecucion (" + std::to_string(log.size()) +
        " instrucciones, muestra de " + std::to_string((log.size()+step-1)/step) + "):\n" + sample +
        "\nResume el flujo: bucles/rutinas repetidas (posible descifrado), APIs o modulos tocados, "
        "y cualquier patron sospechoso. Se breve y tecnico.";

    { std::lock_guard<std::mutex> lk(aiMutex_); chat_.push_back({"user", "[Resumir run-trace]"}); }
    aiBusy_ = true; aiError_.clear();
    if (aiThread_.joinable()) aiThread_.join();
    aiThread_ = std::thread([this, prompt]() {
        std::vector<ChatMessage> h; h.push_back({"user", prompt});
        std::string err;
        std::string resp = ai_.send("Eres un analista de malware experto en interpretar trazas de ejecucion. Responde en espanol.", h, 2048, err);
        std::lock_guard<std::mutex> lk(aiMutex_);
        if (!resp.empty()) chat_.push_back({"assistant", resp});
        else chat_.push_back({"assistant", "[error] " + err});
        aiBusy_ = false;
    });
    pushLog("Enviando run-trace a la IA (ver panel IA).");
}

void App::drawTracePanel() {
    ImGui::Begin("Run trace");
    bool paused = (dbgState_ == DbgState::Paused);
    ImGui::BeginDisabled(!paused);
    if (ImGui::Button("Start trace")) debugger_.runTrace();
    ImGui::EndDisabled();
    ImGui::SameLine();
    ImGui::BeginDisabled(dbgState_ != DbgState::Running);
    if (ImGui::Button("Stop trace")) debugger_.pause();
    ImGui::EndDisabled();
    ImGui::SameLine();
    ImGui::BeginDisabled(aiBusy_ || debugger_.traceLog().empty());
    if (ImGui::Button("Resumir con IA")) summarizeTraceWithAi();   // M4
    ImGui::EndDisabled();
    ImGui::TextDisabled("Single-step de cada instruccion (lento). Stop = Pause.");

    auto log = debugger_.traceLog();
    ImGui::Text("%zu instrucciones registradas", log.size());
    ImGui::Separator();
    ImGui::BeginChild("trlist", ImVec2(0, 0), false);
    ImGuiListClipper clip; clip.Begin((int)log.size());
    while (clip.Step()) {
        for (int i = clip.DisplayStart; i < clip.DisplayEnd; ++i) {
            ImGui::PushID(i);
            std::string sym = paused ? debugger_.symbolAt(log[i]) : "";
            if (ImGui::Selectable((("0x" + hex64(log[i])) + (sym.empty() ? "" : ("  " + sym))).c_str()))
                gotoAddress(log[i]);
            ImGui::PopID();
        }
    }
    ImGui::EndChild();
    ImGui::End();
}

void App::drawReferencesPanel() {
    ImGui::Begin("Referencias");
    if (refTarget_) ImGui::Text("Referencias a 0x%s  (%zu)", hex64(refTarget_).c_str(), refs_.size());
    else ImGui::TextDisabled("Clic derecho en el CPU -> Buscar referencias.");
    ImGui::Separator();
    ImGui::BeginChild("refslist", ImVec2(0, 0), false);
    for (auto a : refs_) {
        ImGui::PushID((int)(a ^ (a >> 32)));
        if (ImGui::Selectable(("0x" + hex64(a)).c_str())) gotoAddress(a);
        ImGui::PopID();
    }
    ImGui::EndChild();
    ImGui::End();
}

// ---------------------------------------------------------------------------
// Search for (menu CPU estilo OllyDbg/x64dbg): All commands, All intermodular
// calls y Binary string. Los resultados van a la ventana "Search results".
// ---------------------------------------------------------------------------
static std::string toLowerCopy(const std::string& s) {
    std::string r = s;
    for (char& c : r) c = (char)std::tolower((unsigned char)c);
    return r;
}

// Extrae la VA de un operando de memoria "[0x...]" (call/jmp indirectos).
static bool extractBracketVA(const std::string& text, uint64_t& va) {
    size_t lb = text.find('[');
    if (lb == std::string::npos) return false;
    size_t rb = text.find(']', lb);
    if (rb == std::string::npos) return false;
    std::string inner = text.substr(lb + 1, rb - lb - 1);
    size_t hx = inner.find("0x");
    if (hx == std::string::npos) return false;   // solo aceptamos VA absoluta, no [reg+...]
    va = strtoull(inner.c_str() + hx + 2, nullptr, 16);
    return va != 0;
}

void App::searchAllCommands(const std::string& needle) {
    searchResults_.clear();
    std::string q = toLowerCopy(needle);
    for (const auto& in : insns_)
        if (toLowerCopy(in.text).find(q) != std::string::npos)
            searchResults_.push_back({ in.address, in.text });
    searchResultsTitle_ = "All commands: \"" + needle + "\"  (" + std::to_string(searchResults_.size()) + ")";
    showSearchResults_ = true;
    pushLog(searchResultsTitle_);
}

void App::searchIntermodularCalls() {
    searchResults_.clear();
    if (!fileLoaded_) { pushLog("Abre un ejecutable primero."); return; }

    // Mapa VA-del-slot-IAT -> "DLL!nombre" (destino de las llamadas a otros modulos).
    std::map<uint64_t, std::string> iat;
    for (const auto& imp : pe_.imports()) {
        std::string nm = imp.name.empty()
            ? (imp.dll + "!#" + std::to_string(imp.ordinal))
            : (imp.dll + "!" + imp.name);
        iat[pe_.imageBase() + imp.iatRva] = nm;
    }
    if (iat.empty()) { pushLog("El PE no tiene tabla de imports."); return; }

    // Mapa VA-instruccion -> indice, para resolver thunks (call directo a un jmp [IAT]).
    std::map<uint64_t, size_t> byAddr;
    for (size_t i = 0; i < insns_.size(); ++i) byAddr[insns_[i].address] = i;

    for (const auto& in : insns_) {
        if (!in.isCall && !in.isJump) continue;
        uint64_t memVA = 0;
        // (a) indirecto: call/jmp [IAT]
        if (extractBracketVA(in.text, memVA)) {
            auto it = iat.find(memVA);
            if (it != iat.end()) { searchResults_.push_back({ in.address, in.text + "  ; " + it->second }); continue; }
        }
        // (b) directo a un thunk que salta a la IAT: call target ; target: jmp [IAT]
        if (in.hasBranchTarget) {
            auto bi = byAddr.find(in.branchTarget);
            if (bi != byAddr.end()) {
                const auto& tgt = insns_[bi->second];
                uint64_t thunkVA = 0;
                if (tgt.isJump && extractBracketVA(tgt.text, thunkVA)) {
                    auto it = iat.find(thunkVA);
                    if (it != iat.end()) searchResults_.push_back({ in.address, in.text + "  ; " + it->second });
                }
            }
        }
    }
    searchResultsTitle_ = "Intermodular calls  (" + std::to_string(searchResults_.size()) + ")";
    showSearchResults_ = true;
    pushLog(searchResultsTitle_);
}

void App::searchBinaryString(const std::string& pattern, bool isHex, bool utf16) {
    searchResults_.clear();
    const uint8_t* data = nullptr; size_t len = 0; uint64_t base = 0;
    if (dbgState_ == DbgState::Paused && memBase_ && !memBuf_.empty()) {
        data = memBuf_.data(); len = memBuf_.size(); base = memBase_;
    } else if (fileLoaded_) {
        data = pe_.raw().data(); len = pe_.raw().size(); base = pe_.imageBase();
    }
    if (!data) { pushLog("No hay datos donde buscar."); return; }

    std::vector<uint64_t> hits;
    if (isHex) {
        std::string perr;
        hits = searchHex(data, len, base, pattern, perr, 5000);
        if (!perr.empty()) { pushLog("Binary string: " + perr); return; }
    } else {
        hits = searchText(data, len, base, pattern, utf16, 5000);
    }
    for (uint64_t h : hits) searchResults_.push_back({ h, isHex ? "hex" : (utf16 ? "utf16" : "ascii") });
    searchResultsTitle_ = std::string("Binary string  (") + std::to_string(searchResults_.size()) + ")";
    showSearchResults_ = true;
    pushLog(searchResultsTitle_);
}

void App::drawSearchResultsPanel() {
    ImGui::SetNextWindowSize(ImVec2(560, 360), ImGuiCond_FirstUseEver);
    if (!ImGui::Begin("Search results", &showSearchResults_)) { ImGui::End(); return; }
    ImGui::TextUnformatted(searchResultsTitle_.c_str());
    ImGui::SameLine();
    if (ImGui::SmallButton("Copiar todo")) {
        std::string all;
        for (auto& h : searchResults_) all += "0x" + hex64(h.address) + "  " + h.text + "\n";
        ImGui::SetClipboardText(all.c_str());
    }
    ImGui::Separator();
    ImGui::TextDisabled("Doble clic en una fila para ir a la direccion.");
    if (ImGui::BeginTable("sr", 2, ImGuiTableFlags_Resizable | ImGuiTableFlags_ScrollY | ImGuiTableFlags_RowBg)) {
        ImGui::TableSetupColumn("Direccion", ImGuiTableColumnFlags_WidthFixed, 150);
        ImGui::TableSetupColumn("Instruccion / tipo");
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableHeadersRow();
        for (int i = 0; i < (int)searchResults_.size(); ++i) {
            const auto& h = searchResults_[i];
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            ImGui::PushID(i);
            std::string va = "0x" + hex64(h.address);
            if (ImGui::Selectable(va.c_str(), false, ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowDoubleClick)
                && ImGui::IsMouseDoubleClicked(0))
                gotoAddress(h.address);
            ImGui::PopID();
            ImGui::TableSetColumnIndex(1);
            ImGui::TextUnformatted(h.text.c_str());
        }
        ImGui::EndTable();
    }
    ImGui::End();
}

// ---------------------------------------------------------------------------
// Motor de expresiones (Fase 2) + IA como funcion de expresion (M9)
// ---------------------------------------------------------------------------
EvalContext App::makeEvalContext() {
    EvalContext ec;
    ec.readReg = [this](const std::string& n, uint64_t& out) -> bool {
        if (dbgState_ != DbgState::Paused) return false;
        Registers r = debugger_.registers();
        static const std::map<std::string, uint64_t Registers::*> m64 = {
            {"rax",&Registers::rax},{"rbx",&Registers::rbx},{"rcx",&Registers::rcx},{"rdx",&Registers::rdx},
            {"rsi",&Registers::rsi},{"rdi",&Registers::rdi},{"rbp",&Registers::rbp},{"rsp",&Registers::rsp},
            {"rip",&Registers::rip},{"r8",&Registers::r8},{"r9",&Registers::r9},{"r10",&Registers::r10},
            {"r11",&Registers::r11},{"r12",&Registers::r12},{"r13",&Registers::r13},{"r14",&Registers::r14},
            {"r15",&Registers::r15},
            // alias 32-bit -> mismo campo (parte baja)
            {"eax",&Registers::rax},{"ebx",&Registers::rbx},{"ecx",&Registers::rcx},{"edx",&Registers::rdx},
            {"esi",&Registers::rsi},{"edi",&Registers::rdi},{"ebp",&Registers::rbp},{"esp",&Registers::rsp},
            {"eip",&Registers::rip},
        };
        auto it = m64.find(n);
        if (it != m64.end()) {
            uint64_t v = r.*(it->second);
            if (n[0] == 'e') v &= 0xFFFFFFFFull;  // registros de 32 bits
            out = v; return true;
        }
        if (n == "eflags") { out = r.eflags; return true; }
        return false;
    };
    ec.readMem = [this](uint64_t va, void* out, size_t len) -> size_t {
        if (dbgState_ == DbgState::Paused) return debugger_.readMemory(va, out, len);
        if (fileLoaded_) return pe_.readAtRva((uint32_t)(va - pe_.imageBase()), (uint8_t*)out, len);
        return 0;
    };
    ec.moduleBase = [this](uint64_t va) -> uint64_t {
        for (auto& m : memMap_) if (va >= m.base && va < m.base + m.size && !m.moduleName.empty()) return m.base;
        if (fileLoaded_ && va >= pe_.imageBase() && va < pe_.imageBase() + pe_.sizeOfImage()) return pe_.imageBase();
        return 0;
    };
    ec.moduleSize = [this](uint64_t va) -> uint64_t {
        if (fileLoaded_ && va >= pe_.imageBase() && va < pe_.imageBase() + pe_.sizeOfImage()) return pe_.sizeOfImage();
        return 0;
    };
    ec.moduleFromName = [this](const std::string& name) -> uint64_t {
        for (auto& m : debugger_.modules()) {
            std::string mn = m.name; for (char& c : mn) c = (char)std::tolower((unsigned char)c);
            std::string q = name; for (char& c : q) c = (char)std::tolower((unsigned char)c);
            if (mn == q) return m.base;
        }
        return 0;
    };
    ec.disasmLen = [this](uint64_t va) -> uint32_t {
        uint8_t buf[16] = {0};
        size_t got = (dbgState_ == DbgState::Paused) ? debugger_.readMemory(va, buf, sizeof(buf))
                   : (fileLoaded_ ? pe_.readAtRva((uint32_t)(va - pe_.imageBase()), buf, sizeof(buf)) : 0);
        if (!got) return 0;
        dis_.setMode(dbgState_ == DbgState::Paused ? debugger_.is64() : pe_.is64Bit());
        auto v = dis_.disassemble(buf, got, va, 1);
        return v.empty() ? 0 : v[0].length;
    };
    return ec;
}

bool App::evalExpr(const std::string& expr, uint64_t& out, std::string& err) {
    ExprEval ev(makeEvalContext());
    // M9: la IA como funcion de expresion. ai.name(addr) sugiere un nombre; ai.classify(addr)
    // devuelve 1 si la IA la considera relevante/maliciosa. Sincronas y lentas: uso ocasional.
    ev.registerFunction("ai.classify", [this](const std::vector<EvalValue>& a, EvalValue& o, std::string& e) -> bool {
        if (a.empty()) { e = "ai.classify(addr)"; return false; }
        const AiAgent* ag = aiConfig_.current();
        if (!ag) { e = "sin agente de IA"; return false; }
        ai_.setAgent(*ag);
        uint64_t va = a[0].num;
        uint8_t buf[64] = {0};
        size_t got = (dbgState_==DbgState::Paused) ? debugger_.readMemory(va, buf, sizeof(buf))
                   : (fileLoaded_ ? pe_.readAtRva((uint32_t)(va-pe_.imageBase()), buf, sizeof(buf)) : 0);
        std::string hexs; for (size_t k=0;k<got;k++){ char b[4]; std::snprintf(b,sizeof(b),"%02X ",buf[k]); hexs+=b; }
        std::vector<ChatMessage> h; h.push_back({"user",
            "Bytes en 0x" + hex64(va) + ": " + hexs +
            ". Responde SOLO '1' si este codigo parece relevante para analisis de malware (cifrado, syscalls, anti-debug), o '0' si es rutinario. Un solo caracter."});
        std::string er; std::string resp = ai_.send("Eres un clasificador binario. Responde 1 o 0.", h, 8, er);
        o = EvalValue::N(resp.find('1') != std::string::npos ? 1 : 0); return true;
    });
    return ev.eval(expr, out, err);
}

// ---------------------------------------------------------------------------
// Command bar hibrida (M1): expresiones (?expr), comandos JSON, o lenguaje natural (IA)
// ---------------------------------------------------------------------------
void App::execCommandBar() {
    std::string line = cmdBar_;
    // recortar espacios
    while (!line.empty() && std::isspace((unsigned char)line.front())) line.erase(line.begin());
    while (!line.empty() && std::isspace((unsigned char)line.back())) line.pop_back();
    if (line.empty()) return;

    if (cmdBarUseAi_) {
        // Manda la instruccion al panel de IA en modo agente (control del debugger).
        std::snprintf(aiInput_, sizeof(aiInput_), "%s", line.c_str());
        bool prevCtx = aiIncludeContext_;
        aiAgentMode_ = true;
        sendAiMessage();
        aiIncludeContext_ = prevCtx;
        cmdBarResult_ = "Enviado a la IA (ver panel IA).";
        cmdBar_[0] = '\0';
        return;
    }
    if (line[0] == '?') {                 // evaluar expresion, estilo x64dbg
        uint64_t v = 0; std::string err;
        if (evalExpr(line.substr(1), v, err))
            cmdBarResult_ = "= 0x" + hex64(v) + "  (" + std::to_string(v) + ")";
        else cmdBarResult_ = "error: " + err;
    } else if (line[0] == '{') {          // comando MCP crudo
        cmdBarResult_ = execDbgCommand(line);
    } else {                              // "cmd" o "cmd {json}"
        std::string cmd = line, args = "{}";
        auto sp = line.find(' ');
        if (sp != std::string::npos) { cmd = line.substr(0, sp); args = line.substr(sp + 1); }
        njson req; req["cmd"] = cmd;
        try { req["args"] = njson::parse(args); } catch (...) { req["args"] = njson::object(); }
        cmdBarResult_ = execDbgCommand(req.dump());
    }
    cmdBar_[0] = '\0';
}

void App::drawCommandBar() {
    ImGui::Begin("Command");
    ImGui::TextDisabled("?expr  (evalua) | cmd {args} (tool dbg_*) | JSON crudo | o activa IA para lenguaje natural");
    ImGui::Checkbox("Usar IA (lenguaje natural -> controla el debugger)", &cmdBarUseAi_);
    ImGui::SetNextItemWidth(-1);
    if (ImGui::InputText("##cmdbar", cmdBar_, sizeof(cmdBar_), ImGuiInputTextFlags_EnterReturnsTrue)) {
        execCommandBar();
        ImGui::SetKeyboardFocusHere(-1);
    }
    if (!cmdBarResult_.empty()) {
        ImGui::Separator();
        ImGui::TextWrapped("%s", cmdBarResult_.c_str());
    }
    ImGui::End();
}

// ---------------------------------------------------------------------------
// Watch (M2): evalua una lista de expresiones en cada pausa
// ---------------------------------------------------------------------------
void App::refreshWatches() {
    for (auto& w : watches_) {
        uint64_t v = 0; std::string err;
        w.ok = evalExpr(w.expr, v, err);
        w.value = w.ok ? ("0x" + hex64(v)) : ("err: " + err);
    }
}

void App::drawWatchPanel() {
    ImGui::Begin("Watch");
    ImGui::SetNextItemWidth(-90);
    bool add = ImGui::InputTextWithHint("##watchin", "expr: dword(esp+4)  |  [eax]  |  rip - mod.base(rip)",
                   watchInput_, sizeof(watchInput_), ImGuiInputTextFlags_EnterReturnsTrue);
    ImGui::SameLine();
    if ((ImGui::Button("Agregar") || add) && watchInput_[0]) {
        watches_.push_back({ watchInput_, "", true });
        watchInput_[0] = '\0';
        refreshWatches();
    }
    ImGui::SameLine();
    if (ImGui::Button("Refrescar")) refreshWatches();
    ImGui::Separator();
    if (ImGui::BeginTable("watches", 3, ImGuiTableFlags_Resizable | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY)) {
        ImGui::TableSetupColumn("Expresion");
        ImGui::TableSetupColumn("Valor", ImGuiTableColumnFlags_WidthFixed, 170);
        ImGui::TableSetupColumn("", ImGuiTableColumnFlags_WidthFixed, 30);
        ImGui::TableHeadersRow();
        int del = -1;
        for (int i = 0; i < (int)watches_.size(); ++i) {
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0); ImGui::TextUnformatted(watches_[i].expr.c_str());
            ImGui::TableSetColumnIndex(1);
            ImGui::TextColored(watches_[i].ok ? ImVec4(0.7f,1,0.7f,1) : ImVec4(1,0.6f,0.6f,1), "%s", watches_[i].value.c_str());
            ImGui::TableSetColumnIndex(2);
            ImGui::PushID(i);
            if (ImGui::SmallButton("x")) del = i;
            ImGui::PopID();
        }
        if (del >= 0) watches_.erase(watches_.begin() + del);
        ImGui::EndTable();
    }
    ImGui::End();
}

// M3: al golpear un BP con accion asociada, ejecutarla. La accion puede ser:
//   - "ai:<prompt>"  -> manda el prompt (con contexto) al agente de IA.
//   - "{...}"         -> comando MCP crudo.
//   - "cmd {args}"    -> tool dbg_* con args JSON.
void App::runBreakpointAction(uint64_t addr) {
    auto it = bpActions_.find(addr);
    if (it == bpActions_.end() || it->second.empty()) return;
    std::string act = it->second;
    pushLog("BP 0x" + hex64(addr) + " accion: " + act);
    if (act.rfind("ai:", 0) == 0) {
        std::snprintf(aiInput_, sizeof(aiInput_), "%s", act.substr(3).c_str());
        aiAgentMode_ = true;
        sendAiMessage();
        return;
    }
    std::string out;
    if (act[0] == '{') out = execDbgCommand(act);
    else {
        std::string cmd = act, args = "{}";
        auto sp = act.find(' ');
        if (sp != std::string::npos) { cmd = act.substr(0, sp); args = act.substr(sp + 1); }
        njson req; req["cmd"] = cmd;
        try { req["args"] = njson::parse(args); } catch (...) { req["args"] = njson::object(); }
        out = execDbgCommand(req.dump());
    }
    pushLog("  -> " + (out.size() > 200 ? out.substr(0, 200) + "..." : out));
}

// ---------------------------------------------------------------------------
// Struct viewer (M8): aplica una definicion de campos a una direccion base
// ---------------------------------------------------------------------------
void App::drawStructPanel() {
    ImGui::Begin("Struct");
    ImGui::TextDisabled("Aplica una struct a una direccion. La base admite expresiones (rax, 0x401000, dword(esp)).");
    ImGui::SetNextItemWidth(240);
    ImGui::InputTextWithHint("Base", "ej: rax  |  0x401000", structBase_, sizeof(structBase_));
    ImGui::SameLine();
    if (ImGui::Button("+ Campo")) structFields_.push_back(StructField{});
    ImGui::SameLine();
    if (ImGui::Button("Limpiar##struct")) structFields_.clear();

    uint64_t base = 0; std::string baseErr;
    bool baseOk = structBase_[0] && evalExpr(structBase_, base, baseErr);

    static const char* typeNames[] = { "byte", "word", "dword", "qword", "ptr", "string" };
    static const int   typeSizes[] = { 1, 2, 4, 8, 8, 16 };

    if (ImGui::BeginTable("struct", 5, ImGuiTableFlags_Resizable | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY)) {
        ImGui::TableSetupColumn("Off", ImGuiTableColumnFlags_WidthFixed, 50);
        ImGui::TableSetupColumn("Tipo", ImGuiTableColumnFlags_WidthFixed, 90);
        ImGui::TableSetupColumn("Nombre", ImGuiTableColumnFlags_WidthFixed, 130);
        ImGui::TableSetupColumn("Valor");
        ImGui::TableSetupColumn("", ImGuiTableColumnFlags_WidthFixed, 28);
        ImGui::TableHeadersRow();
        uint32_t off = 0;
        int del = -1;
        for (int i = 0; i < (int)structFields_.size(); ++i) {
            auto& f = structFields_[i];
            ImGui::TableNextRow();
            ImGui::PushID(i);
            ImGui::TableSetColumnIndex(0); ImGui::Text("+%u", off);
            ImGui::TableSetColumnIndex(1);
            ImGui::SetNextItemWidth(-1);
            ImGui::Combo("##ty", &f.type, typeNames, IM_ARRAYSIZE(typeNames));
            if (f.type < 0 || f.type > 5) f.type = 2;
            ImGui::TableSetColumnIndex(2);
            ImGui::SetNextItemWidth(-1);
            ImGui::InputText("##nm", f.name, sizeof(f.name));
            ImGui::TableSetColumnIndex(3);
            if (baseOk) {
                uint64_t addr = base + off;
                if (f.type == 5) {   // string ASCII
                    char sbuf[17] = {0};
                    makeEvalContext().readMem ? (void)0 : (void)0;
                    size_t got = (dbgState_==DbgState::Paused) ? debugger_.readMemory(addr, sbuf, 16)
                               : (fileLoaded_ ? pe_.readAtRva((uint32_t)(addr-pe_.imageBase()), (uint8_t*)sbuf, 16) : 0);
                    for (size_t k=0;k<got;k++) if ((unsigned char)sbuf[k] < 32 || (unsigned char)sbuf[k] > 126) sbuf[k]='.';
                    ImGui::Text("\"%s\"", sbuf);
                } else {
                    uint64_t v = 0;
                    size_t got = (dbgState_==DbgState::Paused) ? debugger_.readMemory(addr, &v, typeSizes[f.type])
                               : (fileLoaded_ ? pe_.readAtRva((uint32_t)(addr-pe_.imageBase()), (uint8_t*)&v, typeSizes[f.type]) : 0);
                    if (got) ImGui::Text("0x%llX  (%llu)", (unsigned long long)v, (unsigned long long)v);
                    else ImGui::TextDisabled("<no leido>");
                }
            } else ImGui::TextDisabled("%s", baseErr.empty() ? "" : baseErr.c_str());
            ImGui::TableSetColumnIndex(4);
            if (ImGui::SmallButton("x")) del = i;
            ImGui::PopID();
            off += typeSizes[f.type];
        }
        if (del >= 0) structFields_.erase(structFields_.begin() + del);
        ImGui::EndTable();
        ImGui::Text("Tamano total: %u bytes", off);
    }
    ImGui::End();
}

void App::drawAnalysisPanel() {
    ImGui::Begin("Analysis");
    ImGui::TextDisabled("Resultados persistentes de Analyze this. Son analisis estaticos/lineales, no un decompilador completo.");
    ImGui::SameLine();
    if (ImGui::SmallButton("Analyze CPU")) {
        if (selectedInsn_ >= 0 && selectedInsn_ < (int)insns_.size()) analyzeCodeAt(insns_[selectedInsn_].address);
        else if (!insns_.empty()) analyzeCodeAt(insns_.front().address);
    }
    ImGui::SameLine();
    if (ImGui::SmallButton("Limpiar auto")) clearAutoAnalysis();
    if (ImGui::BeginTabBar("analysis_tabs")) {
        if (ImGui::BeginTabItem("Funciones")) {
            ImGui::Text("%zu funciones candidatas", analyzedFunctions_.size());
            if (ImGui::BeginTable("analysis_funcs", 5, ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders | ImGuiTableFlags_ScrollY)) {
                ImGui::TableSetupColumn("Inicio", ImGuiTableColumnFlags_WidthFixed, 145);
                ImGui::TableSetupColumn("Fin", ImGuiTableColumnFlags_WidthFixed, 145);
                ImGui::TableSetupColumn("Nombre", ImGuiTableColumnFlags_WidthStretch);
                ImGui::TableSetupColumn("Inst", ImGuiTableColumnFlags_WidthFixed, 48);
                ImGui::TableSetupColumn("Call/Jmp", ImGuiTableColumnFlags_WidthFixed, 75);
                ImGui::TableHeadersRow();
                for (const auto& function : analyzedFunctions_) {
                    ImGui::TableNextRow(); ImGui::PushID(static_cast<int>(function.start));
                    ImGui::TableSetColumnIndex(0);
                    if (ImGui::Selectable(("0x" + hex64(function.start)).c_str())) gotoAddress(function.start);
                    ImGui::TableSetColumnIndex(1); ImGui::Text("0x%s", hex64(function.end).c_str());
                    ImGui::TableSetColumnIndex(2); ImGui::TextUnformatted(function.name.empty() ? "-" : function.name.c_str());
                    ImGui::TableSetColumnIndex(3); ImGui::Text("%u", function.instructions);
                    ImGui::TableSetColumnIndex(4); ImGui::Text("%u/%u", function.calls, function.branches);
                    ImGui::PopID();
                }
                ImGui::EndTable();
            }
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Xrefs")) {
            ImGui::Text("%zu referencias de call/jump", analysisXrefs_.size());
            if (ImGui::BeginTable("analysis_xrefs", 3, ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders | ImGuiTableFlags_ScrollY)) {
                ImGui::TableSetupColumn("Desde", ImGuiTableColumnFlags_WidthFixed, 150);
                ImGui::TableSetupColumn("Destino", ImGuiTableColumnFlags_WidthFixed, 150);
                ImGui::TableSetupColumn("Tipo", ImGuiTableColumnFlags_WidthStretch); ImGui::TableHeadersRow();
                for (const auto& xref : analysisXrefs_) {
                    ImGui::TableNextRow(); ImGui::PushID(static_cast<int>(xref.from ^ xref.to));
                    ImGui::TableSetColumnIndex(0); if (ImGui::Selectable(("0x" + hex64(xref.from)).c_str())) gotoAddress(xref.from);
                    ImGui::TableSetColumnIndex(1); if (ImGui::Selectable(("0x" + hex64(xref.to)).c_str())) gotoAddress(xref.to);
                    ImGui::TableSetColumnIndex(2); ImGui::TextUnformatted(xref.type.c_str()); ImGui::PopID();
                }
                ImGui::EndTable();
            }
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Loops")) {
            ImGui::Text("%zu bucles detectados por salto hacia atras", analysisLoops_.size());
            for (const auto& loop : analysisLoops_) {
                ImGui::PushID(static_cast<int>(loop.start ^ loop.end));
                if (ImGui::Selectable(("0x" + hex64(loop.start) + " -> 0x" + hex64(loop.end)).c_str())) gotoAddress(loop.start);
                ImGui::PopID();
            }
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Bookmarks")) {
            ImGui::Text("%zu bookmarks", bookmarks_.size());
            for (const auto& [address, text] : bookmarks_) {
                ImGui::PushID(static_cast<int>(address));
                if (ImGui::Selectable(("0x" + hex64(address) + "  " + text).c_str())) gotoAddress(address);
                ImGui::SameLine();
                if (ImGui::SmallButton("quitar")) { bookmarks_.erase(address); saveAnnotations(); break; }
                ImGui::PopID();
            }
            ImGui::EndTabItem();
        }
        ImGui::EndTabBar();
    }
    ImGui::End();
}

// ---------------------------------------------------------------------------
// Barra de estado inferior (estilo OllyDbg: Running verde / Paused amarillo)
// ---------------------------------------------------------------------------
void App::drawStatusBar() {
    const ImGuiViewport* vp = ImGui::GetMainViewport();
    float h = ImGui::GetFrameHeight() + 4;
    ImGui::SetNextWindowPos(ImVec2(vp->WorkPos.x, vp->WorkPos.y + vp->WorkSize.y - h));
    ImGui::SetNextWindowSize(ImVec2(vp->WorkSize.x, h));
    ImGuiWindowFlags f = ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
                         ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoScrollbar |
                         ImGuiWindowFlags_NoScrollWithMouse | ImGuiWindowFlags_NoSavedSettings;
    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 0.0f);
    ImGui::Begin("##statusbar", nullptr, f);

    // Izquierda: archivo + arquitectura
    if (fileLoaded_) {
        std::string p(loadedPath_.begin(), loadedPath_.end());
        auto pos = p.find_last_of("\\/");
        ImGui::Text("%s  [%s]", pos == std::string::npos ? p.c_str() : p.c_str() + pos + 1,
                    (dbgState_ == DbgState::Paused ? debugger_.is64() : pe_.is64Bit()) ? "x64" : "x86");
    } else {
        ImGui::TextDisabled("sin archivo");
    }
    if (dbgState_ == DbgState::Paused) {
        ImGui::SameLine(); ImGui::Text("| RIP=0x%s", hex64(currentIp_).c_str());
    }
    if (mcp_.running()) {
        ImGui::SameLine(); ImGui::TextColored(ImVec4(0.6f,0.8f,1,1), "| MCP:%d (%d)", mcp_.port(), mcp_.clients());
    }

    // Derecha: caja de estado coloreada
    const char* st = "Terminated"; ImVec4 bg(0.4f,0.4f,0.4f,1);
    switch (dbgState_) {
        case DbgState::Idle:      st = "Idle";      bg = ImVec4(0.35f,0.35f,0.35f,1); break;
        case DbgState::Launching: st = "Launching"; bg = ImVec4(0.30f,0.45f,0.70f,1); break;
        case DbgState::Running:   st = "Running";   bg = ImVec4(0.15f,0.55f,0.15f,1); break; // verde
        case DbgState::Paused:    st = "Paused";    bg = ImVec4(0.75f,0.60f,0.10f,1); break; // amarillo
        case DbgState::Exited:    st = "Terminated";bg = ImVec4(0.55f,0.20f,0.20f,1); break;
    }
    float boxW = 110;
    ImGui::SameLine(ImGui::GetWindowWidth() - boxW - 8);
    ImGui::PushStyleColor(ImGuiCol_Button, bg);
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, bg);
    ImGui::PushStyleColor(ImGuiCol_ButtonActive, bg);
    ImGui::Button(st, ImVec2(boxW, 0));
    ImGui::PopStyleColor(3);

    ImGui::End();
    ImGui::PopStyleVar();
}

// ---------------------------------------------------------------------------
// Executable modules (estilo Olly): Base | Tamano | Nombre | Ruta
// ---------------------------------------------------------------------------
void App::drawExecModulesPanel() {
    ImGui::Begin("Executable modules");
    auto mods = debugger_.modules();
    ImGui::Text("%zu modulos cargados (doble clic para abrir codigo)", mods.size());
    ImGui::Separator();
    if (ImGui::BeginTable("execmods", 4, ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders |
                          ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable)) {
        ImGui::TableSetupColumn("Base", ImGuiTableColumnFlags_WidthFixed, 140);
        ImGui::TableSetupColumn("Tamano", ImGuiTableColumnFlags_WidthFixed, 90);
        ImGui::TableSetupColumn("Nombre", ImGuiTableColumnFlags_WidthFixed, 160);
        ImGui::TableSetupColumn("Ruta", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableHeadersRow();
        if (mods.empty() && fileLoaded_) {
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0); ImGui::Text("0x%s", hex64(pe_.imageBase()).c_str());
            ImGui::TableSetColumnIndex(1); ImGui::Text("0x%X", pe_.sizeOfImage());
            std::string p(loadedPath_.begin(), loadedPath_.end());
            auto pos = p.find_last_of("\\/");
            ImGui::TableSetColumnIndex(2);
            const char* moduleName = pos==std::string::npos ? p.c_str() : p.c_str()+pos+1;
            if (ImGui::Selectable(moduleName, false, ImGuiSelectableFlags_SpanAllColumns |
                                  ImGuiSelectableFlags_AllowDoubleClick) && ImGui::IsMouseDoubleClicked(0))
                gotoAddress(pe_.imageBase());
            ImGui::TableSetColumnIndex(3); ImGui::TextUnformatted(p.c_str());
        }
        for (auto& m : mods) {
            // leer SizeOfImage desde la cabecera en memoria
            uint32_t sizeImg = 0, e_lfanew = 0;
            uint8_t hdr[2];
            if (debugger_.readMemory(m.base, hdr, 2) == 2 && hdr[0]=='M' && hdr[1]=='Z') {
                debugger_.readMemory(m.base + 0x3C, &e_lfanew, 4);
                debugger_.readMemory(m.base + e_lfanew + 24 + 0x38, &sizeImg, 4); // SizeOfImage (opt+56, igual 32/64)
            }
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            if (ImGui::Selectable(("0x" + hex64(m.base)).c_str(), false,
                                  ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowDoubleClick) &&
                ImGui::IsMouseDoubleClicked(0))
                gotoAddress(m.base);
            ImGui::TableSetColumnIndex(1); if (sizeImg) ImGui::Text("0x%X", sizeImg); else ImGui::TextDisabled("-");
            ImGui::TableSetColumnIndex(2); ImGui::TextUnformatted(m.name.c_str());
            ImGui::TableSetColumnIndex(3); ImGui::TextUnformatted(m.path.c_str());
        }
        ImGui::EndTable();
    }
    ImGui::End();
}

// ---------------------------------------------------------------------------
// Call stack: camina la cadena de frames (RBP/EBP -> [RBP]=prev, [RBP+ptr]=ret)
// ---------------------------------------------------------------------------
void App::drawCallStackPanel() {
    ImGui::Begin("Call stack");
    if (dbgState_ != DbgState::Paused) { ImGui::TextDisabled("(disponible al pausar)"); ImGui::End(); return; }
    const auto frames = debugger_.walkStack();
    ImGui::TextDisabled("StackWalk64 + DbgHelp; fuente solo aparece si hay PDB/simbolos disponibles.");
    if (ImGui::BeginTable("cs", 5, ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders | ImGuiTableFlags_ScrollY)) {
        ImGui::TableSetupColumn("#", ImGuiTableColumnFlags_WidthFixed, 28);
        ImGui::TableSetupColumn("PC", ImGuiTableColumnFlags_WidthFixed, 150);
        ImGui::TableSetupColumn("Frame / Stack", ImGuiTableColumnFlags_WidthFixed, 220);
        ImGui::TableSetupColumn("Simbolo", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("Fuente", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableHeadersRow();
        for (size_t depth = 0; depth < frames.size(); ++depth) {
            const auto& f = frames[depth];
            ImGui::TableNextRow();
            ImGui::PushID(static_cast<int>(depth));
            ImGui::TableSetColumnIndex(0); ImGui::Text("%zu", depth);
            ImGui::TableSetColumnIndex(1);
            if (ImGui::Selectable(vaStr(f.instruction, regs_.is64).c_str(), false)) gotoAddress(f.instruction);
            ImGui::TableSetColumnIndex(2); ImGui::Text("%s / %s", vaStr(f.frame, regs_.is64).c_str(), vaStr(f.stack, regs_.is64).c_str());
            ImGui::TableSetColumnIndex(3); ImGui::TextUnformatted(f.symbol.empty() ? "-" : f.symbol.c_str());
            ImGui::TableSetColumnIndex(4); ImGui::TextUnformatted(f.source.empty() ? "-" : f.source.c_str());
            ImGui::PopID();
        }
        ImGui::EndTable();
    }
    ImGui::End();
}

// ---------------------------------------------------------------------------
// MCP: control remoto para Claude
// ---------------------------------------------------------------------------
static uint64_t jU64(const njson& v, uint64_t def = 0) {
    if (v.is_number_unsigned()) return v.get<uint64_t>();
    if (v.is_number_integer())  return (uint64_t)v.get<int64_t>();
    if (v.is_string()) {
        std::string s = v.get<std::string>();
        int base = (s.rfind("0x", 0) == 0 || s.rfind("0X", 0) == 0) ? 0 : 16;
        return strtoull(s.c_str(), nullptr, base);
    }
    return def;
}
static std::string hexBytes(const uint8_t* p, size_t n) {
    static const char* H = "0123456789ABCDEF";
    std::string s; s.reserve(n * 2);
    for (size_t i = 0; i < n; ++i) { s.push_back(H[p[i] >> 4]); s.push_back(H[p[i] & 0xF]); }
    return s;
}

// El transporte MCP inserta _mcp_access despues de autenticar al cliente. Las
// acciones de UI y el agente integrado tienen una autorizacion local directa.
static int mcpRequiredAccess(const std::string& cmd) {
    if (cmd == "save_session" || cmd == "load_session" || cmd == "export_report" || cmd == "write_mem" || cmd == "set_reg" || cmd == "assemble" || cmd == "patch" ||
        cmd == "nop" || cmd == "dump" || cmd == "fix_iat" || cmd == "antidebug" ||
        cmd == "plugin_run" || cmd == "plugin_reload" || cmd == "symsrv") return 2;
    if (cmd == "attach" || cmd == "detach" || cmd == "launch" || cmd == "restart" || cmd == "go" || cmd == "pause" ||
        cmd == "step_into" || cmd == "step_over" || cmd == "step_to_ret" || cmd == "stop" ||
        cmd == "set_bp" || cmd == "del_bp" || cmd == "set_hwbp" || cmd == "del_hwbp" ||
        cmd == "set_membp" || cmd == "del_membp" ||
        cmd == "add_exc_bp" || cmd == "rm_exc_bp" || cmd == "set_event_breaks" ||
        cmd == "set_bookmark" || cmd == "del_bookmark" || cmd == "clear_analysis" ||
        cmd == "find_oep" || cmd == "run_trace") return 1;
    return 0;
}

// Encola un comando dbg_* en la cola de UI y espera el resultado.
// Lo usan tanto el servidor MCP como el bucle agentico de la IA; ambos corren
// en hilos de trabajo, mientras drainMcpQueue() (hilo UI) ejecuta cada frame.
std::string App::execDbgCommand(const std::string& line) {
    auto* r = new McpReq(); r->req = line;
    std::future<std::string> fut = r->resp.get_future();
    { std::lock_guard<std::mutex> lk(mcpMutex_); mcpQueue_.push_back(r); }
    if (fut.wait_for(std::chrono::seconds(30)) == std::future_status::ready) return fut.get();
    return "{\"ok\":false,\"error\":\"timeout\"}";
}

void App::startMcp() {
    std::string err;
    if (mcpToken_.empty()) mcpToken_ = makeMcpToken();
    if (mcpToken_.empty()) {
        mcpStatus_ = "Error: no se pudo crear el token MCP.";
        pushLog(mcpStatus_);
        return;
    }
    auto disp = [this](const std::string& line) -> std::string { return execDbgCommand(line); };
    if (mcp_.start(mcpPort_, mcpBindAll_, mcpToken_, mcpAccessLevel_, disp, err, mcpNoAuth_)) {
        mcpStatus_ = "MCP escuchando en " + std::string(mcpBindAll_ ? "0.0.0.0:" : "127.0.0.1:") + std::to_string(mcpPort_) +
                     (mcpNoAuth_ ? " (BYPASS: sin token)" : " (token y permiso de sesion requeridos)");
    } else mcpStatus_ = "Error: " + err;
    pushLog(mcpStatus_);
}
void App::stopMcp() { mcp_.stop(); mcpToken_.clear(); mcpStatus_ = "MCP detenido; el token de sesion fue invalidado."; pushLog(mcpStatus_); }
void App::cliStartMcp(int port, bool bindAll) { mcpPort_ = port; mcpBindAll_ = bindAll; startMcp(); }
void App::cliSetNoAuth(bool on) { mcpNoAuth_ = on; }

void App::loadExternalPlugins() {
    externalPlugins_.load(exeSiblingDir() + "\\plugins", allowNativeDllPlugins_);
    pluginStatus_ = "Plugins cargados: " + std::to_string(externalPlugins_.plugins().size());
    if (!externalPlugins_.errors().empty()) pluginStatus_ += " (hay manifiestos con error)";
    pluginsStamp_ = pluginsDirStamp();
}

// M11: mtime combinado de los archivos de plugins/ (para el hot-reload).
uint64_t App::pluginsDirStamp() {
    std::wstring dirw = std::wstring(exeSiblingDir().begin(), exeSiblingDir().end()) + L"\\plugins\\*";
    WIN32_FIND_DATAW fd{};
    HANDLE h = FindFirstFileW(dirw.c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return 0;
    uint64_t combined = 0;
    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        uint64_t t = ((uint64_t)fd.ftLastWriteTime.dwHighDateTime << 32) | fd.ftLastWriteTime.dwLowDateTime;
        combined ^= t + 0x9e3779b97f4a7c15ull + (combined << 6) + (combined >> 2);
    } while (FindNextFileW(h, &fd));
    FindClose(h);
    return combined;
}

int App::pluginExecuteJson(void* context, const char* command, const char* argsJson, char* output, size_t outputCapacity) {
    if (!context || !command || !output || !outputCapacity) return 0;
    App* app = static_cast<App*>(context);
    std::string cmd(command);
    if (cmd == "plugin_list" || cmd == "plugin_reload" || cmd == "plugin_run") return 0;
    njson args = njson::object(); try { if (argsJson) args = njson::parse(argsJson); } catch (...) {}
    if (!args.is_object()) args = njson::object();
    std::string result = app->handleMcpCommand(njson{{"cmd",cmd},{"args",args}}.dump());
    std::snprintf(output, outputCapacity, "%s", result.c_str());
    return result.size() < outputCapacity ? 1 : 0;
}
void App::pluginLog(void* context, const char* message) {
    if (context && message) static_cast<App*>(context)->pushLog(std::string("[DLL plugin] ") + message);
}

std::string App::runExternalPluginAction(const std::string& pluginId, const std::string& actionId, const std::string& argsJson) {
    const PluginAction* action = externalPlugins_.findAction(pluginId, actionId);
    if (!action) return "{\"ok\":false,\"error\":\"plugin o accion no encontrada/desactivada\"}";
    // Los manifiestos no pueden llamar de nuevo al administrador de plugins:
    // evita recursion y conserva las acciones en el conjunto del debugger.
    if (action->command == "plugin_list" || action->command == "plugin_run" || action->command == "plugin_reload")
        return "{\"ok\":false,\"error\":\"comando de plugin no permitido en un manifiesto\"}";
    const PluginManifest* plugin = externalPlugins_.find(pluginId);
    if (plugin && plugin->kind == PluginKind::NativeDll) {
        DbgPluginHostApi host{DBGJPP_PLUGIN_API_VERSION, sizeof(DbgPluginHostApi), this, pluginExecuteJson, pluginLog};
        std::string out; externalPlugins_.runNative(*plugin, actionId, argsJson, host, out); return out;
    }
    njson args = njson::object(); try { args = njson::parse(action->argsJson); } catch (...) {}
    if (!args.is_object()) args = njson::object();
    return handleMcpCommand(njson{{"cmd", action->command}, {"args", args}}.dump());
}

void App::drainMcpQueue() {
    std::deque<McpReq*> local;
    { std::lock_guard<std::mutex> lk(mcpMutex_); local.swap(mcpQueue_); }
    for (auto* r : local) {
        std::string out;
        try { out = handleMcpCommand(r->req); }
        catch (const std::exception& e) { out = std::string("{\"ok\":false,\"error\":\"") + e.what() + "\"}"; }
        catch (...) { out = "{\"ok\":false,\"error\":\"excepcion\"}"; }
        {
            std::string reqLine = "> " + (r->req.size() > 220 ? r->req.substr(0, 220) + "..." : r->req);
            std::string outLine = "< " + (out.size() > 220 ? out.substr(0, 220) + "..." : out);
            {
                std::lock_guard<std::mutex> lk(mcpLogMutex_);
                mcpLog_.push_back(reqLine);
                mcpLog_.push_back(outLine);
                while (mcpLog_.size() > 600) mcpLog_.pop_front();
            }
            // La cache en disco conserva TODO (sin el limite de 600 de memoria).
            if (mcpLogCacheOn_) { appendMcpCache(reqLine); appendMcpCache(outLine); }
        }
        r->resp.set_value(out);
        delete r;
    }
}

std::string App::handleMcpCommand(const std::string& line) {
    njson req = njson::parse(line);
    std::string cmd = req.value("cmd", "");
    njson a = req.contains("args") ? req["args"] : njson::object();
    njson res; res["ok"] = true;
    const bool externalMcp = req.value("_transport", "") == "mcp";
    const int externalAccess = req.value("_mcp_access", 0);
    if (externalMcp && mcpRequiredAccess(cmd) > externalAccess) {
        res["ok"] = false;
        res["error"] = "permiso MCP insuficiente para '" + cmd + "'; ajusta Permiso MCP en DebuggerJ++.";
        return res.dump();
    }
    bool paused = (dbgState_ == DbgState::Paused);
    bool is64 = paused ? debugger_.is64() : pe_.is64Bit();

    auto need_paused = [&]() -> bool {
        if (!paused) { res["ok"] = false; res["error"] = "el proceso no esta pausado"; return false; }
        return true;
    };

    if (cmd == "ping") { res["pong"] = true; }
    else if (cmd == "status") {
        const char* st = "idle";
        switch (dbgState_) { case DbgState::Running: st="running"; break; case DbgState::Paused: st="paused"; break;
            case DbgState::Launching: st="launching"; break; case DbgState::Exited: st="exited"; break; default: st="idle"; }
        res["state"] = st;
        res["arch"] = is64 ? "x64" : "x86";
        res["file"] = std::string(loadedPath_.begin(), loadedPath_.end());
        if (fileLoaded_) { res["imageBase"] = pe_.imageBase(); res["entry"] = pe_.entryPointVA(); }
        if (paused) res["rip"] = currentIp_;
        if (debugger_.foundOEP()) res["oep"] = debugger_.foundOEP();
    }
    else if (cmd == "plugin_list") {
        for (const auto& p : externalPlugins_.plugins()) {
            njson item = {{"id",p.id},{"name",p.name},{"version",p.version},
                          {"description",p.description},{"enabled",p.enabled},
                          {"kind",p.kind == PluginKind::NativeDll ? "dll" : "json"}};
            for (const auto& act : p.actions)
                item["actions"].push_back({{"id",act.id},{"label",act.label},{"description",act.description},{"input_schema",act.inputSchema}});
            res["plugins"].push_back(item);
        }
        for (const auto& e : externalPlugins_.errors()) res["errors"].push_back(e);
    }
    else if (cmd == "plugin_reload") {
        loadExternalPlugins();
        res["count"] = externalPlugins_.plugins().size();
        for (const auto& e : externalPlugins_.errors()) res["errors"].push_back(e);
    }
    else if (cmd == "plugin_sdk") {
        res["abi_version"] = DBGJPP_PLUGIN_API_VERSION;
        res["header"] = "sdk/DebuggerJppPluginApi.h";
        res["exports"] = {"DebuggerJppPluginGetApiVersion", "DebuggerJppPluginGetInfo", "DebuggerJppPluginRun"};
        res["host_functions"] = {"execute_json(command,args_json,output)", "log(message)"};
        res["notes"] = "Genera C++ x64 con ABI C/__cdecl; devuelve JSON en buffer; no uses STL cruzando la frontera DLL. Compilar y cargar requiere confirmacion del usuario.";
    }
    else if (cmd == "plugin_run") {
        std::string plugin = a.value("plugin", ""), action = a.value("action", "");
        std::string raw = runExternalPluginAction(plugin, action, a.value("args", njson::object()).dump());
        try { res["result"] = njson::parse(raw); }
        catch (...) { res["ok"] = false; res["error"] = "respuesta de plugin invalida"; }
    }
    else if (cmd == "open") {
        std::string p = a.value("path", "");
        std::wstring w(p.begin(), p.end());
        openFile(w);
        res["ok"] = fileLoaded_; if (!fileLoaded_) res["error"] = openError_;
    }
    else if (cmd == "save_session") {
        std::string path = a.value("path", "");
        if (path.empty()) { res["ok"] = false; res["error"] = "path requerido"; }
        else { std::string error; res["ok"] = saveSession(std::wstring(path.begin(), path.end()), error); if (!res["ok"]) res["error"] = error; }
    }
    else if (cmd == "load_session") {
        std::string path = a.value("path", "");
        if (path.empty()) { res["ok"] = false; res["error"] = "path requerido"; }
        else { std::string error; res["ok"] = loadSession(std::wstring(path.begin(), path.end()), error); if (!res["ok"]) res["error"] = error; }
    }
    else if (cmd == "report") {
        if (!fileLoaded_) { res["ok"] = false; res["error"] = "abre un archivo primero"; }
        else res["markdown"] = buildAnalysisReport();
    }
    else if (cmd == "export_report") {
        const std::string path = a.value("path", "");
        if (path.empty()) { res["ok"] = false; res["error"] = "path requerido"; }
        else { std::string error; res["ok"] = saveAnalysisReport(std::wstring(path.begin(), path.end()), error); if (!res["ok"]) res["error"] = error; }
    }
    else if (cmd == "attach") {
        const uint32_t pid = static_cast<uint32_t>(a.value("pid", 0));
        if (!pid) { res["ok"] = false; res["error"] = "pid requerido"; }
        else if (debugger_.state() != DbgState::Idle && debugger_.state() != DbgState::Exited) { res["ok"] = false; res["error"] = "ya hay una sesion activa"; }
        else { attachToProcess(pid); res["pid"] = pid; res["state"] = "attaching"; }
    }
    else if (cmd == "detach") { std::string error; res["ok"] = debugger_.detach(error); if (!res["ok"]) res["error"] = error; }
    else if (cmd == "launch")      { startDebugSession(); }
    else if (cmd == "restart") {
        if (!fileLoaded_) { res["ok"] = false; res["error"] = "abre un ejecutable primero"; }
        else { debugger_.detachAndStop(); startDebugSession(); }
    }
    else if (cmd == "go")          { debugger_.go(); }
    else if (cmd == "pause")       { debugger_.pause(); }
    else if (cmd == "step_into")   { debugger_.stepInto(); }
    else if (cmd == "step_over")   { debugger_.stepOver(); }
    else if (cmd == "step_to_ret") { debugger_.stepToRet(); }
    else if (cmd == "stop")        { debugger_.stop(); }
    else if (cmd == "get_regs") {
        if (!need_paused()) goto done;
        Registers r = debugger_.registers();
        auto put = [&](const char* n, uint64_t v){ res["regs"][n] = v; };
        if (r.is64) { put("rax",r.rax);put("rbx",r.rbx);put("rcx",r.rcx);put("rdx",r.rdx);put("rsi",r.rsi);put("rdi",r.rdi);
                      put("rbp",r.rbp);put("rsp",r.rsp);put("rip",r.rip);put("r8",r.r8);put("r9",r.r9);put("r10",r.r10);
                      put("r11",r.r11);put("r12",r.r12);put("r13",r.r13);put("r14",r.r14);put("r15",r.r15); }
        else { put("eax",r.rax);put("ebx",r.rbx);put("ecx",r.rcx);put("edx",r.rdx);put("esi",r.rsi);put("edi",r.rdi);
               put("ebp",r.rbp);put("esp",r.rsp);put("eip",r.rip); }
        res["regs"]["eflags"] = r.eflags;
    }
    else if (cmd == "set_reg") {
        if (!need_paused()) goto done;
        std::string n = a.value("name", ""); uint64_t v = jU64(a.value("value", njson(0)));
        applyRegEdit(n.c_str(), v);
    }
    else if (cmd == "read_mem") {
        uint64_t addr = jU64(a["addr"]); size_t len = (size_t)a.value("len", 64);
        if (len > 65536) len = 65536;
        std::vector<uint8_t> buf(len);
        size_t got = debugger_.readMemory(addr, buf.data(), len);
        res["addr"] = addr; res["len"] = got; res["hex"] = hexBytes(buf.data(), got);
    }
    else if (cmd == "write_mem") {
        uint64_t addr = jU64(a["addr"]); std::string hex = a.value("hex", "");
        std::vector<uint8_t> bytes;
        for (size_t i = 0; i + 1 < hex.size(); i += 2) bytes.push_back((uint8_t)strtoul(hex.substr(i,2).c_str(),nullptr,16));
        res["written"] = debugger_.writeMemory(addr, bytes.data(), bytes.size());
    }
    else if (cmd == "disasm") {
        int count = a.value("count", 20); if (count > 400) count = 400;
        uint64_t addr = a.contains("addr") ? jU64(a["addr"]) : (paused ? currentIp_ : pe_.entryPointVA());
        std::vector<uint8_t> buf((size_t)count * 15 + 16);
        size_t got = 0;
        if (paused) { got = debugger_.readMemory(addr, buf.data(), buf.size()); dis_.setMode(debugger_.is64()); }
        else if (fileLoaded_) { got = pe_.readAtRva((uint32_t)(addr - pe_.imageBase()), buf.data(), buf.size()); dis_.setMode(pe_.is64Bit()); }
        auto insns = dis_.disassemble(buf.data(), got, addr, count);
        for (auto& in : insns) res["insns"].push_back({{"addr", in.address}, {"bytes", in.bytes}, {"text", in.text}});
    }
    else if (cmd == "goto") {
        uint64_t addr = jU64(a["addr"]);
        gotoAddress(addr);
        res["addr"] = addr;
        res["module"] = moduleNameAt(addr);
    }
    else if (cmd == "goto_entry") {
        if (!fileLoaded_) { res["ok"] = false; res["error"] = "abre un ejecutable primero"; }
        else { uint64_t addr = pe_.entryPointVA(); gotoAddress(addr); res["addr"] = addr; }
    }
    else if (cmd == "analyze_code") {
        uint64_t addr = a.contains("addr") ? jU64(a["addr"]) : (paused ? currentIp_ : pe_.entryPointVA());
        analyzeCodeAt(addr); res["addr"] = addr; res["module"] = moduleNameAt(addr);
    }
    else if (cmd == "list_functions") {
        for (const auto& function : analyzedFunctions_)
            res["functions"].push_back({{"start",function.start},{"end",function.end},{"name",function.name},
                                        {"instructions",function.instructions},{"calls",function.calls},{"branches",function.branches}});
    }
    else if (cmd == "list_xrefs") {
        const uint64_t target = a.contains("addr") ? jU64(a["addr"]) : 0;
        for (const auto& xref : analysisXrefs_)
            if (!target || xref.to == target || xref.from == target)
                res["xrefs"].push_back({{"from",xref.from},{"to",xref.to},{"type",xref.type}});
    }
    else if (cmd == "list_loops") {
        for (const auto& loop : analysisLoops_)
            res["loops"].push_back({{"start",loop.start},{"end",loop.end},{"function",loop.function}});
    }
    else if (cmd == "set_bookmark") {
        const uint64_t address = jU64(a["addr"]);
        if (!address) { res["ok"] = false; res["error"] = "addr requerido"; }
        else { bookmarks_[address] = a.value("text", "bookmark"); saveAnnotations(); }
    }
    else if (cmd == "del_bookmark") { bookmarks_.erase(jU64(a["addr"])); saveAnnotations(); }
    else if (cmd == "list_bookmarks") { for (const auto& [address,text] : bookmarks_) res["bookmarks"].push_back({{"addr",address},{"text",text}}); }
    else if (cmd == "clear_analysis") { clearAutoAnalysis(); }
    else if (cmd == "goto_module") {
        std::string needle = a.value("name", "");
        std::transform(needle.begin(), needle.end(), needle.begin(), [](unsigned char c){ return (char)std::tolower(c); });
        bool found = false;
        for (const auto& m : debugger_.modules()) {
            std::string name = m.name;
            std::transform(name.begin(), name.end(), name.begin(), [](unsigned char c){ return (char)std::tolower(c); });
            if (name.find(needle) == std::string::npos) continue;
            gotoAddress(m.base); res["addr"] = m.base; res["module"] = m.name; found = true; break;
        }
        if (!found) { res["ok"] = false; res["error"] = "modulo no encontrado o aun no esta cargado"; }
    }
    else if (cmd == "stack") {
        if (!need_paused()) goto done;
        Registers r = debugger_.registers();
        int count = a.value("count", 16); if (count > 256) count = 256;
        size_t ptr = r.is64 ? 8 : 4;
        for (int i = 0; i < count; ++i) {
            uint64_t addr = r.rsp + i * ptr, val = 0;
            if (debugger_.readMemory(addr, &val, ptr) != ptr) break;
            res["stack"].push_back({{"addr", addr}, {"value", val}});
        }
    }
    else if (cmd == "set_bp")  {
        const uint64_t address = jU64(a["addr"]);
        const bool added = debugger_.addBreakpoint(address, a.value("label","mcp"));
        if (a.contains("break_on_hit")) debugger_.setBreakpointHitTarget(address, jU64(a["break_on_hit"]));
        if (a.contains("condition")) debugger_.setBreakpointCondition(address, a.value("condition", ""));
        if (a.contains("log_only")) debugger_.setBreakpointLogOnly(address, a.value("log_only", false));
        if (a.contains("action")) {   // M3: accion al golpear
            std::string act = a.value("action", "");
            if (act.empty()) bpActions_.erase(address); else bpActions_[address] = act;
        }
        res["ok"] = added;
    }
    else if (cmd == "del_bp")  { res["ok"] = debugger_.removeBreakpoint(jU64(a["addr"])); }
    else if (cmd == "list_bp") { for (auto& b : debugger_.breakpoints()) if (!b.oneShot) res["bps"].push_back({{"addr",b.address},{"enabled",b.enabled},{"label",b.label},{"hits",b.hits},{"break_on_hit",b.breakOnHit},{"condition",b.condition},{"log_only",b.logOnly}}); }
    else if (cmd == "set_hwbp") { int t=(int)a.value("type",0); int l=(int)a.value("len",1); res["ok"]=debugger_.addHwBreakpoint(jU64(a["addr"]), t, l, a.value("label","mcp")); }
    else if (cmd == "del_hwbp") { res["ok"]=debugger_.removeHwBreakpoint(jU64(a["addr"])); }
    else if (cmd == "list_hwbp") { for (auto& h : debugger_.hwBreakpoints()) res["hwbps"].push_back({{"slot",h.slot},{"addr",h.address},{"type",h.type},{"len",h.len},{"hits",h.hits}}); }
    else if (cmd == "set_membp") {
        std::string error;
        res["ok"] = debugger_.addMemoryBreakpoint(jU64(a["addr"]), jU64(a.value("size", njson(1))),
                                                     a.value("type", 0), a.value("label", "mcp-memory"), error);
        if (!res["ok"]) res["error"] = error;
    }
    else if (cmd == "del_membp") { res["ok"] = debugger_.removeMemoryBreakpoint(static_cast<uint32_t>(a.value("id", 0))); }
    else if (cmd == "list_membp") { for (const auto& b : debugger_.memoryBreakpoints()) res["membps"].push_back({{"id",b.id},{"addr",b.address},{"size",b.size},{"type",b.type},{"hits",b.hits},{"label",b.label}}); }
    else if (cmd == "add_exc_bp") { res["id"] = debugger_.addExceptionBreak((uint32_t)jU64(a.value("code", njson(0))), jU64(a.value("addr", njson(0))), a.value("label","mcp")); }
    else if (cmd == "list_exc") { for (auto& e : debugger_.exceptionBreaks()) res["exc"].push_back({{"id",e.id},{"code",e.code},{"addr",e.address},{"hits",e.hits}}); }
    else if (cmd == "get_event_breaks") { res["mask"] = debugger_.eventBreakMask(); }
    else if (cmd == "set_event_breaks") { debugger_.setEventBreakMask(static_cast<uint32_t>(jU64(a.value("mask", njson(0))))); res["mask"] = debugger_.eventBreakMask(); }
    else if (cmd == "modules") { for (auto& m : debugger_.modules()) res["modules"].push_back({{"base",m.base},{"name",m.name},{"path",m.path}}); }
    else if (cmd == "sections") { for (auto& s : pe_.sections()) res["sections"].push_back({{"name",s.name},{"rva",s.virtualAddress},{"vsize",s.virtualSize},{"entropy",s.entropy},{"exec",s.executable()},{"write",s.writable()}}); }
    else if (cmd == "imports") { for (auto& im : pe_.imports()) res["imports"].push_back({{"dll",im.dll},{"name",im.name},{"ordinal",im.ordinal}}); }
    else if (cmd == "packers") { runPackerScan(); for (auto& m : packerMatches_) res["packers"].push_back({{"name",m.name},{"source",m.source},{"confidence",m.confidence}}); }
    else if (cmd == "search_hex") {
        std::string perr; const uint8_t* data=nullptr; size_t len=0; uint64_t base=0;
        if (fileLoaded_) { data=pe_.raw().data(); len=pe_.raw().size(); base=pe_.imageBase(); }
        if (data) { auto hits = searchHex(data,len,base,a.value("pattern",""),perr); if(!perr.empty()){res["ok"]=false;res["error"]=perr;} for(auto h:hits) res["hits"].push_back(h); }
    }
    else if (cmd == "find_oep") {
        if (!need_paused()) goto done;
        uint64_t stubLo=pe_.imageBase(), stubHi=pe_.imageBase()+pe_.sizeOfImage(); uint32_t ep=pe_.entryPoint();
        for (auto& s : pe_.sections()){ uint32_t hi=s.virtualAddress+(s.virtualSize?s.virtualSize:s.rawSize); if(ep>=s.virtualAddress&&ep<hi){stubLo=pe_.imageBase()+s.virtualAddress;stubHi=pe_.imageBase()+hi;break;} }
        debugger_.findOEP(stubLo,stubHi,pe_.imageBase(),pe_.imageBase()+pe_.sizeOfImage());
    }
    else if (cmd == "get_oep") { res["oep"] = debugger_.foundOEP(); }
    else if (cmd == "dump") {
        std::wstring out = a.contains("path") ? std::wstring(a.value("path","").begin(), a.value("path","").end()) : (loadedPath_ + L"_dump.exe");
        std::string lg; bool ok = dumpProcess(debugger_, pe_, debugger_.foundOEP(), out, lg);
        if (ok) lastDumpPath_ = out; res["ok"]=ok; res["log"]=lg;
    }
    else if (cmd == "resolve_iat") { std::vector<IatEntry> iat; std::string lg; res["ok"]=resolveIAT(debugger_, iat, lg); res["log"]=lg; for(auto&e:iat) res["iat"].push_back({{"iatVA",e.iatVA},{"module",e.module},{"func",e.func},{"resolved",e.resolved}}); }
    else if (cmd == "fix_iat") { if(lastDumpPath_.empty()){res["ok"]=false;res["error"]="genera un dump primero";} else { std::string lg; res["ok"]=fixIATInDump(debugger_,lastDumpPath_,lg); res["log"]=lg; } }
    else if (cmd == "antidebug") { std::string lg; antiActive_ = applyAntiAntiDebug(debugger_, is64, antiOpt_, lg); res["ok"]=antiActive_; res["log"]=lg; }
    else if (cmd == "assemble") {
        uint64_t addr = jU64(a["addr"]); std::string text = a.value("text", "");
        ks_engine* ks = nullptr;
        if (ks_open(KS_ARCH_X86, debugger_.is64() ? KS_MODE_64 : KS_MODE_32, &ks) == KS_ERR_OK) {
            unsigned char* enc = nullptr; size_t sz = 0, cnt = 0;
            if (ks_asm(ks, text.c_str(), addr, &enc, &sz, &cnt) == 0 && sz > 0) {
                res["bytes"] = sz; res["written"] = debugger_.writeMemory(addr, enc, sz);
                ks_free(enc); if (dbgState_==DbgState::Paused) refreshLiveDisassembly(currentIp_);
            } else { res["ok"]=false; res["error"]=ks_strerror(ks_errno(ks)); if(enc) ks_free(enc); }
            ks_close(ks);
        } else { res["ok"]=false; res["error"]="ks_open"; }
    }
    else if (cmd == "patch") {
        uint64_t addr = jU64(a["addr"]); std::string hx = a.value("hex", ""); std::vector<uint8_t> b;
        for (size_t i = 0; i < hx.size();) { if (hx[i]==' '){i++;continue;} if(i+1<hx.size()){ b.push_back((uint8_t)strtoul(hx.substr(i,2).c_str(),nullptr,16)); i+=2;} else break; }
        res["written"] = debugger_.writeMemory(addr, b.data(), b.size());
        if (dbgState_==DbgState::Paused) refreshLiveDisassembly(currentIp_);
    }
    else if (cmd == "nop") { uint64_t addr=jU64(a["addr"]); int n=(int)a.value("count",1); std::vector<uint8_t> nn(n>0?n:1,0x90); res["written"]=debugger_.writeMemory(addr,nn.data(),nn.size()); if(dbgState_==DbgState::Paused) refreshLiveDisassembly(currentIp_); }
    else if (cmd == "symbol") { const uint64_t address = jU64(a["addr"]); res["symbol"] = debugger_.symbolAt(address); res["source"] = debugger_.sourceAt(address); }
    else if (cmd == "source") { res["source"] = debugger_.sourceAt(jU64(a["addr"])); }
    else if (cmd == "call_stack") {
        if (!need_paused()) goto done;
        for (const auto& frame : debugger_.walkStack())
            res["frames"].push_back({{"pc",frame.instruction},{"frame",frame.frame},{"stack",frame.stack},
                                      {"symbol",frame.symbol},{"source",frame.source}});
    }
    else if (cmd == "tls") { for (auto v : pe_.tlsCallbacks()) res["tls"].push_back(v); }
    else if (cmd == "seh") { for (auto& e : debugger_.sehChain()) res["seh"].push_back({{"record",e.first},{"handler",e.second}}); }
    else if (cmd == "exports") { for (auto& e : pe_.exports()) res["exports"].push_back({{"name",e.name},{"ordinal",e.ordinal},{"rva",e.rva}}); }
    else if (cmd == "mem_map") { for (auto& r : debugger_.memoryMap()) res["regions"].push_back({{"base",r.base},{"size",r.size},{"protect",r.protectStr},{"type",r.typeStr},{"module",r.moduleName}}); }
    else if (cmd == "set_comment") { uint64_t addr=jU64(a["addr"]); std::string t=a.value("text",""); if(t.empty())comments_.erase(addr); else comments_[addr]=t; saveAnnotations(); }
    else if (cmd == "set_label") { uint64_t addr=jU64(a["addr"]); std::string t=a.value("text",""); if(t.empty())labels_.erase(addr); else labels_[addr]=t; saveAnnotations(); }
    else if (cmd == "list_annotations") { for(auto&[k,v]:labels_) res["labels"].push_back({{"addr",k},{"text",v}}); for(auto&[k,v]:comments_) res["comments"].push_back({{"addr",k},{"text",v}}); }
    else if (cmd == "find_refs") { findReferences(jU64(a["addr"])); for(auto x:refs_) res["refs"].push_back(x); }
    else if (cmd == "eval") {
        std::string expr = a.value("expr", "");
        uint64_t v = 0; std::string err;
        if (evalExpr(expr, v, err)) { res["value"] = v; res["hex"] = "0x" + hex64(v); }
        else { res["ok"] = false; res["error"] = err; }
    }
    else if (cmd == "symsrv") {
        std::string path = a.value("path", "");
        debugger_.setSymbolSearchPath(path);
        std::snprintf(symPathBuf_, sizeof(symPathBuf_), "%s", path.c_str());
        saveSymPath();
        res["path"] = path;
    }
    else if (cmd == "run_trace") { if(!need_paused()) goto done; debugger_.runTrace(); }
    else if (cmd == "get_trace") { auto t=debugger_.traceLog(); res["count"]=t.size(); size_t lim=t.size()>5000?5000:t.size(); for(size_t i=0;i<lim;++i) res["trace"].push_back(t[i]); }
    else if (cmd == "rm_exc_bp") { debugger_.removeExceptionBreak((uint32_t)jU64(a["id"])); }
    else { res["ok"] = false; res["error"] = "comando desconocido: " + cmd; }

done:
    return res.dump();
}

static std::string mcpCacheFilePath() {
    wchar_t exe[MAX_PATH] = {0};
    GetModuleFileNameW(nullptr, exe, MAX_PATH);
    std::wstring w(exe);
    auto pos = w.find_last_of(L"\\/");
    std::wstring dir = (pos == std::wstring::npos) ? L"." : w.substr(0, pos);
    std::wstring path = dir + L"\\mcp_log_cache.txt";
    return std::string(path.begin(), path.end());
}

void App::appendMcpCache(const std::string& line) {
    std::ofstream f(mcpCacheFilePath(), std::ios::app | std::ios::binary);
    if (f) f << line << "\n";
}

void App::loadMcpLogCache() {
    std::ifstream f(mcpCacheFilePath(), std::ios::binary);
    if (!f) { pushLog("No hay cache de MCP log que cargar."); return; }
    std::deque<std::string> loaded;
    std::string line;
    while (std::getline(f, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        loaded.push_back(line);
    }
    std::lock_guard<std::mutex> lk(mcpLogMutex_);
    mcpLog_.swap(loaded);
    while (mcpLog_.size() > 5000) mcpLog_.pop_front();  // tope de visualizacion en memoria
    mcpLogViewCount_ = (size_t)-1;  // fuerza reconstruccion del buffer
    pushLog("Cache de MCP log cargada (" + std::to_string(mcpLog_.size()) + " lineas).");
}

std::string App::mcpLogJoined() {
    std::lock_guard<std::mutex> lk(mcpLogMutex_);
    std::string s;
    for (auto& l : mcpLog_) { s += l; s.push_back('\n'); }
    return s;
}

void App::drawMcpLogPanel() {
    ImGui::Begin("MCP Log");
    if (mcp_.running())
        ImGui::TextColored(ImVec4(0.5f,1,0.5f,1), "MCP activo: puerto %d, %d cliente(s)", mcp_.port(), mcp_.clients());
    else
        ImGui::TextDisabled("MCP inactivo (actívalo en Plugins -> Claude MCP)");

    if (ImGui::SmallButton("Limpiar")) {
        { std::lock_guard<std::mutex> lk(mcpLogMutex_); mcpLog_.clear(); }
        mcpLogViewCount_ = (size_t)-1;
    }
    ImGui::SameLine();
    if (ImGui::SmallButton("Load cache")) loadMcpLogCache();
    ImGui::SameLine();
    if (ImGui::SmallButton("Copy to clipboard")) ImGui::SetClipboardText(mcpLogJoined().c_str());
    ImGui::SameLine();
    ImGui::Checkbox("Cache a disco", &mcpLogCacheOn_);
    ImGui::SameLine();
    ImGui::TextDisabled("(selecciona texto y Ctrl+C, o usa los botones)");
    ImGui::Separator();

    // Reconstruir el buffer solo cuando cambie el numero de lineas (evita rehacerlo cada frame).
    size_t count;
    { std::lock_guard<std::mutex> lk(mcpLogMutex_); count = mcpLog_.size(); }
    if (count != mcpLogViewCount_) {
        mcpLogView_ = mcpLogJoined();
        mcpLogViewCount_ = count;
    }

    // InputText de solo lectura: permite seleccionar y copiar con el mouse/teclado.
    ImGuiInputTextFlags flags = ImGuiInputTextFlags_ReadOnly;
    ImGui::InputTextMultiline("##mcplog", mcpLogView_.data(), mcpLogView_.size() + 1,
                              ImVec2(-1, -1), flags);
    ImGui::End();
}

void App::drawLogPanel() {
    ImGui::Begin("Log");
    std::lock_guard<std::mutex> lk(logMutex_);
    ImGui::BeginChild("logscroll", ImVec2(0, 0), false, ImGuiWindowFlags_HorizontalScrollbar);
    for (auto& l : log_) ImGui::TextUnformatted(l.c_str());
    if (ImGui::GetScrollY() >= ImGui::GetScrollMaxY() - 5) ImGui::SetScrollHereY(1.0f);
    ImGui::EndChild();
    ImGui::End();
}

// ---------------------------------------------------------------------------
// Panel de IA
// ---------------------------------------------------------------------------
std::string App::aiContextSnapshot() {
    std::string ctx = "Contexto del debugger:\n";
    ctx += pe_.is64Bit() ? "Arquitectura: x64\n" : "Arquitectura: x86\n";
    if (dbgState_ == DbgState::Paused) {
        ctx += "Estado: pausado. Registros:\n";
        char b[256];
        if (regs_.is64) {
            std::snprintf(b, sizeof(b), "RIP=%llX RSP=%llX RBP=%llX RAX=%llX RBX=%llX RCX=%llX RDX=%llX\n",
                (unsigned long long)regs_.rip,(unsigned long long)regs_.rsp,(unsigned long long)regs_.rbp,
                (unsigned long long)regs_.rax,(unsigned long long)regs_.rbx,(unsigned long long)regs_.rcx,(unsigned long long)regs_.rdx);
        } else {
            std::snprintf(b, sizeof(b), "EIP=%llX ESP=%llX EBP=%llX EAX=%llX EBX=%llX ECX=%llX EDX=%llX\n",
                (unsigned long long)regs_.rip,(unsigned long long)regs_.rsp,(unsigned long long)regs_.rbp,
                (unsigned long long)regs_.rax,(unsigned long long)regs_.rbx,(unsigned long long)regs_.rcx,(unsigned long long)regs_.rdx);
        }
        ctx += b;
    }
    if (dbgState_ == DbgState::Paused) {
        ctx += "\nPila (top):\n";
        size_t ptr = regs_.is64 ? 8 : 4;
        for (int i = 0; i < 8; ++i) {
            uint64_t addr = regs_.rsp + i * ptr, val = 0;
            if (debugger_.readMemory(addr, &val, ptr) != ptr) break;
            char b[80]; std::snprintf(b, sizeof(b), "  [%016llX] = %016llX\n",
                                      (unsigned long long)addr, (unsigned long long)val);
            ctx += b;
        }
    }
    ctx += "\nDesensamblado alrededor del punto actual:\n";
    bool is64 = (dbgState_ == DbgState::Paused) ? debugger_.is64() : pe_.is64Bit();
    int shown = 0;
    for (auto& in : insns_) {
        if (dbgState_ == DbgState::Paused && in.address < currentIp_) continue;
        ctx += vaStr(in.address, is64);
        ctx += "  " + in.bytes + "\t" + in.text + "\n";
        if (++shown >= 40) break;
    }
    return ctx;
}

// Catalogo de herramientas dbg_* que la IA puede invocar. Espeja las tools del
// servidor MCP (mcp/server.mjs); cada una se despacha por handleMcpCommand.
std::vector<ToolDef> App::aiToolDefs() {
    auto obj = [](njson props, std::vector<std::string> req) {
        njson s; s["type"] = "object"; s["properties"] = props;
        s["required"] = req; return s.dump();
    };
    njson HEX; HEX["type"] = "string"; HEX["description"] = "direccion en hex, ej '401000' o '0x401000'";
    njson INT; INT["type"] = "integer";
    njson STR; STR["type"] = "string";
    njson EMPTY = njson::object();

    std::vector<ToolDef> t;
    auto add = [&](const char* cmd, const char* desc, const std::string& schema) {
        t.push_back({ std::string("dbg_") + cmd, desc, schema });
    };
    add("status",      "Estado del debugger (arch, imageBase, estado, RIP, OEP).", obj(EMPTY, {}));
    add("plugin_list", "Lista los plugins JSON externos y sus acciones disponibles.", obj(EMPTY, {}));
    add("plugin_reload", "Recarga los manifiestos JSON de plugins desde disco.", obj(EMPTY, {}));
    add("plugin_sdk", "Describe la ABI y exportaciones para generar codigo fuente de un plugin DLL x64 compatible.", obj(EMPTY, {}));
    add("plugin_run", "Ejecuta una accion declarada por un plugin local JSON/DLL.", obj({{"plugin", STR}, {"action", STR}, {"args", EMPTY}}, {"plugin","action"}));
    add("open",        "Abre un .exe/.dll para analizar (parsea PE, desensambla).", obj({{"path", STR}}, {"path"}));
    add("save_session", "Guarda objetivo, argumentos, anotaciones y breakpoints en un archivo .dbgjsession.", obj({{"path", STR}}, {"path"}));
    add("load_session", "Carga un archivo .dbgjsession. Requiere no tener una sesion de debug activa.", obj({{"path", STR}}, {"path"}));
    add("report",      "Genera un informe Markdown de PE, estado, secciones, detecciones y breakpoints sin escribir disco.", obj(EMPTY, {}));
    add("export_report", "Exporta el informe Markdown a path.", obj({{"path", STR}}, {"path"}));
    add("attach",      "Se adjunta a un proceso existente por PID; intenta abrir tambien su PE estatico.", obj({{"pid", INT}}, {"pid"}));
    add("detach",      "Desadjunta un proceso conectado por Attach sin terminarlo.", obj(EMPTY, {}));
    add("launch",      "Lanza el archivo abierto bajo depuracion.", obj(EMPTY, {}));
    add("restart",     "Detiene la sesion actual y reinicia el ejecutable abierto bajo depuracion.", obj(EMPTY, {}));
    add("go",          "Continua la ejecucion (Play).", obj(EMPTY, {}));
    add("pause",       "Pausa la ejecucion.", obj(EMPTY, {}));
    add("step_into",   "Un paso, entrando a los call.", obj(EMPTY, {}));
    add("step_over",   "Un paso, saltando los call.", obj(EMPTY, {}));
    add("step_to_ret", "Ejecuta hasta el ret de la funcion actual.", obj(EMPTY, {}));
    add("stop",        "Termina el proceso depurado.", obj(EMPTY, {}));
    add("get_regs",    "Lee los registros (requiere pausado).", obj(EMPTY, {}));
    add("set_reg",     "Escribe un registro. name=rax/eip/eflags..., value=hex.", obj({{"name", STR}, {"value", HEX}}, {"name","value"}));
    add("read_mem",    "Lee memoria (requiere pausado). Devuelve hex.", obj({{"addr", HEX}, {"len", INT}}, {"addr"}));
    add("write_mem",   "Escribe memoria (hex).", obj({{"addr", HEX}, {"hex", STR}}, {"addr","hex"}));
    add("disasm",      "Desensambla en una direccion (o RIP). count=n instrucciones.", obj({{"addr", HEX}, {"count", INT}}, {}));
    add("goto",        "Lleva la vista CPU a una direccion para inspeccionarla.", obj({{"addr", HEX}}, {"addr"}));
    add("goto_entry",  "Lleva la vista CPU al EntryPoint del PE abierto.", obj(EMPTY, {}));
    add("analyze_code", "Analiza la funcion/bloque actual: flujo local, destinos y simbolos; agrega etiquetas/comentarios.", obj({{"addr", HEX}}, {}));
    add("list_functions", "Lista funciones candidatas descubiertas por Analyze this.", obj(EMPTY, {}));
    add("list_xrefs", "Lista xrefs persistentes de call/jump; addr opcional filtra por origen o destino.", obj({{"addr", HEX}}, {}));
    add("list_loops", "Lista bucles detectados mediante saltos hacia atras.", obj(EMPTY, {}));
    add("set_bookmark", "Agrega un bookmark persistente en una VA.", obj({{"addr", HEX}, {"text", STR}}, {"addr"}));
    add("del_bookmark", "Quita un bookmark persistente.", obj({{"addr", HEX}}, {"addr"}));
    add("list_bookmarks", "Lista bookmarks persistentes.", obj(EMPTY, {}));
    add("clear_analysis", "Limpia funciones/xrefs/loops y anotaciones automaticas de Analyze this.", obj(EMPTY, {}));
    add("goto_module", "Lleva la vista CPU a la base de un modulo/DLL cargado. name acepta nombre parcial.", obj({{"name", STR}}, {"name"}));
    add("stack",       "Lee la pila desde RSP/ESP. count=n entradas.", obj({{"count", INT}}, {}));
    add("set_bp",      "Pone un breakpoint software. condition admite registros, hit, &, | y comparadores; log_only registra sin pausar; action se ejecuta al golpear ('ai:<prompt>', 'cmd {args}' o JSON).", obj({{"addr", HEX}, {"label", STR}, {"break_on_hit", INT}, {"condition", STR}, {"log_only", njson{{"type","boolean"}}}, {"action", STR}}, {"addr"}));
    add("del_bp",      "Quita un breakpoint.", obj({{"addr", HEX}}, {"addr"}));
    add("list_bp",     "Lista los breakpoints.", obj(EMPTY, {}));
    add("set_hwbp",    "Hardware breakpoint (DR0-3). type=0 exec/1 write/3 rw, len=1/2/4/8.", obj({{"addr", HEX}, {"type", INT}, {"len", INT}}, {"addr"}));
    add("del_hwbp",    "Quita un hardware breakpoint.", obj({{"addr", HEX}}, {"addr"}));
    add("list_hwbp",   "Lista los hardware breakpoints.", obj(EMPTY, {}));
    add("set_membp",   "Memory breakpoint PAGE_GUARD. type=0 access/1 write/8 execute; protege paginas completas y requiere pausa.", obj({{"addr", HEX}, {"size", INT}, {"type", INT}, {"label", STR}}, {"addr"}));
    add("del_membp",   "Quita un memory breakpoint por id.", obj({{"id", INT}}, {"id"}));
    add("list_membp",  "Lista memory breakpoints PAGE_GUARD y sus hits.", obj(EMPTY, {}));
    add("add_exc_bp",  "Breakpoint de excepcion. code=0 (cualquiera) o codigo hex.", obj({{"code", HEX}, {"addr", HEX}}, {}));
    add("list_exc",    "Lista los breakpoints de excepcion.", obj(EMPTY, {}));
    add("get_event_breaks", "Devuelve la mascara de breakpoints de eventos: 1 hilo nuevo, 2 fin hilo, 4 carga DLL, 8 descarga DLL.", obj(EMPTY, {}));
    add("set_event_breaks", "Configura breakpoints de eventos con mascara: 1=create thread, 2=exit thread, 4=load DLL, 8=unload DLL; combinables.", obj({{"mask", INT}}, {"mask"}));
    add("modules",     "Lista los modulos cargados.", obj(EMPTY, {}));
    add("sections",    "Lista las secciones del PE (con entropia).", obj(EMPTY, {}));
    add("imports",     "Lista los imports del PE.", obj(EMPTY, {}));
    add("exports",     "Lista los exports del PE.", obj(EMPTY, {}));
    add("packers",     "Escanea packers/protectores.", obj(EMPTY, {}));
    add("search_hex",  "Busca un patron hex (ej '48 8B ?? C3') en el archivo.", obj({{"pattern", STR}}, {"pattern"}));
    add("find_oep",    "Busca el OEP (traza saltando calls). Requiere pausado.", obj(EMPTY, {}));
    add("get_oep",     "Devuelve el OEP encontrado.", obj(EMPTY, {}));
    add("dump",        "Vuelca el proceso a disco (memory-aligned).", obj({{"path", STR}}, {}));
    add("resolve_iat", "Resuelve la IAT contra los exports cargados.", obj(EMPTY, {}));
    add("fix_iat",     "Reconstruye la IAT en el dump (experimental).", obj(EMPTY, {}));
    add("antidebug",   "Aplica anti-anti-debug (parcha el PEB).", obj(EMPTY, {}));
    add("assemble",    "Ensambla texto x86/x64 (Keystone) y lo escribe en memoria.", obj({{"addr", HEX}, {"text", STR}}, {"addr","text"}));
    add("patch",       "Escribe bytes hex en una direccion.", obj({{"addr", HEX}, {"hex", STR}}, {"addr","hex"}));
    add("nop",         "Rellena con NOP (0x90) en una direccion.", obj({{"addr", HEX}, {"count", INT}}, {"addr"}));
    add("symbol",      "Resuelve simbolo y, si existe PDB, fuente/linea de una direccion.", obj({{"addr", HEX}}, {"addr"}));
    add("source",      "Devuelve archivo:linea para una direccion si DbgHelp encontro PDB.", obj({{"addr", HEX}}, {"addr"}));
    add("call_stack",  "Camina la pila de llamadas (frames + simbolos).", obj(EMPTY, {}));
    add("tls",         "Lista los TLS callbacks del PE.", obj(EMPTY, {}));
    add("seh",         "Lista la cadena SEH (x86).", obj(EMPTY, {}));
    add("mem_map",     "Lista el mapa de memoria (regiones/permisos/modulo).", obj(EMPTY, {}));
    add("set_comment", "Pone/actualiza (o borra si vacio) un comentario en una VA.", obj({{"addr", HEX}, {"text", STR}}, {"addr"}));
    add("set_label",   "Pone/actualiza (o borra si vacio) una etiqueta en una VA.", obj({{"addr", HEX}, {"text", STR}}, {"addr"}));
    add("list_annotations", "Lista comentarios y etiquetas.", obj(EMPTY, {}));
    add("find_refs",   "Busca referencias (code+data) a una direccion.", obj({{"addr", HEX}}, {"addr"}));
    add("run_trace",   "Inicia run-trace (registra cada instruccion). Requiere pausado.", obj(EMPTY, {}));
    add("get_trace",   "Devuelve el log del run-trace.", obj(EMPTY, {}));
    add("eval",        "Evalua una expresion (hex por defecto; byte/dword/ptr(a), reg, mod.base/fromname, dis.len, [mem]).", obj({{"expr", STR}}, {"expr"}));
    add("symsrv",      "Configura la ruta de simbolos (symsrv), ej 'srv*C:\\\\symbols*https://msdl.microsoft.com/download/symbols'.", obj({{"path", STR}}, {"path"}));
    add("rm_exc_bp",   "Quita un breakpoint de excepcion por id.", obj({{"id", INT}}, {"id"}));
    return t;
}

void App::sendAiMessage() {
    if (aiBusy_) return;
    std::string raw = aiInput_;
    if (raw.empty()) return;

    const AiAgent* agent = aiConfig_.current();
    if (!agent) { aiError_ = "No hay agente configurado (Tools -> Options -> AI)."; return; }
    ai_.setAgent(*agent);
    bool agentMode = aiAgentMode_ && agent->supportsTools;

    std::string userMsg = raw;
    if (aiIncludeContext_) userMsg = aiContextSnapshot() + "\n\nPregunta:\n" + raw;

    std::vector<ChatMessage> hist;
    { std::lock_guard<std::mutex> lk(aiMutex_); hist = chat_; chat_.push_back({"user", raw}); }
    aiInput_[0] = '\0';
    aiBusy_ = true; aiError_.clear();

    if (aiThread_.joinable()) aiThread_.join();

    aiThread_ = std::thread([this, hist, userMsg, agentMode]() {
        std::string err, resp;
        if (agentMode) {
            std::string sys =
                "Eres un asistente experto en ingenieria inversa y analisis de malware con fines "
                "defensivos. Controlas un debugger (tipo x64dbg) mediante las herramientas dbg_*. "
                "Usa las tools para ACTUAR sobre el proceso: abrir/lanzar, poner breakpoints, hacer "
                "step, leer registros y memoria, desensamblar, parchear, volcar, etc. "
                "Reglas: las direcciones van en hex; para leer registros/memoria o step, el proceso "
                "debe estar lanzado y PAUSADO (usa dbg_launch y consulta dbg_status). Tras un go/step, "
                "vuelve a consultar dbg_status/dbg_get_regs para ver el nuevo estado. Encadena varias "
                "tools si hace falta y, al terminar, resume en texto lo que hiciste. Se conciso y "
                "tecnico. Responde en espanol.";

            AiCallbacks cb;
            cb.execTool = [this](const std::string& name, const std::string& argsJson) -> std::string {
                std::string cmd = (name.rfind("dbg_", 0) == 0) ? name.substr(4) : name;
                njson args = njson::object();
                if (!argsJson.empty()) { try { args = njson::parse(argsJson); } catch (...) {} }
                if (!args.is_object()) args = njson::object();
                njson req; req["cmd"] = cmd; req["args"] = args;
                std::string out = execDbgCommand(req.dump());
                if (out.size() > 6000) out = out.substr(0, 6000) + " ...[truncado]";
                return out;
            };
            cb.onEvent = [this](const std::string& kind, const std::string& text) {
                std::lock_guard<std::mutex> lk(aiMutex_);
                std::string t = text.size() > 400 ? text.substr(0, 400) + " ..." : text;
                chat_.push_back({"assistant", (kind == "tool" ? "[tool] " : "") + t});
            };
            cb.cancelled = []() { return false; };

            resp = ai_.runAgent(sys, hist, userMsg, aiToolDefs(), 4096, 16, cb, err);
        } else {
            std::string sys =
                "Eres un asistente experto en ingenieria inversa y analisis de malware. "
                "Ayudas a interpretar ensamblador x86/x64, volcados de memoria, y a identificar "
                "comportamiento malicioso con fines defensivos (crear antivirus/limpiar equipos). "
                "Se conciso y tecnico. Responde en espanol.";
            std::vector<ChatMessage> h = hist;
            h.push_back({"user", userMsg});
            resp = ai_.send(sys, h, 4096, err);
        }
        std::lock_guard<std::mutex> lk(aiMutex_);
        if (!resp.empty()) chat_.push_back({"assistant", resp});
        else { aiError_ = err; chat_.push_back({"assistant", "[error] " + err}); }
        aiBusy_ = false;
    });
}

void App::drawAiPanel() {
    ImGui::Begin("IA");

    // Seleccion del agente: solo se elige entre los ya configurados en Options.
    auto& agents = aiConfig_.agents();
    const AiAgent* cur = aiConfig_.current();
    ImGui::SetNextItemWidth(220);
    ImGui::BeginDisabled(aiBusy_);
    if (ImGui::BeginCombo("##agent", cur ? cur->name.c_str() : "(sin agentes)")) {
        for (int i = 0; i < (int)agents.size(); ++i) {
            bool sel = (i == aiConfig_.selected());
            if (ImGui::Selectable(agents[i].name.c_str(), sel)) aiConfig_.setSelected(i);
            if (sel) ImGui::SetItemDefaultFocus();
        }
        ImGui::EndCombo();
    }
    ImGui::EndDisabled();
    ImGui::SameLine();
    if (cur) ImGui::TextDisabled("%s", cur->model.c_str());
    ImGui::SameLine(ImGui::GetContentRegionAvail().x - 80);
    if (ImGui::Button("Configurar")) {
        showOptions_ = true;
        optLoadDraft(aiConfig_.selected());
    }
    ImGui::Checkbox("Incluir contexto (registros + desensamblado)", &aiIncludeContext_);
    bool canTools = cur && cur->supportsTools;
    ImGui::BeginDisabled(!canTools || aiBusy_);
    ImGui::Checkbox("Permitir control del debugger (tools)", &aiAgentMode_);
    ImGui::EndDisabled();
    ImGui::SameLine();
    if (!canTools) ImGui::TextDisabled("(agente sin tools)");
    else if (aiAgentMode_) ImGui::TextColored(ImVec4(1,0.6f,0.3f,1), "La IA puede ejecutar acciones sobre el proceso.");
    ImGui::Separator();

    ImGui::BeginChild("chat", ImVec2(0, ImGui::GetContentRegionAvail().y - 90), true);
    {
        std::lock_guard<std::mutex> lk(aiMutex_);
        for (auto& m : chat_) {
            bool user = (m.role == "user");
            ImGui::TextColored(user ? ImVec4(0.6f,0.9f,1,1) : ImVec4(0.7f,1,0.7f,1),
                               "%s:", user ? "Tu" : "IA");
            ImGui::TextWrapped("%s", m.content.c_str());
            ImGui::Separator();
        }
    }
    if (ImGui::GetScrollY() >= ImGui::GetScrollMaxY() - 5) ImGui::SetScrollHereY(1.0f);
    ImGui::EndChild();

    if (aiBusy_) ImGui::TextColored(ImVec4(1,0.9f,0.4f,1), "La IA esta pensando...");

    ImGui::InputTextMultiline("##in", aiInput_, sizeof(aiInput_), ImVec2(-80, 60));
    ImGui::SameLine();
    ImGui::BeginDisabled(aiBusy_);
    if (ImGui::Button("Enviar", ImVec2(70, 60))) sendAiMessage();
    ImGui::EndDisabled();

    ImGui::End();
}

// ---------------------------------------------------------------------------
// Ventana Code: convierte una rutina en pseudocodigo C++ legible. Es una
// interpretacion asistida; no afirma recuperar el codigo fuente original.
// ---------------------------------------------------------------------------
void App::sendCodeRequest() {
    if (aiBusy_) return;
    const AiAgent* agent = aiConfig_.current();
    if (!agent) { aiError_ = "No hay agente configurado (Tools -> Options -> AI)."; return; }

    std::string request = codeInput_;
    if (request.empty()) request = "Interpreta el procedimiento como pseudocodigo C++ claro.";
    uint64_t target = 0;
    if (codeAddr_[0]) target = strtoull(codeAddr_, nullptr, 16);
    else if (dbgState_ == DbgState::Paused) target = currentIp_;
    if (target) request += "\n\nDireccion inicial de la rutina: 0x" + hex64(target) + ".";
    request += "\nUsa el desensamblado de esa direccion antes de responder.";
    if (aiIncludeContext_) request = aiContextSnapshot() + "\n\nSolicitud Code:\n" + request;

    ai_.setAgent(*agent);
    aiBusy_ = true;
    aiError_.clear();
    { std::lock_guard<std::mutex> lk(aiMutex_); codeOutput_ = "Analizando rutina..."; }
    if (aiThread_.joinable()) aiThread_.join();

    aiThread_ = std::thread([this, request, toolsEnabled = agent->supportsTools]() {
        std::string err, response;
        std::string sys =
            "Eres un analista experto de binarios x86/x64 con fines defensivos. "
            "Convierte la rutina solicitada en PSEUDOCODIGO C++ legible. No es codigo fuente "
            "recuperado: marca las inferencias, nombres tentativos y partes desconocidas. "
            "Usa dbg_disasm y, si hace falta, dbg_read_mem, dbg_modules, dbg_symbol o dbg_call_stack. "
            "En esta ventana solo puedes INSPECCIONAR: no lances, continues, pares, escribas, "
            "parchees ni cambies breakpoints. Responde en espanol con un bloque C++ seguido de "
            "notas muy breves.";
        if (toolsEnabled) {
            auto tools = aiToolDefs();
            const std::vector<std::string> allowed = {
                "dbg_status", "dbg_plugin_list", "dbg_plugin_sdk", "dbg_get_regs", "dbg_read_mem", "dbg_disasm", "dbg_stack",
                "dbg_modules", "dbg_sections", "dbg_imports", "dbg_exports", "dbg_packers",
                "dbg_search_hex", "dbg_get_oep", "dbg_symbol", "dbg_source", "dbg_call_stack", "dbg_tls",
                "dbg_seh", "dbg_mem_map", "dbg_list_annotations", "dbg_find_refs", "dbg_get_trace",
                "dbg_list_functions", "dbg_list_xrefs", "dbg_list_loops", "dbg_list_bookmarks"
            };
            tools.erase(std::remove_if(tools.begin(), tools.end(), [&](const ToolDef& t) {
                return std::find(allowed.begin(), allowed.end(), t.name) == allowed.end();
            }), tools.end());
            AiCallbacks cb;
            cb.execTool = [this](const std::string& name, const std::string& argsJson) {
                std::string cmd = name.rfind("dbg_", 0) == 0 ? name.substr(4) : name;
                njson args = njson::object();
                try { if (!argsJson.empty()) args = njson::parse(argsJson); } catch (...) {}
                njson req = {{"cmd", cmd}, {"args", args.is_object() ? args : njson::object()}};
                std::string out = execDbgCommand(req.dump());
                return out.size() > 6000 ? out.substr(0, 6000) + " ...[truncado]" : out;
            };
            cb.cancelled = []() { return false; };
            response = ai_.runAgent(sys, {}, request, tools, 4096, 12, cb, err);
        } else {
            response = ai_.send(sys, {{"user", request}}, 4096, err);
        }
        std::lock_guard<std::mutex> lk(aiMutex_);
        codeOutput_ = response.empty() ? "[error] " + err : response;
        aiBusy_ = false;
    });
}

void App::drawCodePanel() {
    ImGui::Begin("Code");
    ImGui::TextDisabled("Pseudocodigo C++ interpretado; no recupera el fuente original.");
    ImGui::SetNextItemWidth(190);
    ImGui::InputTextWithHint("Direccion", "RIP o VA hexadecimal", codeAddr_, sizeof(codeAddr_));
    ImGui::SameLine();
    if (ImGui::Button("Usar RIP") && dbgState_ == DbgState::Paused)
        std::snprintf(codeAddr_, sizeof(codeAddr_), "%llX", (unsigned long long)currentIp_);
    ImGui::InputTextMultiline("##code_request", codeInput_, sizeof(codeInput_), ImVec2(-1, 75));
    ImGui::BeginDisabled(aiBusy_);
    if (ImGui::Button("Interpretar como C++")) sendCodeRequest();
    ImGui::SameLine();
    if (ImGui::Button("Generar DLL plugin")) {
        std::snprintf(codeInput_, sizeof(codeInput_), "%s", "Usa dbg_plugin_sdk y genera el codigo fuente C++ completo de un plugin DLL x64 para esta tarea. Define acciones MCP con input_schema y explica como compilarlo. No intentes cargarlo ni ejecutarlo.");
    }
    ImGui::EndDisabled();
    if (aiBusy_) { ImGui::SameLine(); ImGui::TextDisabled("El agente esta analizando..."); }
    ImGui::Separator();
    ImGui::BeginChild("code_output", ImVec2(0, 0), true, ImGuiWindowFlags_HorizontalScrollbar);
    { std::lock_guard<std::mutex> lk(aiMutex_); ImGui::TextUnformatted(codeOutput_.c_str()); }
    ImGui::EndChild();
    ImGui::End();
}

// ---------------------------------------------------------------------------
// Tools -> Options (seccion AI: alta/edicion de agentes)
// ---------------------------------------------------------------------------
void App::optLoadDraft(int idx) {
    auto& agents = aiConfig_.agents();
    optStatus_.clear();
    optPresetIdx_ = -1;
    if (idx < 0 || idx >= (int)agents.size()) {
        optEditIdx_ = -1;
        optDraft_ = AiAgent{};
        optName_[0] = optHost_[0] = optPath_[0] = optKey_[0] = optModel_[0] = '\0';
        optPort_ = 443;
        return;
    }
    optEditIdx_ = idx;
    optDraft_ = agents[idx];
    std::snprintf(optName_,  sizeof(optName_),  "%s", optDraft_.name.c_str());
    std::snprintf(optHost_,  sizeof(optHost_),  "%s", optDraft_.host.c_str());
    std::snprintf(optPath_,  sizeof(optPath_),  "%s", optDraft_.path.c_str());
    std::snprintf(optKey_,   sizeof(optKey_),   "%s", optDraft_.apiKey.c_str());
    std::snprintf(optModel_, sizeof(optModel_), "%s", optDraft_.model.c_str());
    optPort_ = optDraft_.port;
    // Si coincide con un preset, dejarlo marcado para mostrar sus modelos.
    const auto& ps = aiPresets();
    for (int i = 0; i < (int)ps.size(); ++i)
        if (optDraft_.host == ps[i].host && optDraft_.path == ps[i].path) { optPresetIdx_ = i; break; }
}

void App::optApplyPreset(int presetIdx) {
    const auto& ps = aiPresets();
    if (presetIdx < 0 || presetIdx >= (int)ps.size()) return;
    const AiPreset& p = ps[presetIdx];
    optPresetIdx_ = presetIdx;
    optDraft_.style = p.style;
    optDraft_.https = p.https;
    optDraft_.supportsTools = p.tools;
    std::snprintf(optHost_, sizeof(optHost_), "%s", p.host);
    std::snprintf(optPath_, sizeof(optPath_), "%s", p.path);
    optPort_ = p.port;
    if (!optName_[0]) std::snprintf(optName_, sizeof(optName_), "%s", p.name);
    if (!p.models.empty()) std::snprintf(optModel_, sizeof(optModel_), "%s", p.models[0]);
    optStatus_.clear();
}

void App::drawOptionsWindow() {
    ImGui::SetNextWindowSize(ImVec2(680, 460), ImGuiCond_FirstUseEver);
    if (!ImGui::Begin("Options", &showOptions_)) { ImGui::End(); return; }

    if (ImGui::BeginTabBar("##opttabs")) {
        if (ImGui::BeginTabItem("AI")) {
            auto& agents = aiConfig_.agents();

            // ---- Columna izquierda: lista de agentes dados de alta ----
            ImGui::BeginChild("agents", ImVec2(200, 0), true);
            ImGui::TextDisabled("Agentes");
            ImGui::Separator();
            for (int i = 0; i < (int)agents.size(); ++i) {
                ImGui::PushID(i);
                std::string label = agents[i].name + (i == aiConfig_.selected() ? "  [en uso]" : "");
                if (ImGui::Selectable(label.c_str(), i == optEditIdx_)) optLoadDraft(i);
                ImGui::PopID();
            }
            ImGui::Separator();
            if (ImGui::Button("Nuevo", ImVec2(-1, 0))) optLoadDraft(-1);
            ImGui::BeginDisabled(optEditIdx_ < 0);
            if (ImGui::Button("Eliminar", ImVec2(-1, 0))) {
                agents.erase(agents.begin() + optEditIdx_);
                if (aiConfig_.selected() >= (int)agents.size())
                    aiConfig_.setSelected((int)agents.size() - 1);
                aiConfig_.save();
                if (const AiAgent* a = aiConfig_.current()) ai_.setAgent(*a);
                optLoadDraft(-1);
            }
            ImGui::EndDisabled();
            ImGui::EndChild();

            // ---- Columna derecha: formulario del agente ----
            ImGui::SameLine();
            ImGui::BeginChild("form", ImVec2(0, 0), true);
            ImGui::TextDisabled(optEditIdx_ < 0 ? "Nuevo agente" : "Editar agente");
            ImGui::Separator();

            const auto& ps = aiPresets();
            ImGui::SetNextItemWidth(240);
            if (ImGui::BeginCombo("Preset", optPresetIdx_ >= 0 ? ps[optPresetIdx_].name : "(personalizado)")) {
                for (int i = 0; i < (int)ps.size(); ++i)
                    if (ImGui::Selectable(ps[i].name, i == optPresetIdx_)) optApplyPreset(i);
                ImGui::EndCombo();
            }

            ImGui::SetNextItemWidth(240);
            ImGui::InputText("Nombre", optName_, sizeof(optName_));

            int style = (optDraft_.style == ApiStyle::Anthropic) ? 0 : 1;
            ImGui::SetNextItemWidth(240);
            if (ImGui::Combo("Estilo de API", &style, "Anthropic (messages)\0OpenAI (chat/completions)\0"))
                optDraft_.style = style == 0 ? ApiStyle::Anthropic : ApiStyle::OpenAI;

            ImGui::SetNextItemWidth(240);
            ImGui::InputText("Host / IP", optHost_, sizeof(optHost_));
            ImGui::SetNextItemWidth(100);
            ImGui::InputInt("Puerto", &optPort_, 0);
            ImGui::SameLine();
            ImGui::Checkbox("HTTPS", &optDraft_.https);
            ImGui::SetNextItemWidth(240);
            ImGui::InputText("Ruta", optPath_, sizeof(optPath_));
            ImGui::SetNextItemWidth(240);
            ImGui::InputText("API Key", optKey_, sizeof(optKey_), ImGuiInputTextFlags_Password);
            if (optPresetIdx_ >= 0 && !ps[optPresetIdx_].needsKey)
                { ImGui::SameLine(); ImGui::TextDisabled("(no requerida)"); }

            ImGui::SetNextItemWidth(240);
            ImGui::InputText("Modelo", optModel_, sizeof(optModel_));
            if (optPresetIdx_ >= 0 && !ps[optPresetIdx_].models.empty()) {
                ImGui::SameLine();
                ImGui::SetNextItemWidth(20);
                if (ImGui::BeginCombo("##models", "", ImGuiComboFlags_NoPreview)) {
                    for (auto* m : ps[optPresetIdx_].models)
                        if (ImGui::Selectable(m)) std::snprintf(optModel_, sizeof(optModel_), "%s", m);
                    ImGui::EndCombo();
                }
            }

            ImGui::Checkbox("Soporta tools (function calling)", &optDraft_.supportsTools);
            ImGui::SameLine();
            ImGui::TextDisabled("(permite que la IA controle el debugger)");

            ImGui::Separator();
            if (ImGui::Button("Guardar", ImVec2(120, 0))) {
                if (!optName_[0])       optStatus_ = "Falta el nombre del agente.";
                else if (!optHost_[0])  optStatus_ = "Falta el host o IP.";
                else if (!optModel_[0]) optStatus_ = "Falta el modelo.";
                else {
                    optDraft_.name   = optName_;
                    optDraft_.host   = optHost_;
                    optDraft_.port   = optPort_ > 0 ? optPort_ : (optDraft_.https ? 443 : 80);
                    optDraft_.path   = optPath_[0] ? optPath_ : "/v1/chat/completions";
                    optDraft_.apiKey = optKey_;
                    optDraft_.model  = optModel_;
                    if (optEditIdx_ < 0) {
                        agents.push_back(optDraft_);
                        optEditIdx_ = (int)agents.size() - 1;
                        if (agents.size() == 1) aiConfig_.setSelected(0);
                    } else {
                        agents[optEditIdx_] = optDraft_;
                    }
                    aiConfig_.save();
                    if (const AiAgent* a = aiConfig_.current()) ai_.setAgent(*a);
                    optStatus_ = "Guardado.";
                }
            }
            ImGui::SameLine();
            ImGui::BeginDisabled(optEditIdx_ < 0);
            if (ImGui::Button("Usar este agente", ImVec2(140, 0))) {
                aiConfig_.setSelected(optEditIdx_);
                if (const AiAgent* a = aiConfig_.current()) ai_.setAgent(*a);
                optStatus_ = "Agente en uso: " + aiConfig_.agents()[optEditIdx_].name;
            }
            ImGui::EndDisabled();
            if (!optStatus_.empty()) {
                ImGui::SameLine();
                ImGui::TextColored(ImVec4(1, 0.9f, 0.4f, 1), "%s", optStatus_.c_str());
            }
            ImGui::EndChild();
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("Simbolos")) {   // M5: symbol server
            ImGui::TextWrapped("Ruta de simbolos (formato DbgHelp/symsrv). Se usa para resolver "
                               "nombres y call stack. Ejemplo con el servidor de Microsoft:");
            ImGui::TextDisabled("srv*C:\\symbols*https://msdl.microsoft.com/download/symbols");
            ImGui::SetNextItemWidth(-1);
            ImGui::InputText("##sympath", symPathBuf_, sizeof(symPathBuf_));
            if (ImGui::Button("Usar servidor de Microsoft")) {
                std::snprintf(symPathBuf_, sizeof(symPathBuf_),
                    "srv*C:\\symbols*https://msdl.microsoft.com/download/symbols");
            }
            ImGui::SameLine();
            if (ImGui::Button("Aplicar y guardar")) {
                debugger_.setSymbolSearchPath(symPathBuf_);
                saveSymPath();
                optStatus_ = "Ruta de simbolos aplicada.";
            }
            ImGui::SameLine();
            if (ImGui::Button("Limpiar##sym")) { symPathBuf_[0] = '\0'; debugger_.setSymbolSearchPath(""); saveSymPath(); }
            ImGui::EndTabItem();
        }
        ImGui::EndTabBar();
    }
    ImGui::End();
}

static std::string symPathFilePath() {
    wchar_t exe[MAX_PATH] = {0};
    GetModuleFileNameW(nullptr, exe, MAX_PATH);
    std::wstring w(exe);
    auto pos = w.find_last_of(L"\\/");
    std::wstring dir = (pos == std::wstring::npos) ? L"." : w.substr(0, pos);
    std::wstring path = dir + L"\\symsrv.txt";
    return std::string(path.begin(), path.end());
}
void App::saveSymPath() {
    std::ofstream f(symPathFilePath(), std::ios::binary);
    if (f) f << symPathBuf_;
}
void App::loadSymPath() {
    std::ifstream f(symPathFilePath(), std::ios::binary);
    if (!f) return;
    std::string s((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    while (!s.empty() && (s.back() == '\n' || s.back() == '\r')) s.pop_back();
    std::snprintf(symPathBuf_, sizeof(symPathBuf_), "%s", s.c_str());
    if (s.size()) debugger_.setSymbolSearchPath(s);
}

} // namespace dbg

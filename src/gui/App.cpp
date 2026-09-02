#include "App.h"

#include <windows.h>
#include <bcrypt.h>
#include <commdlg.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <shellapi.h>
#include <algorithm>
#include <array>
#include <set>
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

static constexpr const char* kAppVersion = "1.0.0";
static std::string favFilePath();   // definida mas abajo; usada en el menu Favourites
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
    cb.onModule = [this](const LoadedModule& m){ pushLog("DLL: " + m.name + "  @0x" + hex64(m.base)); pushEvent("load_dll", m.base); };
    cb.onBreak  = [this](uint64_t va){ pushEvent("breakpoint", va); };
    // Fase 3: bus de eventos CB_*. Se publica al log y a la cola de eventos que
    // los clientes MCP sondean con poll_events (streaming por polling).
    cb.onEvent  = [this](const std::string& type, uint64_t arg){
        pushLog("[evento] " + type + "  0x" + hex64(arg));
        pushEvent(type, arg);
    };
    debugger_.setCallbacks(cb);

    aiConfig_.load();
    if (const AiAgent* a = aiConfig_.current()) ai_.setAgent(*a);
    loadExternalPlugins();
    loadRecent();
    loadSymPath();
    loadNotes();
    loadFavourites();
    loadSkills();
    loadContainerState();
    containerDockInit_ = true;   // construir el layout del Contenedor la primera vez que se dibuje
    loadLayouts();
    loadVisibility();
    ensureVisibilityKeys();
    // Primer arranque (sin imgui.ini): construir un layout de docking ordenado.
    { std::ifstream ini("imgui.ini"); if (!ini.good()) dockNeedsInit_ = true; }
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

// Fase 3: encola un evento para poll_events (streaming por MCP) y para plugins.
void App::pushEvent(const std::string& type, uint64_t arg) {
    { std::lock_guard<std::mutex> lk(eventsMutex_);
      events_.push_back({ ++eventSeq_, type, arg });
      while (events_.size() > 2000) events_.pop_front(); }
    // Reenvio a plugins: si un plugin JSON declara una accion con id "on_event",
    // se invoca con el tipo y el argumento (suscripcion declarativa).
    for (const auto& p : externalPlugins_.plugins()) {
        if (!p.enabled) continue;
        for (const auto& a : p.actions) {
            if (a.id == "on_event") {
                njson args; args["type"] = type; args["arg"] = arg;
                runExternalPluginAction(p.id, a.id, args.dump());
            }
        }
    }
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

// Conmuta el target a un proceso hijo: desadjunta el actual (lo deja corriendo) y
// programa el attach al hijo cuando el motor vuelva a Idle (se completa en render()).
void App::switchToChild(uint32_t pid) {
    if (!pid) { pushLog("Conmutar: PID invalido."); return; }
    if (dbgState_ == DbgState::Idle) { attachToProcess(pid); return; }
    std::string err;
    if (debugger_.detach(err)) { pendingSwitchPid_ = pid; pushLog("Conmutando al hijo PID " + std::to_string(pid) + " (desadjuntando el actual)..."); }
    else { debugger_.detachAndStop(); pendingSwitchPid_ = pid; pushLog("Conmutando al hijo PID " + std::to_string(pid) + "..."); }
}

// Run to cursor: pone un breakpoint temporal en 'va' y continua. Al pausar en esa
// direccion (ver render()), el breakpoint se retira automaticamente.
// Skip: avanza el puntero de instruccion a la siguiente instruccion SIN ejecutar la actual.
void App::skipInstruction() {
    if (dbgState_ != DbgState::Paused) { pushLog("Skip: el proceso debe estar pausado."); return; }
    uint8_t buf[16] = {0};
    size_t got = debugger_.readMemory(currentIp_, buf, sizeof(buf));
    dis_.setMode(debugger_.is64());
    auto v = dis_.disassemble(buf, got, currentIp_, 1);
    uint32_t len = v.empty() ? 1 : v[0].length;
    debugger_.setRegister(debugger_.is64() ? "rip" : "eip", currentIp_ + len);
    pushLog("Skip: RIP avanzado a 0x" + hex64(currentIp_ + len));
    refreshLiveDisassembly(currentIp_ + len);
}
// Undo: restaura los registros que habia antes del ultimo paso (no revierte memoria).
void App::undoInstruction() {
    if (dbgState_ != DbgState::Paused) return;
    if (!haveRegsBefore_) { pushLog("Undo: no hay estado previo guardado."); return; }
    Registers r = regsBeforeStep_;
    auto set = [&](const char* n, uint64_t val){ debugger_.setRegister(n, val); };
    if (r.is64) { set("rax",r.rax);set("rbx",r.rbx);set("rcx",r.rcx);set("rdx",r.rdx);set("rsi",r.rsi);set("rdi",r.rdi);
                  set("rbp",r.rbp);set("rsp",r.rsp);set("rip",r.rip);set("r8",r.r8);set("r9",r.r9);set("r10",r.r10);
                  set("r11",r.r11);set("r12",r.r12);set("r13",r.r13);set("r14",r.r14);set("r15",r.r15); }
    else { set("eax",r.rax);set("ebx",r.rbx);set("ecx",r.rcx);set("edx",r.rdx);set("esi",r.rsi);set("edi",r.rdi);
           set("ebp",r.rbp);set("esp",r.rsp);set("eip",r.rip); }
    set("eflags", r.eflags);
    haveRegsBefore_ = false;
    pushLog("Undo: registros restaurados a 0x" + hex64(r.rip) + " (no revierte memoria).");
    refreshLiveDisassembly(r.rip);
}

// Run until expression: arranca el bucle de single-step condicional.
void App::startRunUntil(const std::string& expr, int mode, int maxSteps) {
    if (dbgState_ != DbgState::Paused) { pushLog("Run until: el proceso debe estar pausado."); return; }
    runUntilExpr_ = expr; runUntilMode_ = mode; runUntilMax_ = maxSteps > 0 ? maxSteps : 100000;
    runUntilCount_ = 0; runUntilActive_ = true;
    pushLog("Run until '" + expr + "' iniciado.");
    tickRunUntil();
}
// Llamado en cada pausa: evalua la expresion; si es cierta o se agoto el tope, para;
// si no, da el siguiente single-step (into/over).
void App::tickRunUntil() {
    if (!runUntilActive_ || dbgState_ != DbgState::Paused) return;
    uint64_t v = 0; std::string err;
    bool okEval = evalExpr(runUntilExpr_, v, err);
    if (okEval && v != 0) { runUntilActive_ = false; pushLog("Run until: condicion cumplida en 0x" + hex64(currentIp_) + " tras " + std::to_string(runUntilCount_) + " pasos."); return; }
    if (runUntilCount_ >= runUntilMax_) { runUntilActive_ = false; pushLog("Run until: tope de " + std::to_string(runUntilMax_) + " pasos alcanzado."); return; }
    runUntilCount_++;
    if (runUntilMode_ == 1) debugger_.stepOver(); else debugger_.stepInto();
}

void App::runToAddress(uint64_t va) {
    if (dbgState_ != DbgState::Paused) { pushLog("Run hasta: el proceso debe estar pausado."); return; }
    bool already = false;
    for (auto& b : debugger_.breakpoints()) if (b.address == va) already = true;
    if (!already) { debugger_.addBreakpoint(va, "run-to"); runToTemp_.insert(va); }
    debugger_.go();
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

// Hash del contenido del PE (FNV-1a 64). Identificador estable para la DB por hash (M6).
std::string App::peContentHash() {
    if (!fileLoaded_) return "";
    uint64_t h = 1469598103934665603ull;
    for (uint8_t b : pe_.raw()) { h ^= b; h *= 1099511628211ull; }
    char buf[20]; std::snprintf(buf, sizeof(buf), "%016llX", (unsigned long long)h);
    return buf;
}

// Informe estructurado en JSON (base para integraciones/SARIF).
std::string App::buildAnalysisReportJson() {
    njson j;
    j["tool"] = "DebuggerJ++";
    j["target"] = std::string(loadedPath_.begin(), loadedPath_.end());
    j["peHash"] = peContentHash();
    j["arch"] = pe_.is64Bit() ? "x64" : "x86";
    j["imageBase"] = pe_.imageBase();
    j["entryPoint"] = pe_.entryPointVA();
    j["overallEntropy"] = pe_.overallEntropy();
    const char* state = dbgState_ == DbgState::Paused ? "paused" : dbgState_ == DbgState::Running ? "running" :
                        dbgState_ == DbgState::Launching ? "launching" : dbgState_ == DbgState::Exited ? "exited" : "idle";
    j["state"] = state;
    for (const auto& s : pe_.sections())
        j["sections"].push_back({{"name", s.name}, {"rva", s.virtualAddress}, {"vsize", s.virtualSize},
                                 {"entropy", s.entropy}, {"exec", s.executable()}, {"write", s.writable()}});
    for (const auto& p : packerMatches_)
        j["packers"].push_back({{"name", p.name}, {"confidence", p.confidence}, {"source", p.source}});
    for (const auto& bp : debugger_.breakpoints()) if (!bp.oneShot)
        j["breakpoints"].push_back({{"addr", bp.address}, {"hits", bp.hits}, {"break_on_hit", bp.breakOnHit},
                                    {"condition", bp.condition}, {"log_only", bp.logOnly}});
    for (const auto& f : analyzedFunctions_)
        j["functions"].push_back({{"start", f.start}, {"end", f.end}, {"instructions", f.instructions},
                                  {"calls", f.calls}, {"branches", f.branches}, {"name", f.name}});
    j["note"] = "Informe de sesion; no prueba por si solo comportamiento malicioso. Ejecutar en VM aislada.";
    return j.dump(2);
}

bool App::saveAnalysisReportJson(const std::wstring& path, std::string& error) {
    if (!fileLoaded_) { error = "abre un archivo antes de exportar el informe"; return false; }
    std::ofstream file(path, std::ios::binary | std::ios::trunc);
    if (!file) { error = "no se pudo crear el informe JSON"; return false; }
    file << buildAnalysisReportJson();
    if (!file) { error = "no se pudo escribir el informe JSON"; return false; }
    return true;
}

// Informe SARIF 2.1.0: cada heurística/deteccion es un 'result' con su regla.
std::string App::buildSarifReport() {
    njson rules = njson::array();
    njson results = njson::array();
    auto addRule = [&](const char* id, const char* name, const char* desc) {
        rules.push_back({{"id", id}, {"name", name},
                         {"shortDescription", {{"text", desc}}}});
    };
    auto addResult = [&](const char* ruleId, const char* level, const std::string& msg, uint64_t addr) {
        njson r;
        r["ruleId"] = ruleId;
        r["level"] = level;   // note | warning | error
        r["message"] = {{"text", msg}};
        njson loc;
        loc["physicalLocation"]["artifactLocation"]["uri"] = std::string(loadedPath_.begin(), loadedPath_.end());
        if (addr) loc["physicalLocation"]["region"]["startLine"] = 1, loc["logicalLocations"] = njson::array({{{"name", "0x" + hex64(addr)}}});
        r["locations"] = njson::array({loc});
        results.push_back(r);
    };

    addRule("DBGJ.PACKER", "packer-detected", "Firma o heuristica de packer/protector.");
    addRule("DBGJ.HIGH_ENTROPY", "high-entropy-section", "Seccion con entropia alta (posible cifrado/empaquetado).");
    addRule("DBGJ.WX_SECTION", "writable-executable-section", "Seccion escribible y ejecutable a la vez.");
    addRule("DBGJ.TLS", "tls-callbacks", "El PE declara TLS callbacks (codigo antes del entrypoint).");
    addRule("DBGJ.LOW_IMPORTS", "few-imports", "Muy pocos imports (tipico de binarios empaquetados).");

    for (const auto& p : packerMatches_)
        addResult("DBGJ.PACKER", "warning", "Packer: " + p.name + " (" + std::to_string(p.confidence) + "%, " + p.source + ")", pe_.entryPointVA());
    for (const auto& s : pe_.sections()) {
        if (s.entropy > 7.2)
            addResult("DBGJ.HIGH_ENTROPY", "warning", "Seccion " + s.name + " entropia " + std::to_string(s.entropy), pe_.imageBase() + s.virtualAddress);
        if (s.executable() && s.writable())
            addResult("DBGJ.WX_SECTION", "error", "Seccion " + s.name + " es W+X", pe_.imageBase() + s.virtualAddress);
    }
    if (!pe_.tlsCallbacks().empty())
        addResult("DBGJ.TLS", "warning", std::to_string(pe_.tlsCallbacks().size()) + " TLS callback(s)", pe_.tlsCallbacks().front());
    if (pe_.imports().size() < 10 && !pe_.imports().empty())
        addResult("DBGJ.LOW_IMPORTS", "note", std::to_string(pe_.imports().size()) + " imports", 0);

    njson sarif;
    sarif["version"] = "2.1.0";
    sarif["$schema"] = "https://json.schemastore.org/sarif-2.1.0.json";
    njson run;
    run["tool"]["driver"] = {{"name", "DebuggerJ++"}, {"informationUri", "https://github.com/jaime64net/DebuggerJ-"},
                             {"rules", rules}};
    run["results"] = results;
    sarif["runs"] = njson::array({run});
    return sarif.dump(2);
}

bool App::saveSarifReport(const std::wstring& path, std::string& error) {
    if (!fileLoaded_) { error = "abre un archivo antes de exportar SARIF"; return false; }
    std::ofstream file(path, std::ios::binary | std::ios::trunc);
    if (!file) { error = "no se pudo crear el SARIF"; return false; }
    file << buildSarifReport();
    if (!file) { error = "no se pudo escribir el SARIF"; return false; }
    return true;
}

// Validación de un ejecutable volcado (unpacking): carga el PE y revisa coherencia.
bool App::validateDump(const std::wstring& path, std::string& report) {
    PeFile dump; std::string err;
    if (!dump.load(path, err)) { report = "No es un PE válido: " + err; return false; }
    std::ostringstream o;
    bool ok = true;
    o << "Arquitectura: " << (dump.is64Bit() ? "x64" : "x86") << "\n";
    o << "ImageBase: 0x" << hex64(dump.imageBase()) << "  EntryPoint: 0x" << hex64(dump.entryPointVA()) << "\n";

    // 1) entrypoint dentro de una sección ejecutable
    uint64_t epRva = dump.entryPointVA() - dump.imageBase();
    bool epExec = false;
    for (const auto& s : dump.sections())
        if (epRva >= s.virtualAddress && epRva < s.virtualAddress + s.virtualSize && s.executable()) epExec = true;
    o << (epExec ? "[OK] " : "[!!] ") << "EntryPoint " << (epExec ? "cae en sección ejecutable\n" : "NO cae en sección ejecutable (dump sospechoso)\n");
    if (!epExec) ok = false;

    // 2) entropía por sección (si sigue muy alta, probablemente sigue empacado)
    int highEntropy = 0;
    for (const auto& s : dump.sections()) {
        o << "  " << s.name << "  entropia=" << s.entropy;
        if (s.executable() && s.entropy > 7.0) { o << "  [!! alta para código]"; highEntropy++; }
        o << "\n";
    }
    if (highEntropy) { o << "[!!] " << highEntropy << " sección(es) de código con entropía alta: puede seguir empacado.\n"; ok = false; }
    else o << "[OK] Entropía de código en rango normal.\n";

    // 3) IAT / imports
    if (dump.imports().empty()) { o << "[!!] Sin imports: la IAT no está reconstruida (usa Corregir IAT).\n"; ok = false; }
    else o << "[OK] " << dump.imports().size() << " imports presentes.\n";

    // 4) coherencia de secciones: solapamientos y sizeOfImage
    {
        std::vector<std::pair<uint64_t,uint64_t>> ranges;
        for (const auto& s : dump.sections()) ranges.push_back({s.virtualAddress, s.virtualAddress + (s.virtualSize ? s.virtualSize : 1)});
        std::sort(ranges.begin(), ranges.end());
        bool overlap = false;
        for (size_t k = 1; k < ranges.size(); ++k) if (ranges[k].first < ranges[k-1].second) overlap = true;
        if (overlap) { o << "[!!] Hay secciones que se solapan (dump/headers inconsistentes).\n"; ok = false; }
        else o << "[OK] Secciones sin solapamiento.\n";
        uint64_t maxEnd = ranges.empty() ? 0 : ranges.back().second;
        if (dump.sizeOfImage() < maxEnd) { o << "[!!] sizeOfImage (0x" << hex64(dump.sizeOfImage()) << ") menor que el fin de la ultima seccion.\n"; ok = false; }
        else o << "[OK] sizeOfImage coherente.\n";
    }
    // 5) TLS callbacks (informativo)
    if (!dump.tlsCallbacks().empty()) o << "[i] " << dump.tlsCallbacks().size() << " TLS callback(s): revisa que apunten a codigo valido.\n";

    o << (ok ? "\nRESULTADO: el dump parece VALIDO.\n" : "\nRESULTADO: el dump tiene PROBLEMAS; revisa OEP/IAT/headers.\n");
    report = o.str();
    return ok;
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
            if (dbgState_ == DbgState::Running || dbgState_ == DbgState::Paused) { regsBeforeStep_ = regs_; haveRegsBefore_ = true; }  // para Undo
            regs_ = debugger_.registers();
            currentIp_ = regs_.ip();
            curModule_ = moduleNameAt(currentIp_);
            refreshLiveDisassembly(currentIp_);
            memMap_ = debugger_.memoryMap();
            if (debugger_.foundOEP()) pluginOEP_ = debugger_.foundOEP();
            refreshWatches();
            // Run to cursor: si pausamos en un BP temporal, retirarlo.
            if (runToTemp_.count(currentIp_)) { debugger_.removeBreakpoint(currentIp_); runToTemp_.erase(currentIp_); }
            if (runUntilActive_) tickRunUntil();   // Obj E: run until expression
            runBreakpointAction(currentIp_);   // M3: accion al golpear un BP
            // Re-aplicar anti-anti-debug si esta activado (el malware puede re-chequear)
            if (antiReapply_ && antiActive_) {
                std::string lg;
                applyAntiAntiDebug(debugger_, debugger_.is64(), antiOpt_, lg);
            }
        }
    }

    drainMcpQueue();

    // DockSpace del main: permite anclar (dock) las ventanas dentro de la ventana
    // principal. PassthruCentralNode deja el centro transparente para el fondo.
    // Nodo central OPACO (sin PassthruCentralNode): el central transparente parpadea como
    // recuadros con multi-viewport al dejar ver el fondo.
    ImGuiID mainDock = ImGui::DockSpaceOverViewport(0, ImGui::GetMainViewport());
    if (dockNeedsInit_) { dockNeedsInit_ = false; buildDefaultDock(mainDock); }

    // Animate (step animado): mientras esté activo y pausado, da un paso cada ~15 frames.
    if (animateActive_) {
        if (dbgState_ == DbgState::Paused) {
            if (++animateFrame_ >= 15) { animateFrame_ = 0; if (animateMode_ == 1) debugger_.stepOver(); else debugger_.stepInto(); }
        } else if (dbgState_ == DbgState::Exited || dbgState_ == DbgState::Idle) {
            animateActive_ = false;
        }
    }

    // Conmutacion a proceso hijo: cuando el detach del actual termina (Idle), adjunta el hijo.
    if (pendingSwitchPid_ && debugger_.state() == DbgState::Idle) {
        uint32_t pid = pendingSwitchPid_; pendingSwitchPid_ = 0;
        attachToProcess(pid);
    }

    // M11: hot-reload de plugins (cada ~120 frames si esta activado).
    if (pluginAutoReload_ && ++pluginCheckCounter_ >= 120) {
        pluginCheckCounter_ = 0;
        uint64_t now = pluginsDirStamp();
        if (now != pluginsStamp_) { loadExternalPlugins(); pushLog("Plugins recargados (cambio en disco)."); }
    }

    drawMenuBar();
    drawToolbar();
    // Paneles gestionados: se dibujan en el main salvo los que el usuario envió al Contenedor.
    for (auto nm : managedWindows())
        if (showInMain(nm)) drawManagedPanel(nm);
    if (showSearchResults_)              drawSearchResultsPanel();
    if (showOptions_)                    drawOptionsWindow();
    if (showSkillBrowser_)               drawSkillBrowser();
    if (showSkillManage_)                drawSkillManage();
    if (showHelp_)                       drawHelpWindow();
    if (showAttach_)                     drawAttachWindow();

    drawAddCustomPopup();
    drawStatusBar();
    applyMagneticSnap();     // imantacion de ventanas (si esta activada)
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
        "Command", "Watch", "Struct", "CFG", "Compare", "Script", "Threads", "Notes", "System", "Entropy"
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

// Ruta del archivo .ini de un layout con nombre (sanitizado).
static std::string layoutIniPath(const std::string& name) {
    wchar_t exe[MAX_PATH] = {0}; GetModuleFileNameW(nullptr, exe, MAX_PATH);
    std::wstring w(exe); auto p = w.find_last_of(L"\\/");
    std::wstring dir = (p == std::wstring::npos) ? L"." : w.substr(0, p);
    std::string safe; for (char c : name) safe += (std::isalnum((unsigned char)c) ? c : '_');
    std::wstring path = dir + L"\\layout_" + std::wstring(safe.begin(), safe.end()) + L".ini";
    return std::string(path.begin(), path.end());
}

// Un layout completo guarda: el .ini del contexto principal (posiciones/tamanos/docking del
// main), el .ini del contexto Contenedor, que paneles estan en el Contenedor, si estaba
// abierto y la geometria de la ventana OS del Contenedor. Todo en un archivo con secciones.
void App::captureLayout(const std::string& name) {
    std::string mainIni;
    { size_t sz = 0; const char* ini = ImGui::SaveIniSettingsToMemory(&sz); if (ini) mainIni.assign(ini, sz); }
    std::string contIni;
    if (contImGuiCtx_) {
        ImGuiContext* prev = ImGui::GetCurrentContext();
        ImGui::SetCurrentContext((ImGuiContext*)contImGuiCtx_);
        size_t sz2 = 0; const char* ini2 = ImGui::SaveIniSettingsToMemory(&sz2); if (ini2) contIni.assign(ini2, sz2);
        ImGui::SetCurrentContext(prev);
    }
    // geometria de la ventana OS del Contenedor
    int cx=0,cy=0,cw=0,ch=0;
    if (contHwnd_) { RECT rc; if (GetWindowRect((HWND)contHwnd_, &rc)) { cx=rc.left; cy=rc.top; cw=rc.right-rc.left; ch=rc.bottom-rc.top; } }

    std::ofstream f(layoutIniPath(name), std::ios::binary | std::ios::trunc);
    if (f) {
        f << "[meta]\n";
        f << "open|" << (containerOpen_?1:0) << "\n";
        f << "contwin|" << cx << "|" << cy << "|" << cw << "|" << ch << "\n";
        for (auto& [k,v] : winContainer_) if (v) f << "panel|" << k << "\n";
        f << "[main_ini]\n" << mainIni << "\n";
        f << "[cont_ini]\n" << contIni << "\n";
    }
    for (auto& e : customLayouts_) if (e.name == name) { saveLayouts(); pushLog("Layout actualizado: " + name); return; }
    WinLayout L; L.name = name;
    customLayouts_.push_back(L);
    saveLayouts();
    pushLog("Layout guardado (main + Contenedor): " + name);
}

void App::applyLayout(const WinLayout& L) {
    std::ifstream f(layoutIniPath(L.name), std::ios::binary);
    if (!f) { pushLog("Layout sin archivo: " + L.name); return; }
    std::string all((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    // separar secciones
    auto section = [&](const std::string& tag) -> std::string {
        std::string open = "[" + tag + "]\n";
        auto s = all.find(open); if (s == std::string::npos) return "";
        s += open.size();
        auto e = all.find("\n[", s);
        return all.substr(s, e == std::string::npos ? std::string::npos : e - s);
    };
    std::string meta = section("meta"), mainIni = section("main_ini"), contIni = section("cont_ini");

    // meta: paneles del contenedor, open, geometria
    winContainer_.clear();
    { std::stringstream ss(meta); std::string line;
      while (std::getline(ss, line)) {
          if (!line.empty() && line.back()=='\r') line.pop_back();
          auto bar = line.find('|'); if (bar==std::string::npos) continue;
          std::string k=line.substr(0,bar), rest=line.substr(bar+1);
          if (k=="open") containerOpen_ = (rest=="1");
          else if (k=="panel") winContainer_[rest] = true;
          else if (k=="contwin") {
              int v[4]={0,0,0,0}; std::stringstream rs(rest); std::string t; int i=0;
              while (std::getline(rs,t,'|') && i<4) v[i++]=atoi(t.c_str());
              if (v[2]>0 && v[3]>0) { for(int j=0;j<4;j++) pendingContWinRect_[j]=v[j]; pendingContWinMove_ = true; }
          }
      }
    }
    saveContainerState();
    // aplicar inis a cada contexto
    if (!mainIni.empty()) ImGui::LoadIniSettingsFromMemory(mainIni.data(), mainIni.size());
    if (!contIni.empty() && contImGuiCtx_) {
        ImGuiContext* prev = ImGui::GetCurrentContext();
        ImGui::SetCurrentContext((ImGuiContext*)contImGuiCtx_);
        ImGui::LoadIniSettingsFromMemory(contIni.data(), contIni.size());
        ImGui::SetCurrentContext(prev);
    }
    containerDockInit_ = false;   // usar el docking del layout, no reconstruir
    pushLog("Layout aplicado (main + Contenedor): " + L.name);
}

// La lista de layouts (solo nombres) se guarda en layouts.txt; cada uno tiene su .ini.
void App::saveLayouts() {
    std::ofstream f(layoutsFilePath());
    if (!f) return;
    for (auto& L : customLayouts_) f << L.name << "\n";
}

void App::loadLayouts() {
    customLayouts_.clear();
    std::ifstream f(layoutsFilePath());
    if (!f) return;
    std::string line;
    while (std::getline(f, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        // Compatibilidad: ignora las lineas del formato antiguo (con '|' o '[').
        if (line.empty() || line[0] == '[' || line.find('|') != std::string::npos) continue;
        WinLayout L; L.name = line; customLayouts_.push_back(L);
    }
}

bool App::visible(const char* name) {
    auto it = winVisible_.find(name);
    return it == winVisible_.end() ? true : it->second;
}
void App::ensureVisibilityKeys() {
    // Paneles auxiliares nuevos: ocultos por defecto para no saturar la pantalla al abrir
    // (se activan desde Window -> Show). El resto arranca visible.
    static const std::set<std::string> hiddenByDefault = {
        "Command", "Watch", "Struct", "CFG", "Compare", "Script", "Threads", "Notes", "System", "Entropy"
    };
    for (auto nm : managedWindows())
        if (winVisible_.find(nm) == winVisible_.end())
            winVisible_[nm] = (hiddenByDefault.count(nm) == 0);
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

    if (ImGui::MenuItem("Arrange Windows (reorganizar)")) dockNeedsInit_ = true;   // reconstruye el layout de docking

    // Ventana Contenedor NATIVA (segunda ventana del sistema, se puede llevar a otro monitor
    // sin parpadeo porque no usa el multi-viewport de ImGui).
    if (ImGui::MenuItem("Contenedor (ventana aparte para 2do monitor)", nullptr, containerOpen_))
        setContainerOpen(!containerOpen_);
    if (containerOpen_ && ImGui::BeginMenu("Enviar al Contenedor")) {
        ImGui::TextDisabled("Marca los paneles que quieres en la ventana Contenedor:");
        for (auto nm : managedWindows()) {
            bool inC = winContainer_[nm];
            if (ImGui::MenuItem(nm, nullptr, inC)) { winContainer_[nm] = !inC; containerDockInit_ = true; saveContainerState(); }
        }
        ImGui::EndMenu();
    }
    ImGui::MenuItem("Snap magnetico", nullptr, &magneticSnap_);
    if (ImGui::MenuItem("VSync", nullptr, &vsyncOn_)) {}

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
            if (ImGui::MenuItem("Exportar informe JSON...", nullptr, false, fileLoaded_)) {
                wchar_t path[MAX_PATH] = L"analisis.json";
                OPENFILENAMEW ofn{}; ofn.lStructSize = sizeof(ofn); ofn.lpstrFile = path; ofn.nMaxFile = MAX_PATH;
                ofn.lpstrFilter = L"JSON\0*.json\0Todos\0*.*\0"; ofn.Flags = OFN_OVERWRITEPROMPT;
                if (GetSaveFileNameW(&ofn)) { std::string err; if (!saveAnalysisReportJson(path, err)) pushLog("Informe JSON: " + err); else pushLog("Informe JSON exportado."); }
            }
            if (ImGui::MenuItem("Exportar SARIF...", nullptr, false, fileLoaded_)) {
                wchar_t path[MAX_PATH] = L"analisis.sarif";
                OPENFILENAMEW ofn{}; ofn.lStructSize = sizeof(ofn); ofn.lpstrFile = path; ofn.nMaxFile = MAX_PATH;
                ofn.lpstrFilter = L"SARIF\0*.sarif;*.json\0Todos\0*.*\0"; ofn.Flags = OFN_OVERWRITEPROMPT;
                if (GetSaveFileNameW(&ofn)) { std::string err; if (!saveSarifReport(path, err)) pushLog("SARIF: " + err); else pushLog("SARIF exportado."); }
            }
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
            bool paused = (dbgState_ == DbgState::Paused);
            if (ImGui::MenuItem("Saltar instruccion (skip)", nullptr, false, paused)) skipInstruction();
            if (ImGui::MenuItem("Deshacer paso (undo)", nullptr, false, paused && haveRegsBefore_)) undoInstruction();
            if (ImGui::MenuItem("Animar (step into)", nullptr, animateActive_, paused || animateActive_)) { animateMode_=0; animateActive_ = !animateActive_; }
            if (ImGui::MenuItem("Animar (step over)", nullptr, animateActive_ && animateMode_==1, paused || animateActive_)) { animateMode_=1; animateActive_ = !animateActive_; }
            ImGui::Separator();
            bool follow = debugger_.followChildren();
            if (ImGui::MenuItem("Seguir procesos hijos", nullptr, follow, dbgState_ == DbgState::Idle))
                debugger_.setFollowChildren(!follow);
            auto children = debugger_.childPids();
            if (ImGui::BeginMenu("Conmutar a proceso hijo", !children.empty())) {
                for (uint32_t cpid : children) {
                    char lbl[32]; std::snprintf(lbl, sizeof(lbl), "PID %u", cpid);
                    if (ImGui::MenuItem(lbl)) switchToChild(cpid);
                }
                ImGui::EndMenu();
            }
            ImGui::EndMenu();
        }
        if (ImGui::BeginMenu("Tools")) {
            if (ImGui::MenuItem("Options...")) {
                showOptions_ = true;
                optLoadDraft(aiConfig_.selected());
            }
            ImGui::Separator();
            if (ImGui::MenuItem("Reiniciar como administrador")) {
                wchar_t exe[MAX_PATH] = {0}; GetModuleFileNameW(nullptr, exe, MAX_PATH);
                SHELLEXECUTEINFOW sei{}; sei.cbSize = sizeof(sei); sei.lpVerb = L"runas";
                sei.lpFile = exe; sei.nShow = SW_SHOWNORMAL;
                if (ShellExecuteExW(&sei)) PostQuitMessage(0);
                else pushLog("No se pudo reiniciar como admin (cancelado?).");
            }
            ImGui::EndMenu();
        }
        if (ImGui::BeginMenu("Favourites")) {
            if (favourites_.empty()) ImGui::TextDisabled("(edita favourites.txt: nombre|comando)");
            for (const auto& f : favourites_) if (ImGui::MenuItem(f.name.c_str())) runFavourite(f);
            ImGui::Separator();
            if (ImGui::MenuItem("Recargar favourites")) loadFavourites();
            if (ImGui::MenuItem("Editar favourites.txt")) {
                std::string p = favFilePath();
                if (!std::ifstream(p).good()) { std::ofstream(p) << "# nombre|comando  (usa %DEBUGGEE% y %PID%)\n# Ejemplo: PEview|C:\\tools\\peview.exe %DEBUGGEE%\n"; }
                ShellExecuteA(nullptr, "open", p.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
            }
            ImGui::EndMenu();
        }
        if (ImGui::BeginMenu("Help")) {
            if (ImGui::MenuItem("Basic")) { helpPage_ = 0; showHelp_ = true; }
            if (ImGui::MenuItem("MCP")) { helpPage_ = 1; showHelp_ = true; }
            if (ImGui::MenuItem("Plugins")) { helpPage_ = 2; showHelp_ = true; }
            if (ImGui::MenuItem("Roadmap")) { helpPage_ = 3; showHelp_ = true; }
            ImGui::Separator();
            if (ImGui::MenuItem("About")) { helpPage_ = 4; showHelp_ = true; }
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
            ImGui::BulletText("Threads (Window -> Threads): lista los hilos del proceso (TID, hilo actual, prioridad, descripcion) y clic derecho para suspender/reanudar/terminar/prioridad. Por MCP: threads, thread_ctrl.");
            ImGui::BulletText("Notes (Window -> Notes): notas GLOBALES (siempre) y por BINARIO (guardadas por hash del contenido). Por MCP: notes_get, notes_set.");
            ImGui::BulletText("System (Window -> System): privilegios del token del proceso, conexiones TCP (IPv4) y conteo de handles. Por MCP: system_info.");
            ImGui::BulletText("Entropy (Window -> Entropy): entropia global y por seccion con barras (verde bajo, amarillo medio, rojo alto >7.2 = posible cifrado/empaquetado).");
            ImGui::BulletText("Operaciones de memoria (solo por MCP, requieren pausa): mem_alloc, mem_free, mem_fill, mem_copy, mem_save, page_protect.");
            ImGui::BulletText("CPU -> clic derecho -> 'Ejecutar hasta aqui' (run to cursor): continua hasta la linea, con un breakpoint temporal que se retira solo. Por MCP: run_to.");
            ImGui::BulletText("Run until expression (MCP run_until {expr, over, max}): single-step hasta que una expresion sea cierta (p.ej. 'eax == 0' o 'dword(esp) > 0x400000'). Requiere pausado.");
            ImGui::BulletText("Depurar -> Saltar/Deshacer/Animar (paridad x64dbg): Skip avanza RIP sin ejecutar; Undo restaura los registros del ultimo paso (no memoria); Animar da pasos periodicos. Por MCP: skip_instruction, undo_instruction, animate.");
            ImGui::BulletText("Strings y Busqueda: busca texto o hex con ?? como comodin. Packers muestra firmas y heuristicas.");
            ImGui::BulletText("Run trace registra ejecucion instruccion a instruccion; Call stack y Referencias ayudan a reconstruir el flujo. El boton 'Resumir con IA' envia una muestra de la traza al agente para que explique el flujo (bucles de descifrado, APIs tocadas).");
            ImGui::Separator();
            ImGui::TextColored(ImVec4(0.6f,0.85f,1,1), "Novedades (inspiradas en x64dbg)");
            ImGui::BulletText("Command (Window -> Command): barra de comandos hibrida. '?expr' evalua una expresion; 'cmd {args}' ejecuta una tool dbg_*; JSON crudo se envia tal cual. Marca 'Usar IA' para escribir en lenguaje natural y que el agente controle el debugger.");
            ImGui::BulletText("Watch (Window -> Watch): evalua expresiones en cada pausa. Ej: dword(esp+4), [eax], rip - mod.base(rip). Usa el motor de expresiones (hex por defecto; byte/word/dword/qword/ptr(a), registros, mod.base/size/fromname, dis.len, [mem], + - * / %% & | ^ ~ << >>). Marca 'Watchdog' para que avise en el Log cuando el valor cambie.");
            ImGui::BulletText("Variables globales (paridad x64dbg $vars): por MCP var_set/var_get/var_list. Usables en cualquier expresion (Watch, condiciones, eval).");
            ImGui::BulletText("Favourites (menu Favourites): herramientas externas configurables en favourites.txt (nombre|comando, con %%DEBUGGEE%% y %%PID%%). Tools -> Reiniciar como administrador relanza elevado.");
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
            ImGui::Separator();
            ImGui::TextColored(ImVec4(0.6f,0.85f,1,1), "Ventanas: docking, X para cerrar y Contenedor");
            ImGui::BulletText("Cada ventana tiene una X en su barra de titulo para cerrarla (se reactiva en Window -> Show).");
            ImGui::BulletText("Docking: arrastra la barra de titulo de una ventana sobre otra o sobre los bordes para anclarla; las ventanas se agrupan en pestanas y paneles divididos dentro del main.");
            ImGui::BulletText("Ventana Contenedor (Window -> Contenedor): es una VENTANA DEL SISTEMA aparte (con minimizar/maximizar/cerrar propios) que puedes mover a OTRO MONITOR sin parpadeo (no usa el multi-viewport de ImGui, tiene su propio render).");
            ImGui::BulletText("Enviar paneles al Contenedor: con el Contenedor abierto, Window -> 'Enviar al Contenedor' y marca los paneles que quieres alli; dentro del Contenedor se anclan/organizan con docking igual que en el main. Se recuerda entre sesiones.");
            ImGui::BulletText("VSync (Window -> VSync): normalmente dejalo activado; solo afecta al suavizado del refresco.");
            ImGui::Separator();
            ImGui::TextColored(ImVec4(0.6f,0.85f,1,1), "Skills de IA (panel IA -> menu Skills)");
            ImGui::BulletText("Skill browser: marca skills (recetas de texto) para aplicarlos al agente de IA actual; sus instrucciones se anaden al prompt del sistema.");
            ImGui::BulletText("Manage Skills: crea (genera una plantilla .md), edita o elimina skills. Se guardan en la carpeta 'skills'. Fase 1 local; el repositorio de comunidad llegara despues.");
            ImGui::BulletText("Window -> Custom -> Add to custom: guarda el layout COMPLETO con nombre: posiciones/tamanos/docking del main Y del Contenedor, que paneles estan en cada uno, si el Contenedor estaba abierto y la posicion/tamano de su ventana. Elige el nombre en Custom para restaurarlo todo (main + Contenedor).");
            ImGui::BulletText("CFG (Window -> CFG): grafo de las funciones analizadas (Analyze this) y sus xrefs; doble clic en un nodo navega a la funcion.");
            ImGui::BulletText("Compare (Window -> Compare): compara dos archivos/dumps byte a byte y lista los rangos que difieren. Tambien por MCP: diff_files.");
            ImGui::BulletText("Struct -> Inferir con IA: pide a la IA una struct probable a partir de los bytes en la direccion base. Tambien por MCP: infer_struct.");
            ImGui::BulletText("Command bar: acepta 'cmd key=val, key=val' (args por pares) y varios comandos separados por ';', ademas de '?expr' y JSON.");
            ImGui::BulletText("Archivo -> Exportar informe JSON: informe estructurado (secciones, packers, breakpoints, funciones, peHash). Por MCP: report format=json / export_report .json.");
            ImGui::BulletText("Streaming de eventos: los clientes MCP sondean poll_events(since) para recibir load_dll/unload_dll/exit_process/breakpoint/hijos en vivo. Los plugins con una accion 'on_event' se invocan por cada evento.");
            ImGui::BulletText("DB de analisis portable (M6): la cache se guarda tambien por hash del contenido (cache/<hash>.dbj); si mueves o renombras el binario, las anotaciones/funciones se recuperan igual.");
            ImGui::BulletText("CFG (Window -> CFG): elige una funcion analizada y muestra sus bloques basicos con aristas (verde=condicional, naranja=incondicional/fallthrough). Clic derecho arrastra, rueda hace zoom.");
            ImGui::BulletText("Script (Window -> Script): mini-lenguaje que automatiza el debugger. Lineas: $v=expr | print expr | log txt | label: | goto label | if expr goto label | cmd key=val. Por MCP: run_script.");
            ImGui::BulletText("Informes: Archivo -> Exportar SARIF genera SARIF 2.1.0 con las detecciones (packer, entropia, W+X, TLS, pocos imports). Por MCP: report format=sarif.");
            ImGui::BulletText("Unpacking: al hacer Dump se ejecuta una validacion automatica (entrypoint en seccion ejecutable, entropia de codigo, IAT, solapamiento de secciones, sizeOfImage, TLS). Plugins -> 'Validar dump'/'Validar otro' o MCP validate_dump para revisar cualquier .exe volcado.");
            ImGui::BulletText("Seguir procesos hijos: activa Depurar -> Seguir procesos hijos antes de lanzar. Los hijos se detectan y listan. Depurar -> Conmutar a proceso hijo (o MCP switch_to_child) desadjunta el actual y adjunta el hijo en un paso. El seguimiento SIMULTANEO de varios procesos a la vez aun no esta (se depura uno a la vez por conmutacion).");
            ImGui::Separator();
            ImGui::TextColored(ImVec4(0.6f,0.85f,1,1), "Navegacion del CPU (estilo OllyDbg)");
            ImGui::BulletText("Clic en una linea SELECCIONA (ya no pone breakpoint). El BP se pone/quita con F2 sobre la seleccion o desde el menu contextual -> Breakpoints.");
            ImGui::BulletText("Flechas arriba/abajo y RePag/AvPag mueven la seleccion; Shift+flecha o Shift+clic selecciona varias lineas.");
            ImGui::BulletText("Enter (o doble clic) sobre un call/jmp sigue el salto y te lleva al destino o al inicio del procedimiento.");
            ImGui::BulletText("Al seleccionar un call/jmp, el panel Referencias muestra automaticamente todas las direcciones que saltan/llaman a ese destino; doble clic o clic derecho -> Go to.");
            ImGui::BulletText("Menu contextual -> 'Goto RVA / VA...': pide una direccion (VA con 0x, o RVA sin prefijo) y navega alli.");
            ImGui::BulletText("Menu contextual -> 'Analyze / AI as C++': manda las lineas seleccionadas a la IA y muestra el pseudocodigo C++ en la ventana Code.");
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
            ImGui::BulletText("Si el puerto elegido esta ocupado (p.ej. un socket huerfano), el servidor prueba automaticamente los 10 siguientes; el estado indica que puerto quedo en uso. Flag --access=N fija el nivel (0/1/2) por CLI.");
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
            ImGui::BulletText("HECHO: motor de expresiones (eval/watch/struct), command bar hibrida + comandos de texto, Watch, Struct viewer + inferencia IA, Search for, symbol server, resumen de traza con IA, ai.classify, breakpoints con accion (M3), hot-reload plugins (M11), headless (M10), MCP bypass, bus de eventos + streaming poll_events (Fase 3), DB de analisis portable por hash (M6), informe JSON, comparacion de dumps (diff_files), CFG basico.");
            ImGui::BulletText("PARCIAL: seguir procesos hijos (M7): se detectan/reportan/listan (list_children) pero falta following completo (adoptar el hijo como target activo con su propio contexto). Capa de comandos: falta parser de texto avanzado (solo key=val).");
            ImGui::BulletText("HECHO (proyectos grandes): lenguaje de scripting (Script/run_script); SARIF 2.1.0; CFG interactivo con bloques basicos (pan/zoom); validacion de dumps (validate_dump).");
            ImGui::BulletText("PARCIAL: seguir procesos hijos (deteccion+listado+conmutacion manual, falta simultaneo); unpacking/IAT (dump+validacion+fix experimental, falta reconstruccion PE 100%% robusta).");
            ImGui::BulletText("FUERA DE ALCANCE por ahora: decompilador nativo real (el panel Code da interpretacion por IA, no genera pseudo-C fiel). Es un proyecto en si mismo.");
            ImGui::EndTabItem();
        }
        if (ImGui::BeginTabItem("About", nullptr, helpPage_ == 4 ? ImGuiTabItemFlags_SetSelected : 0)) {
            ImGui::PushFont(nullptr);
            ImGui::TextColored(ImVec4(0.6f,0.85f,1,1), "DebuggerJ++");
            ImGui::PopFont();
            ImGui::Text("Version %s", kAppVersion);
            ImGui::Separator();
            ImGui::TextWrapped("Debugger y desensamblador para Windows (x86/x64) orientado al analisis "
                "de malware con fines defensivos. Interfaz estilo OllyDbg/x64dbg con Dear ImGui, "
                "desensamblado con Zydis, ensamblador Keystone y motor de depuracion sobre la Windows "
                "Debug API. Integra un asistente de IA (multi-proveedor) y un servidor MCP para "
                "automatizar el analisis. Incluye breakpoints (software/hardware/memoria/excepcion), "
                "unpacking asistido, motor de expresiones, scripting, CFG, informes SARIF/JSON y mas.");
            ImGui::Separator();
            ImGui::TextColored(ImVec4(0.7f,1,0.7f,1), "Autor");
            ImGui::BulletText("Ing. Jaime Macias");
            ImGui::TextColored(ImVec4(0.7f,1,0.7f,1), "Co-autor");
            ImGui::BulletText("Claude (Anthropic) - asistente de IA");
            ImGui::Separator();
            ImGui::TextColored(ImVec4(1,0.9f,0.4f,1), "Licencia");
            ImGui::TextWrapped("Publicado bajo la GNU General Public License v3.0 (GPLv3). "
                "Puedes usar, estudiar, modificar y redistribuir el programa; las obras derivadas "
                "deben distribuirse tambien bajo GPLv3 y con el codigo fuente disponible. El software "
                "se ofrece SIN GARANTIA. Consulta el archivo LICENSE para el texto completo.");
            ImGui::Separator();
            ImGui::TextDisabled("Repositorio: github.com/jaime64net/DebuggerJ-");
            ImGui::TextDisabled("Analiza muestras de malware solo en una VM aislada.");
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
    { bool was = winVisible_["CPU"]; ImGui::Begin(title.c_str(), &winVisible_["CPU"]);
      if (was && !winVisible_["CPU"]) saveVisibility(); }
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

                // Col BP: muestra el breakpoint. El click en la FILA solo selecciona;
                // el doble-click sigue el salto/call (como OllyDbg). El BP se pone/quita
                // con F2 sobre la seleccion o desde el menu contextual, NO al hacer click.
                ImGui::TableSetColumnIndex(0);
                bool bp = hasBp(in.address);
                ImGui::PushID(i);
                if (bp) ImGui::TextColored(ImVec4(1,0.35f,0.35f,1), "*"); else ImGui::TextUnformatted(" ");
                // Resaltado de la seleccion (rango [anchor..sel] para seleccion multiple).
                int selLo = selAnchor_ >= 0 ? std::min(selAnchor_, selectedInsn_) : selectedInsn_;
                int selHi = selAnchor_ >= 0 ? std::max(selAnchor_, selectedInsn_) : selectedInsn_;
                bool inSel = (i >= selLo && i <= selHi && selectedInsn_ >= 0);
                // Selectable transparente que cubre toda la fila (seleccion + doble clic).
                ImGui::SameLine(0,0);
                if (ImGui::Selectable("##sel", inSel,
                        ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowDoubleClick)) {
                    if (ImGui::GetIO().KeyShift && selAnchor_ >= 0) selectedInsn_ = i;   // extiende rango
                    else { selectedInsn_ = i; selAnchor_ = i; }                          // nueva seleccion
                    if (ImGui::IsMouseDoubleClicked(0) && in.hasBranchTarget) gotoAddress(in.branchTarget);
                }
                // Menu contextual (clic derecho sobre el renglon)
                if (ImGui::BeginPopupContextItem("cpuctx")) {
                    // Si el click derecho cae fuera de la seleccion multiple, resetea a esta fila;
                    // si cae dentro del rango, conserva la seleccion (para "AI as C++").
                    {
                        int lo = selAnchor_ >= 0 ? std::min(selAnchor_, selectedInsn_) : selectedInsn_;
                        int hi = selAnchor_ >= 0 ? std::max(selAnchor_, selectedInsn_) : selectedInsn_;
                        if (!(i >= lo && i <= hi)) { selectedInsn_ = i; selAnchor_ = i; }
                    }
                    int selCount = (selAnchor_ >= 0 ? std::abs(selectedInsn_ - selAnchor_) + 1 : 1);
                    if (selCount > 1) ImGui::TextDisabled("%d lineas seleccionadas", selCount);
                    else ImGui::TextDisabled("0x%s", vaStr(in.address, dbgState_==DbgState::Paused?debugger_.is64():pe_.is64Bit()).c_str());
                    ImGui::Separator();
                    if (ImGui::MenuItem("Analyze / AI as C++")) analyzeSelectionAsCpp();
                    if (ImGui::MenuItem("Goto RVA / VA...")) { gotoRvaBuf_[0] = '\0'; openGotoRva_ = true; }
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
                    if (ImGui::MenuItem("Ejecutar hasta aqui", nullptr, false, dbgState_==DbgState::Paused)) runToAddress(in.address);
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

    // Navegacion con teclado (estilo OllyDbg) cuando el panel CPU tiene foco.
    if (ImGui::IsWindowFocused(ImGuiFocusedFlags_RootAndChildWindows) && !insns_.empty()) {
        bool shift = ImGui::GetIO().KeyShift;
        int prev = selectedInsn_;
        if (ImGui::IsKeyPressed(ImGuiKey_DownArrow)) selectedInsn_ = selectedInsn_ < 0 ? 0 : std::min((int)insns_.size()-1, selectedInsn_+1);
        else if (ImGui::IsKeyPressed(ImGuiKey_UpArrow)) selectedInsn_ = selectedInsn_ <= 0 ? 0 : selectedInsn_-1;
        else if (ImGui::IsKeyPressed(ImGuiKey_PageDown)) selectedInsn_ = selectedInsn_ < 0 ? 0 : std::min((int)insns_.size()-1, selectedInsn_+20);
        else if (ImGui::IsKeyPressed(ImGuiKey_PageUp)) selectedInsn_ = selectedInsn_ <= 0 ? 0 : std::max(0, selectedInsn_-20);
        if (selectedInsn_ != prev) {
            if (!shift) selAnchor_ = selectedInsn_;      // sin shift, mueve el ancla; con shift, extiende
            pendingScroll_ = selectedInsn_;              // mantener la seleccion visible
        }
        // Enter: seguir el salto/call de la instruccion seleccionada (como OllyDbg).
        if (selectedInsn_ >= 0 && selectedInsn_ < (int)insns_.size() &&
            (ImGui::IsKeyPressed(ImGuiKey_Enter) || ImGui::IsKeyPressed(ImGuiKey_KeypadEnter))) {
            const auto& s = insns_[selectedInsn_];
            if (s.hasBranchTarget) gotoAddress(s.branchTarget);
        }
        // F2: poner/quitar breakpoint en la linea seleccionada (el click NO lo hace).
        if (selectedInsn_ >= 0 && selectedInsn_ < (int)insns_.size() && ImGui::IsKeyPressed(ImGuiKey_F2)) {
            uint64_t a = insns_[selectedInsn_].address;
            bool has = false; for (auto& b : debugger_.breakpoints()) if (b.address == a) has = true;
            if (has) debugger_.removeBreakpoint(a); else debugger_.addBreakpoint(a, "cpu");
        }
    }
    if (selectedInsn_ >= 0 && selectedInsn_ < (int)insns_.size() && ImGui::GetIO().KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_A))
        analyzeCodeAt(insns_[selectedInsn_].address);

    // Xrefs automaticos: al seleccionar un call/jmp, buscar quien salta/llama a su destino
    // (solo al cambiar de seleccion, para no rescanear cada frame).
    if (selectedInsn_ >= 0 && selectedInsn_ < (int)insns_.size() && selectedInsn_ != lastXrefSel_) {
        lastXrefSel_ = selectedInsn_;
        const auto& s = insns_[selectedInsn_];
        if ((s.isCall || s.isJump) && s.hasBranchTarget) findReferences(s.branchTarget);
    }

    // Popup "Goto RVA / VA": navega a una direccion (RVA relativa a imageBase, o VA con 0x).
    if (openGotoRva_) { ImGui::OpenPopup("gotorva"); openGotoRva_ = false; }
    if (ImGui::BeginPopup("gotorva")) {
        ImGui::TextUnformatted("Ir a direccion (VA con 0x, o RVA sin prefijo):");
        ImGui::SetNextItemWidth(240);
        bool ok = ImGui::InputTextWithHint("##grva", "ej: 0x401000  o  1000", gotoRvaBuf_, sizeof(gotoRvaBuf_),
                     ImGuiInputTextFlags_EnterReturnsTrue | ImGuiInputTextFlags_CharsHexadecimal | ImGuiInputTextFlags_AutoSelectAll);
        if ((ImGui::Button("Ir") || ok) && gotoRvaBuf_[0]) {
            std::string t = gotoRvaBuf_;
            uint64_t v = strtoull(t.c_str(), nullptr, 16);
            uint64_t va = (t.rfind("0x", 0) == 0 || v >= pe_.imageBase()) ? v : pe_.imageBase() + v;  // RVA -> VA
            gotoAddress(va);
            ImGui::CloseCurrentPopup();
        }
        ImGui::SameLine();
        if (ImGui::Button("Cancelar##grva")) ImGui::CloseCurrentPopup();
        ImGui::EndPopup();
    }

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
    beginManaged("Breakpoints");
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
    beginManaged("Memoria");
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
    beginManaged("Strings & Busqueda");

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
    beginManaged("Modulos & Simbolos");
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
    beginManaged("Packers / Proteccion");
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
    beginManaged("Excepciones");
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
    beginManaged("Plugins");
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
            if (dumpProcess(debugger_, pe_, oep, out, lg)) {
                lastDumpPath_ = out;
                std::string rep; validateDump(out, rep);   // auto-validacion tras el dump
                lg += "\n--- Validacion automatica ---\n" + rep;
            }
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
        ImGui::BeginDisabled(lastDumpPath_.empty());
        if (ImGui::Button("Validar dump")) {
            std::string rep; validateDump(lastDumpPath_, rep);
            pluginStatus_ = rep; pushLog("Validacion de dump:\n" + rep);
        }
        ImGui::EndDisabled();
        ImGui::SameLine();
        if (ImGui::SmallButton("Validar otro...")) {
            wchar_t f[MAX_PATH]={0}; OPENFILENAMEW o{}; o.lStructSize=sizeof(o); o.lpstrFile=f; o.nMaxFile=MAX_PATH;
            o.lpstrFilter=L"Ejecutables\0*.exe;*.dll\0Todos\0*.*\0";
            if (GetOpenFileNameW(&o)) { std::string rep; validateDump(f, rep); pluginStatus_ = rep; pushLog("Validacion de dump:\n" + rep); }
        }
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
        cache["peHash"] = peContentHash();   // M6: identidad por contenido (portable)

        const std::string dump = cache.dump(1);
        std::ofstream file(path, std::ios::binary | std::ios::trunc);
        if (file) file << dump;
        // M6: copia portable indexada por hash del contenido (sigue al binario si se mueve).
        std::string h = peContentHash();
        if (!h.empty()) {
            std::wstring dbPath = std::wstring(exeSiblingDir().begin(), exeSiblingDir().end()) + L"\\cache\\" +
                                  std::wstring(h.begin(), h.end()) + L".dbj";
            std::ofstream db(dbPath, std::ios::binary | std::ios::trunc);
            if (db) db << dump;
        }
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

    // Aplica el contenido de un JSON de cache al estado. Devuelve true si se aplicó.
    auto applyCache = [this](const njson& cache) {
        strings_.clear(); packerMatches_.clear(); labels_.clear(); comments_.clear();
        bookmarks_.clear(); analyzedFunctions_.clear(); analysisXrefs_.clear(); analysisLoops_.clear();
        for (const auto& item : cache.value("strings", njson::array())) {
            FoundString s; s.address = item.value("address", uint64_t{0});
            s.kind = item.value("kind", "ascii") == "utf16" ? StrKind::Utf16 : StrKind::Ascii;
            s.text = item.value("text", ""); strings_.push_back(std::move(s));
        }
        for (const auto& item : cache.value("packers", njson::array())) {
            PackerMatch p; p.name = item.value("name", ""); p.source = item.value("source", "");
            p.confidence = item.value("confidence", 0); packerMatches_.push_back(std::move(p));
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
    };

    try {
        std::ifstream file(path, std::ios::binary);
        bool matched = false;
        if (file) {
            const njson cache = njson::parse(file);
            if (cache.value("schemaVersion", 0) == 1 &&
                cache.value("sourceSize", uint64_t{0}) == sourceSize &&
                cache.value("sourceWriteTime", uint64_t{0}) == sourceWriteTime &&
                cache.value("minStringLength", size_t{0}) == minStrLen_) {
                applyCache(cache);
                pushLog("Cache de analisis cargada (por ruta).");
                return true;
            }
        }
        // M6: fallback portable por hash de contenido (binario movido/renombrado).
        if (!matched) {
            std::string h = peContentHash();
            if (!h.empty()) {
                std::wstring dbPath = std::wstring(exeSiblingDir().begin(), exeSiblingDir().end()) + L"\\cache\\" +
                                      std::wstring(h.begin(), h.end()) + L".dbj";
                std::ifstream db(dbPath, std::ios::binary);
                if (db) {
                    const njson cache = njson::parse(db);
                    if (cache.value("peHash", std::string{}) == h) {
                        applyCache(cache);
                        pushLog("Cache de analisis cargada (DB portable por hash " + h + ").");
                        return true;
                    }
                }
            }
        }
        return false;
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
    beginManaged("Run trace");
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
    beginManaged("Referencias");
    if (refTarget_) ImGui::Text("Saltan/llaman a 0x%s  (%zu)", hex64(refTarget_).c_str(), refs_.size());
    else ImGui::TextDisabled("Selecciona un call/jmp en el CPU: aqui aparecen quienes saltan alli.");
    ImGui::TextDisabled("Doble clic o clic derecho -> Go to.");
    ImGui::Separator();
    ImGui::BeginChild("refslist", ImVec2(0, 0), false);
    for (auto a : refs_) {
        ImGui::PushID((int)(a ^ (a >> 32)));
        std::string sym = (dbgState_ == DbgState::Paused) ? debugger_.symbolAt(a) : "";
        std::string label = "0x" + hex64(a) + (sym.empty() ? "" : ("  " + sym));
        if (ImGui::Selectable(label.c_str(), false, ImGuiSelectableFlags_AllowDoubleClick) && ImGui::IsMouseDoubleClicked(0))
            gotoAddress(a);
        if (ImGui::BeginPopupContextItem("refctx")) {
            if (ImGui::MenuItem("Go to")) gotoAddress(a);
            if (ImGui::MenuItem("Copiar direccion")) ImGui::SetClipboardText(("0x" + hex64(a)).c_str());
            ImGui::EndPopup();
        }
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
        // Variable global del usuario (funciona con o sin sesion).
        { auto gv = globalVars_.find(n); if (gv != globalVars_.end()) { out = gv->second; return true; } }
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
    // Varios comandos separados por ';' (fuera de llaves).
    std::vector<std::string> parts;
    {
        std::string cur; int depth = 0;
        for (char c : line) {
            if (c == '{') depth++;
            if (c == '}') depth--;
            if (c == ';' && depth == 0) { parts.push_back(cur); cur.clear(); }
            else cur.push_back(c);
        }
        if (!cur.empty()) parts.push_back(cur);
    }
    std::string out;
    for (std::string seg : parts) {
        while (!seg.empty() && std::isspace((unsigned char)seg.front())) seg.erase(seg.begin());
        while (!seg.empty() && std::isspace((unsigned char)seg.back())) seg.pop_back();
        if (seg.empty()) continue;
        if (seg[0] == '?') {                 // evaluar expresion, estilo x64dbg
            uint64_t v = 0; std::string err;
            out += evalExpr(seg.substr(1), v, err) ? ("= 0x" + hex64(v) + "  (" + std::to_string(v) + ")\n")
                                                   : ("error: " + err + "\n");
        } else if (seg[0] == '{') {          // comando MCP crudo
            out += execDbgCommand(seg) + "\n";
        } else {                             // "cmd {json}"  o  "cmd key=val, key=val"
            std::string cmd = seg, rest;
            auto sp = seg.find(' ');
            if (sp != std::string::npos) { cmd = seg.substr(0, sp); rest = seg.substr(sp + 1); }
            njson args = njson::object();
            if (!rest.empty()) {
                std::string t = rest; while (!t.empty() && std::isspace((unsigned char)t.front())) t.erase(t.begin());
                if (!t.empty() && t[0] == '{') { try { args = njson::parse(t); } catch (...) {} }
                else {   // key=val, key=val  -> objeto JSON (numeros hex, strings, bool)
                    std::string kv; std::vector<std::string> pairs;
                    for (char c : rest) { if (c == ',') { pairs.push_back(kv); kv.clear(); } else kv.push_back(c); }
                    if (!kv.empty()) pairs.push_back(kv);
                    for (auto& pr : pairs) {
                        auto eq = pr.find('=');
                        if (eq == std::string::npos) continue;
                        std::string k = pr.substr(0, eq), val = pr.substr(eq + 1);
                        auto trim=[&](std::string& s){ while(!s.empty()&&std::isspace((unsigned char)s.front()))s.erase(s.begin()); while(!s.empty()&&std::isspace((unsigned char)s.back()))s.pop_back(); };
                        trim(k); trim(val);
                        if (val == "true") args[k] = true;
                        else if (val == "false") args[k] = false;
                        else if (!val.empty() && (isxdigit((unsigned char)val[0]) || val.rfind("0x",0)==0)) {
                            uint64_t n = strtoull(val.c_str(), nullptr, 16); args[k] = n;
                        } else args[k] = val;
                    }
                }
            }
            njson req; req["cmd"] = cmd; req["args"] = args;
            out += execDbgCommand(req.dump()) + "\n";
        }
    }
    cmdBarResult_ = out;
    cmdBar_[0] = '\0';
}

void App::drawCommandBar() {
    beginManaged("Command");
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
// Motor de scripting: mini-lenguaje sobre la capa de comandos + expresiones.
// Lineas soportadas (una por linea; // = comentario):
//   $var = <expr>            asigna una variable (hex por defecto)
//   print <expr>             evalua e imprime
//   log <texto>              imprime texto (con $var sustituidas)
//   <label>:                 define una etiqueta
//   goto <label>             salta
//   if <expr> goto <label>   salta si expr != 0
//   <cmd> key=val, ...       ejecuta una tool dbg_* (o JSON crudo con {})
// ---------------------------------------------------------------------------
std::string App::runScript(const std::string& src, std::string& err) {
    std::vector<std::string> lines;
    { std::string cur; for (char c : src) { if (c == '\n') { lines.push_back(cur); cur.clear(); } else if (c != '\r') cur.push_back(c); } lines.push_back(cur); }

    std::map<std::string, uint64_t> vars;
    std::map<std::string, int> labels;
    for (int i = 0; i < (int)lines.size(); ++i) {
        std::string t = lines[i];
        auto a = t.find_first_not_of(" \t"); if (a == std::string::npos) continue;
        t = t.substr(a);
        if (!t.empty() && t.back() == ':' && t.find(' ') == std::string::npos) labels[t.substr(0, t.size()-1)] = i;
    }

    auto substVars = [&](std::string s) {
        for (auto& [k, v] : vars) {
            std::string needle = "$" + k, rep = "0x" + hex64(v);
            size_t p; while ((p = s.find(needle)) != std::string::npos) s.replace(p, needle.size(), rep);
        }
        return s;
    };

    std::string out;
    int steps = 0;
    for (int ip = 0; ip < (int)lines.size(); ++ip) {
        if (++steps > 100000) { err = "limite de pasos (posible bucle infinito)"; break; }
        std::string t = lines[ip];
        auto a = t.find_first_not_of(" \t"); if (a == std::string::npos) continue;
        t = t.substr(a);
        while (!t.empty() && (t.back() == ' ' || t.back() == '\t')) t.pop_back();
        if (t.empty() || t.rfind("//", 0) == 0) continue;
        if (t.back() == ':' && t.find(' ') == std::string::npos) continue;   // label

        // asignacion $var = expr
        if (t[0] == '$') {
            auto eq = t.find('=');
            if (eq != std::string::npos) {
                std::string name = t.substr(1, eq-1);
                while (!name.empty() && (name.back()==' '||name.back()=='\t')) name.pop_back();
                uint64_t v = 0; std::string e;
                if (!evalExpr(substVars(t.substr(eq+1)), v, e)) { err = "linea " + std::to_string(ip+1) + ": " + e; break; }
                vars[name] = v; continue;
            }
        }
        std::string kw = t.substr(0, t.find(' '));
        std::string rest = (t.size() > kw.size()) ? t.substr(kw.size()+1) : "";
        if (kw == "print") {
            uint64_t v = 0; std::string e;
            if (!evalExpr(substVars(rest), v, e)) { err = "linea " + std::to_string(ip+1) + ": " + e; break; }
            out += "0x" + hex64(v) + "  (" + std::to_string(v) + ")\n";
        } else if (kw == "log") {
            out += substVars(rest) + "\n";
        } else if (kw == "goto") {
            auto it = labels.find(rest); if (it == labels.end()) { err = "label desconocido: " + rest; break; }
            ip = it->second; continue;
        } else if (kw == "if") {
            auto g = rest.find(" goto ");
            if (g == std::string::npos) { err = "if sin goto (linea " + std::to_string(ip+1) + ")"; break; }
            std::string cond = rest.substr(0, g), lbl = rest.substr(g+6);
            uint64_t v = 0; std::string e;
            if (!evalExpr(substVars(cond), v, e)) { err = "linea " + std::to_string(ip+1) + ": " + e; break; }
            if (v) { auto it = labels.find(lbl); if (it == labels.end()) { err = "label desconocido: " + lbl; break; } ip = it->second; }
            continue;
        } else {
            // comando dbg_*: reusa el parseo key=val / JSON del command bar.
            std::string cmd = kw, args = substVars(rest);
            njson jargs = njson::object();
            std::string tr = args; while (!tr.empty() && tr.front()==' ') tr.erase(tr.begin());
            if (!tr.empty() && tr[0]=='{') { try { jargs = njson::parse(tr); } catch (...) {} }
            else if (!tr.empty()) {
                std::string kv; std::vector<std::string> pairs;
                for (char c : args) { if (c==',') { pairs.push_back(kv); kv.clear(); } else kv.push_back(c); }
                if (!kv.empty()) pairs.push_back(kv);
                for (auto& pr : pairs) { auto eq=pr.find('='); if (eq==std::string::npos) continue;
                    std::string k=pr.substr(0,eq), val=pr.substr(eq+1);
                    auto trim=[&](std::string&s){while(!s.empty()&&s.front()==' ')s.erase(s.begin());while(!s.empty()&&s.back()==' ')s.pop_back();};
                    trim(k); trim(val);
                    if (val=="true") jargs[k]=true; else if (val=="false") jargs[k]=false;
                    else if (!val.empty() && (isxdigit((unsigned char)val[0])||val.rfind("0x",0)==0)) jargs[k]=(uint64_t)strtoull(val.c_str(),nullptr,16);
                    else jargs[k]=val;
                }
            }
            njson req; req["cmd"]=cmd; req["args"]=jargs;
            std::string r = execDbgCommand(req.dump());
            out += kw + ": " + (r.size()>200 ? r.substr(0,200)+"..." : r) + "\n";
        }
    }
    return out;
}

void App::drawScriptPanel() {
    beginManaged("Script");
    ImGui::TextDisabled("$v=expr | print expr | log txt | label: | goto label | if expr goto label | cmd key=val");
    ImGui::InputTextMultiline("##script", scriptBuf_, sizeof(scriptBuf_), ImVec2(-1, ImGui::GetContentRegionAvail().y - 130));
    if (ImGui::Button("Ejecutar")) { std::string err; scriptOutput_ = runScript(scriptBuf_, err); if (!err.empty()) scriptOutput_ += "\n[error] " + err; }
    ImGui::SameLine();
    if (ImGui::Button("Limpiar salida")) scriptOutput_.clear();
    ImGui::Separator();
    ImGui::InputTextMultiline("##scriptout", scriptOutput_.data(), scriptOutput_.size()+1, ImVec2(-1, -1), ImGuiInputTextFlags_ReadOnly);
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
        // Watchdog: alerta cuando el valor cambia respecto al anterior.
        if (w.ok && w.watchdog) {
            if (w.haveLast && v != w.last)
                pushLog("[watchdog] '" + w.expr + "' cambio: 0x" + hex64(w.last) + " -> 0x" + hex64(v));
            w.last = v; w.haveLast = true;
        }
    }
}

void App::drawWatchPanel() {
    beginManaged("Watch");
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
    if (ImGui::BeginTable("watches", 4, ImGuiTableFlags_Resizable | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY)) {
        ImGui::TableSetupColumn("Expresion");
        ImGui::TableSetupColumn("Valor", ImGuiTableColumnFlags_WidthFixed, 170);
        ImGui::TableSetupColumn("Watchdog", ImGuiTableColumnFlags_WidthFixed, 70);
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
            ImGui::Checkbox("##wd", &watches_[i].watchdog);
            ImGui::TableSetColumnIndex(3);
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

// Divide una función en bloques básicos sobre insns_ (líderes = entry, targets de
// saltos dentro del rango, y la instrucción posterior a un salto/ret).
std::vector<App::BasicBlock> App::computeBasicBlocks(uint64_t funcStart, uint64_t funcEnd) {
    std::vector<BasicBlock> blocks;
    // índice de insns dentro del rango
    std::vector<int> idx;
    std::map<uint64_t,int> addrToIdx;
    for (int i = 0; i < (int)insns_.size(); ++i)
        if (insns_[i].address >= funcStart && insns_[i].address <= funcEnd) { addrToIdx[insns_[i].address] = (int)idx.size(); idx.push_back(i); }
    if (idx.empty()) return blocks;

    std::set<uint64_t> leaders;
    leaders.insert(insns_[idx.front()].address);
    for (size_t k = 0; k < idx.size(); ++k) {
        const auto& in = insns_[idx[k]];
        bool isUncond = in.isJump && in.text.rfind("jmp", 0) == 0;
        if (in.isJump || in.isRet) {
            if (in.hasBranchTarget && in.branchTarget >= funcStart && in.branchTarget <= funcEnd) leaders.insert(in.branchTarget);
            if (k + 1 < idx.size()) leaders.insert(insns_[idx[k+1]].address);   // fallthrough leader
        }
        (void)isUncond;
    }
    // construir bloques
    BasicBlock cur; bool open = false;
    auto closeBlock = [&](int lastIdx) {
        const auto& last = insns_[lastIdx];
        cur.end = last.address;
        bool isUncond = last.isJump && last.text.rfind("jmp", 0) == 0;
        if (last.hasBranchTarget && last.branchTarget >= funcStart && last.branchTarget <= funcEnd) cur.succ.push_back(last.branchTarget);
        if (!last.isRet && !isUncond) {
            // fallthrough al siguiente líder
            auto it = addrToIdx.find(last.address);
            if (it != addrToIdx.end() && it->second + 1 < (int)idx.size()) cur.succ.push_back(insns_[idx[it->second+1]].address);
        }
        blocks.push_back(cur); cur = BasicBlock(); open = false;
    };
    for (size_t k = 0; k < idx.size(); ++k) {
        const auto& in = insns_[idx[k]];
        if (!open || leaders.count(in.address)) { if (open) closeBlock(idx[k-1]); cur = BasicBlock(); cur.start = in.address; open = true; }
        cur.insnIdx.push_back(idx[k]);
        bool ends = in.isJump || in.isRet || (k+1 < idx.size() && leaders.count(insns_[idx[k+1]].address));
        if (ends) closeBlock(idx[k]);
    }
    if (open) closeBlock(idx.back());
    return blocks;
}

// ---------------------------------------------------------------------------
// CFG interactivo: bloques básicos de una función, con pan (arrastrar) y zoom.
// ---------------------------------------------------------------------------
void App::drawCfgPanel() {
    beginManaged("CFG");
    if (analyzedFunctions_.empty()) {
        ImGui::TextDisabled("No hay funciones analizadas. Clic derecho -> Analyze en el CPU.");
        ImGui::End(); return;
    }
    // selector de función
    std::string curName = cfgFunc_ ? ("0x" + hex64(cfgFunc_)) : "(elige función)";
    ImGui::SetNextItemWidth(220);
    if (ImGui::BeginCombo("Función", curName.c_str())) {
        for (const auto& f : analyzedFunctions_) {
            std::string nm = (f.name.empty() ? ("sub_" + hex64(f.start)) : f.name);
            if (ImGui::Selectable(nm.c_str(), f.start == cfgFunc_)) cfgFunc_ = f.start;
        }
        ImGui::EndCombo();
    }
    ImGui::SameLine(); ImGui::Text("zoom %.0f%%", cfgZoom_ * 100);
    ImGui::SameLine(); if (ImGui::SmallButton("Reset")) { cfgZoom_ = 1.0f; cfgPanX_ = cfgPanY_ = 0; }
    if (!cfgFunc_) { ImGui::TextDisabled("Elige una función."); ImGui::End(); return; }

    uint64_t fend = 0;
    for (const auto& f : analyzedFunctions_) if (f.start == cfgFunc_) fend = f.end;
    auto blocks = computeBasicBlocks(cfgFunc_, fend);

    ImGui::BeginChild("cfgcanvas", ImVec2(0, 0), true, ImGuiWindowFlags_NoMove);
    // pan con arrastre del boton medio o izquierdo sobre vacio
    if (ImGui::IsWindowHovered()) {
        if (ImGui::IsMouseDragging(ImGuiMouseButton_Right)) { cfgPanX_ += ImGui::GetIO().MouseDelta.x; cfgPanY_ += ImGui::GetIO().MouseDelta.y; }
        float wheel = ImGui::GetIO().MouseWheel;
        if (wheel != 0) { cfgZoom_ *= (wheel > 0 ? 1.1f : 0.9f); if (cfgZoom_ < 0.3f) cfgZoom_ = 0.3f; if (cfgZoom_ > 3.0f) cfgZoom_ = 3.0f; }
    }
    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2 org = ImGui::GetCursorScreenPos();
    float z = cfgZoom_;
    const float BW = 260 * z, GAPY = 34 * z, PAD = 6 * z;
    float lineH = ImGui::GetTextLineHeight() * z;

    // layout vertical por orden; posición Y acumulada
    std::map<uint64_t, ImVec2> blockTopCenter, blockBotCenter;
    float y = org.y + 10 + cfgPanY_;
    float x = org.x + 20 + cfgPanX_;
    for (auto& b : blocks) {
        int n = (int)b.insnIdx.size();
        float bh = PAD * 2 + n * lineH + lineH;   // header + instrucciones
        ImVec2 tl(x, y), br(x + BW, y + bh);
        blockTopCenter[b.start] = ImVec2(x + BW*0.5f, y);
        blockBotCenter[b.start] = ImVec2(x + BW*0.5f, y + bh);
        dl->AddRectFilled(tl, br, ImGui::GetColorU32(ImVec4(0.14f,0.16f,0.2f,1)), 4);
        dl->AddRect(tl, br, ImGui::GetColorU32(ImVec4(0.45f,0.6f,0.9f,1)), 4);
        dl->AddText(ImGui::GetFont(), ImGui::GetFontSize()*z, ImVec2(tl.x+PAD, tl.y+PAD),
                    ImGui::GetColorU32(ImVec4(0.7f,0.9f,1,1)), ("loc_" + hex64(b.start)).c_str());
        float ty = tl.y + PAD + lineH;
        for (int ii : b.insnIdx) {
            std::string line = insns_[ii].text;
            dl->AddText(ImGui::GetFont(), ImGui::GetFontSize()*z, ImVec2(tl.x+PAD, ty),
                        ImGui::GetColorU32(ImVec4(0.85f,0.85f,0.85f,1)), line.c_str());
            ty += lineH;
        }
        y += bh + GAPY;
    }
    // aristas entre bloques
    for (auto& b : blocks) {
        auto from = blockBotCenter.find(b.start); if (from == blockBotCenter.end()) continue;
        for (uint64_t s : b.succ) {
            auto to = blockTopCenter.find(s); if (to == blockTopCenter.end()) continue;
            ImU32 col = ImGui::GetColorU32(b.succ.size() > 1 ? ImVec4(0.4f,0.9f,0.5f,0.8f) : ImVec4(0.9f,0.7f,0.3f,0.8f));
            dl->AddLine(from->second, to->second, col, 1.5f * z);
            dl->AddCircleFilled(to->second, 2.5f * z, col);
        }
    }
    ImGui::Dummy(ImVec2(BW + 60, y - org.y + 40));
    ImGui::EndChild();
    ImGui::TextDisabled("Arrastra con clic derecho para desplazar; rueda para zoom. %zu bloques.", blocks.size());
    ImGui::End();
}

// ---------------------------------------------------------------------------
// Comparación de dumps: diff byte a byte de dos archivos, lista rangos distintos
// ---------------------------------------------------------------------------
void App::drawComparePanel() {
    beginManaged("Compare");
    ImGui::TextDisabled("Compara dos archivos (dumps) byte a byte y lista los rangos que difieren.");
    ImGui::InputTextWithHint("A", "ruta del archivo A", cmpPathA_, sizeof(cmpPathA_));
    ImGui::SameLine();
    if (ImGui::SmallButton("...##a")) {
        wchar_t f[MAX_PATH]={0}; OPENFILENAMEW o{}; o.lStructSize=sizeof(o); o.lpstrFile=f; o.nMaxFile=MAX_PATH;
        o.lpstrFilter=L"Todos\0*.*\0"; if (GetOpenFileNameW(&o)) { std::wstring w(f); std::string s(w.begin(),w.end()); std::snprintf(cmpPathA_,sizeof(cmpPathA_),"%s",s.c_str()); }
    }
    ImGui::InputTextWithHint("B", "ruta del archivo B", cmpPathB_, sizeof(cmpPathB_));
    ImGui::SameLine();
    if (ImGui::SmallButton("...##b")) {
        wchar_t f[MAX_PATH]={0}; OPENFILENAMEW o{}; o.lStructSize=sizeof(o); o.lpstrFile=f; o.nMaxFile=MAX_PATH;
        o.lpstrFilter=L"Todos\0*.*\0"; if (GetOpenFileNameW(&o)) { std::wstring w(f); std::string s(w.begin(),w.end()); std::snprintf(cmpPathB_,sizeof(cmpPathB_),"%s",s.c_str()); }
    }
    if (ImGui::Button("Comparar") && cmpPathA_[0] && cmpPathB_[0]) {
        auto readAll = [](const char* p) {
            std::ifstream f(p, std::ios::binary);
            return std::vector<uint8_t>((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
        };
        std::vector<uint8_t> A = readAll(cmpPathA_), B = readAll(cmpPathB_);
        if (A.empty() || B.empty()) { cmpResult_ = "No se pudo leer uno de los archivos."; }
        else {
            size_t n = A.size() < B.size() ? A.size() : B.size();
            std::string r = "A=" + std::to_string(A.size()) + " bytes, B=" + std::to_string(B.size()) + " bytes\n";
            int ranges = 0; size_t diffCount = 0;
            for (size_t k = 0; k < n; ) {
                if (A[k] != B[k]) {
                    size_t start = k; while (k < n && A[k] != B[k]) { k++; diffCount++; }
                    if (ranges < 200) r += "  0x" + hex64(start) + " .. 0x" + hex64(k-1) + "  (" + std::to_string(k-start) + " bytes)\n";
                    ranges++;
                } else k++;
            }
            if (A.size() != B.size()) r += "  (tamaños distintos; sobran " + std::to_string((A.size()>B.size()?A.size():B.size())-n) + " bytes)\n";
            r = "Diferencias: " + std::to_string(diffCount) + " bytes en " + std::to_string(ranges) + " rangos\n" + r;
            if (ranges > 200) r += "  ...(mas de 200 rangos, truncado)\n";
            cmpResult_ = r;
        }
    }
    ImGui::Separator();
    ImGui::InputTextMultiline("##cmpres", cmpResult_.data(), cmpResult_.size()+1, ImVec2(-1,-1), ImGuiInputTextFlags_ReadOnly);
    ImGui::End();
}

// M8+: pide a la IA que infiera la struct en la direccion base a partir de los bytes.
void App::inferStructWithAi() {
    if (aiBusy_) return;
    const AiAgent* ag = aiConfig_.current();
    if (!ag) { pushLog("No hay agente de IA."); return; }
    ai_.setAgent(*ag);
    uint64_t base = 0; std::string err;
    if (!structBase_[0] || !evalExpr(structBase_, base, err)) { pushLog("Base de struct invalida: " + err); return; }
    uint8_t buf[128] = {0};
    size_t got = (dbgState_==DbgState::Paused) ? debugger_.readMemory(base, buf, sizeof(buf))
               : (fileLoaded_ ? pe_.readAtRva((uint32_t)(base-pe_.imageBase()), buf, sizeof(buf)) : 0);
    std::string hexs; for (size_t k=0;k<got;k++){ char b[4]; std::snprintf(b,sizeof(b),"%02X ",buf[k]); hexs+=b; }
    { std::lock_guard<std::mutex> lk(aiMutex_); chat_.push_back({"user","[Inferir struct en 0x"+hex64(base)+"]"}); }
    aiBusy_ = true;
    if (aiThread_.joinable()) aiThread_.join();
    aiThread_ = std::thread([this, hexs, base]() {
        std::vector<ChatMessage> h; h.push_back({"user",
            "Bytes (" + std::to_string(hexs.size()/3) + ") en 0x" + hex64(base) + ": " + hexs +
            ". Infiere una posible estructura C: lista campos con tipo (BYTE/WORD/DWORD/QWORD/ptr/char[]) "
            "y un nombre tentativo, uno por linea como 'offset tipo nombre'. Se conciso."});
        std::string er;
        std::string resp = ai_.send("Eres un experto en ingenieria inversa de estructuras en memoria. Responde en espanol.", h, 1024, er);
        std::lock_guard<std::mutex> lk(aiMutex_);
        chat_.push_back({"assistant", resp.empty() ? ("[error] "+er) : resp});
        aiBusy_ = false;
    });
    pushLog("Inferencia de struct enviada a la IA (ver panel IA).");
}

// ---------------------------------------------------------------------------
// Struct viewer (M8): aplica una definicion de campos a una direccion base
// ---------------------------------------------------------------------------
void App::drawStructPanel() {
    beginManaged("Struct");
    ImGui::TextDisabled("Aplica una struct a una direccion. La base admite expresiones (rax, 0x401000, dword(esp)).");
    ImGui::SetNextItemWidth(240);
    ImGui::InputTextWithHint("Base", "ej: rax  |  0x401000", structBase_, sizeof(structBase_));
    ImGui::SameLine();
    if (ImGui::Button("+ Campo")) structFields_.push_back(StructField{});
    ImGui::SameLine();
    if (ImGui::Button("Limpiar##struct")) structFields_.clear();
    ImGui::SameLine();
    ImGui::BeginDisabled(aiBusy_);
    if (ImGui::Button("Inferir con IA")) inferStructWithAi();
    ImGui::EndDisabled();

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
    beginManaged("Analysis");
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
    beginManaged("Executable modules");
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
    beginManaged("Call stack");
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
// Notes (paridad x64dbg): notas globales (notes_global.txt) y por-binario (por hash).
// ---------------------------------------------------------------------------
static std::string notesGlobalPath() {
    wchar_t exe[MAX_PATH] = {0}; GetModuleFileNameW(nullptr, exe, MAX_PATH);
    std::wstring w(exe); auto p = w.find_last_of(L"\\/");
    std::wstring dir = (p == std::wstring::npos) ? L"." : w.substr(0, p);
    std::wstring path = dir + L"\\notes_global.txt";
    return std::string(path.begin(), path.end());
}
static std::string notesDebuggeePath(const std::string& hash) {
    wchar_t exe[MAX_PATH] = {0}; GetModuleFileNameW(nullptr, exe, MAX_PATH);
    std::wstring w(exe); auto p = w.find_last_of(L"\\/");
    std::wstring dir = (p == std::wstring::npos) ? L"." : w.substr(0, p);
    std::wstring path = dir + L"\\cache\\" + std::wstring(hash.begin(), hash.end()) + L".notes.txt";
    return std::string(path.begin(), path.end());
}
static std::string readFileText(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    return f ? std::string((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>()) : std::string();
}
// Favourites: herramientas externas configurables en favourites.txt (nombre|comando).
// El comando admite %DEBUGGEE% (ruta del binario) y %PID%.
static std::string favFilePath() {
    wchar_t exe[MAX_PATH] = {0}; GetModuleFileNameW(nullptr, exe, MAX_PATH);
    std::wstring w(exe); auto p = w.find_last_of(L"\\/");
    std::wstring dir = (p == std::wstring::npos) ? L"." : w.substr(0, p);
    std::wstring path = dir + L"\\favourites.txt";
    return std::string(path.begin(), path.end());
}
void App::loadFavourites() {
    favourites_.clear();
    std::ifstream f(favFilePath(), std::ios::binary);
    if (!f) return;
    std::string line;
    while (std::getline(f, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        auto bar = line.find('|');
        if (bar == std::string::npos || line.empty() || line[0] == '#') continue;
        favourites_.push_back({ line.substr(0, bar), line.substr(bar + 1) });
    }
}
void App::runFavourite(const FavTool& f) {
    std::string cmd = f.command;
    std::string debuggee(loadedPath_.begin(), loadedPath_.end());
    std::string pid = (dbgState_ != DbgState::Idle) ? std::to_string(debugger_.pid()) : "0";
    auto rep = [&](const std::string& k, const std::string& v){ size_t p; while ((p = cmd.find(k)) != std::string::npos) cmd.replace(p, k.size(), v); };
    rep("%DEBUGGEE%", debuggee); rep("%PID%", pid);
    std::wstring wcmd(cmd.begin(), cmd.end());
    STARTUPINFOW si{}; si.cb = sizeof(si); PROCESS_INFORMATION pi{};
    std::wstring mut = wcmd;
    if (CreateProcessW(nullptr, mut.data(), nullptr, nullptr, FALSE, 0, nullptr, nullptr, &si, &pi)) {
        CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
        pushLog("Favourite ejecutado: " + f.name);
    } else pushLog("Favourite fallo: " + f.name);
}

void App::loadNotes() {
    std::snprintf(notesGlobal_, sizeof(notesGlobal_), "%s", readFileText(notesGlobalPath()).c_str());
    std::string h = peContentHash();
    if (!h.empty()) { notesDebuggeeHash_ = h; std::snprintf(notesDebuggee_, sizeof(notesDebuggee_), "%s", readFileText(notesDebuggeePath(h)).c_str()); }
}
void App::saveNotesGlobal() { std::ofstream f(notesGlobalPath(), std::ios::binary | std::ios::trunc); if (f) f << notesGlobal_; }
void App::saveNotesDebuggee() {
    if (notesDebuggeeHash_.empty()) return;
    std::ofstream f(notesDebuggeePath(notesDebuggeeHash_), std::ios::binary | std::ios::trunc);
    if (f) f << notesDebuggee_;
}
void App::drawNotesPanel() {
    beginManaged("Notes");
    std::string h = peContentHash();
    if (!h.empty() && h != notesDebuggeeHash_) { notesDebuggeeHash_ = h; std::snprintf(notesDebuggee_, sizeof(notesDebuggee_), "%s", readFileText(notesDebuggeePath(h)).c_str()); }

    float half = ImGui::GetContentRegionAvail().y * 0.5f - 30;
    ImGui::TextDisabled("Notas globales (persisten siempre):");
    ImGui::InputTextMultiline("##ng", notesGlobal_, sizeof(notesGlobal_), ImVec2(-1, half));
    if (ImGui::Button("Guardar globales")) saveNotesGlobal();
    ImGui::Separator();
    ImGui::TextDisabled("Notas de este binario (%s):", h.empty() ? "abre un archivo" : h.c_str());
    ImGui::BeginDisabled(h.empty());
    ImGui::InputTextMultiline("##nd", notesDebuggee_, sizeof(notesDebuggee_), ImVec2(-1, half));
    if (ImGui::Button("Guardar del binario")) saveNotesDebuggee();
    ImGui::EndDisabled();
    ImGui::End();
}

// ---------------------------------------------------------------------------
// System (paridad x64dbg): privilegios del token, conexiones TCP y handles.
// ---------------------------------------------------------------------------
std::string App::systemInfoJson() {
    njson j;
    if (dbgState_ == DbgState::Idle || dbgState_ == DbgState::Exited || !debugger_.processHandle()) {
        j["active"] = false; return j.dump();
    }
    j["active"] = true;
    uint32_t pid = debugger_.pid();
    HANDLE hProc = (HANDLE)debugger_.processHandle();

    // Privilegios del token del proceso
    HANDLE token = nullptr;
    if (OpenProcessToken(hProc, TOKEN_QUERY, &token)) {
        DWORD len = 0; GetTokenInformation(token, TokenPrivileges, nullptr, 0, &len);
        std::vector<uint8_t> buf(len);
        if (len && GetTokenInformation(token, TokenPrivileges, buf.data(), len, &len)) {
            auto* tp = (TOKEN_PRIVILEGES*)buf.data();
            for (DWORD i = 0; i < tp->PrivilegeCount; ++i) {
                char name[128] = {0}; DWORD nlen = sizeof(name);
                LUID luid = tp->Privileges[i].Luid;
                if (LookupPrivilegeNameA(nullptr, &luid, name, &nlen)) {
                    bool enabled = (tp->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED) != 0;
                    j["privileges"].push_back({{"name", name}, {"enabled", enabled}});
                }
            }
        }
        CloseHandle(token);
    }
    // Handle count
    DWORD hc = 0; if (GetProcessHandleCount(hProc, &hc)) j["handleCount"] = hc;
    // Conexiones TCP del proceso (IPv4)
    {
        ULONG sz = 0;
        GetExtendedTcpTable(nullptr, &sz, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
        std::vector<uint8_t> tbuf(sz);
        if (sz && GetExtendedTcpTable(tbuf.data(), &sz, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
            auto* t = (MIB_TCPTABLE_OWNER_PID*)tbuf.data();
            for (DWORD i = 0; i < t->dwNumEntries; ++i) {
                if (t->table[i].dwOwningPid != pid) continue;
                auto ipstr = [](DWORD ip){ char b[16]; unsigned char* p=(unsigned char*)&ip; std::snprintf(b,sizeof(b),"%u.%u.%u.%u",p[0],p[1],p[2],p[3]); return std::string(b); };
                static const char* states[] = {"","CLOSED","LISTEN","SYN_SENT","SYN_RCVD","ESTABLISHED","FIN_WAIT1","FIN_WAIT2","CLOSE_WAIT","CLOSING","LAST_ACK","TIME_WAIT","DELETE_TCB"};
                DWORD st = t->table[i].dwState;
                j["tcp"].push_back({
                    {"local", ipstr(t->table[i].dwLocalAddr) + ":" + std::to_string(ntohs((u_short)t->table[i].dwLocalPort))},
                    {"remote", ipstr(t->table[i].dwRemoteAddr) + ":" + std::to_string(ntohs((u_short)t->table[i].dwRemotePort))},
                    {"state", (st < 13) ? states[st] : "?"}
                });
            }
        }
    }
    return j.dump();
}

// Begin de una ventana gestionada con boton X en el titulo. Devuelve lo que devuelve
// Begin (false = colapsada). Al pulsar la X, winVisible_[name] pasa a false y la ventana
// deja de dibujarse (render usa visible()). Guarda la visibilidad para que persista.
bool App::beginManaged(const char* name) {
    bool wasVisible = winVisible_[name];
    bool ret = ImGui::Begin(name, &winVisible_[name]);
    if (wasVisible && !winVisible_[name]) saveVisibility();   // se cerro con la X
    return ret;
}

// Layout de docking por defecto: CPU al centro, logs abajo, el resto en pestañas a la
// derecha. Evita que las ventanas se solapen sueltas al abrir por primera vez.
void App::buildDefaultDock(unsigned int dockspaceId) {
    ImGui::DockBuilderRemoveNode(dockspaceId);
    ImGui::DockBuilderAddNode(dockspaceId, ImGuiDockNodeFlags_DockSpace);
    ImGui::DockBuilderSetNodeSize(dockspaceId, ImGui::GetMainViewport()->WorkSize);

    ImGuiID center = dockspaceId;
    ImGuiID down  = ImGui::DockBuilderSplitNode(center, ImGuiDir_Down,  0.26f, nullptr, &center);
    ImGuiID right = ImGui::DockBuilderSplitNode(center, ImGuiDir_Right, 0.34f, nullptr, &center);

    ImGui::DockBuilderDockWindow("CPU", center);
    for (const char* w : { "Log", "MCP Log", "Run trace", "Analysis", "Referencias" })
        ImGui::DockBuilderDockWindow(w, down);
    for (const char* w : { "Breakpoints", "Memoria", "Modulos & Simbolos", "Strings & Busqueda",
                           "Call stack", "Executable modules", "Packers / Proteccion", "Excepciones",
                           "Plugins", "IA", "Code", "Command", "Watch", "Struct", "CFG", "Compare",
                           "Script", "Threads", "Notes", "System", "Entropy" })
        ImGui::DockBuilderDockWindow(w, right);
    ImGui::DockBuilderFinish(dockspaceId);
    pushLog("Layout de ventanas reorganizado.");
}

// Ventana Contenedor: un DockSpace secundario. Con multi-viewport, arrastra su barra de
// titulo fuera del main y quedara como ventana del sistema (con minimizar/maximizar/cerrar)
// en el monitor que quieras; ancla dentro las demas ventanas para organizarlas.
// showInMain/showInContainer: reparto de paneles entre la ventana principal y la ventana
// Contenedor nativa (segundo monitor). Un panel visible se dibuja en una o en la otra.
bool App::showInMain(const char* name) { return visible(name) && !winContainer_[name]; }
bool App::showInContainer(const char* name) { return visible(name) && winContainer_[name]; }

// Despacha el dibujo de un panel gestionado por su nombre (usado por render y renderContainer).
void App::drawManagedPanel(const char* name) {
    std::string n = name;
    if (n=="CPU") drawCpuPanel();
    else if (n=="Breakpoints") drawBreakpointsPanel();
    else if (n=="Memoria") drawMemoryPanel();
    else if (n=="Strings & Busqueda") drawStringsPanel();
    else if (n=="Modulos & Simbolos") drawModulesPanel();
    else if (n=="Packers / Proteccion") drawPackerPanel();
    else if (n=="Excepciones") drawExceptionsPanel();
    else if (n=="Call stack") drawCallStackPanel();
    else if (n=="Threads") drawThreadsPanel();
    else if (n=="Notes") drawNotesPanel();
    else if (n=="System") drawSystemPanel();
    else if (n=="Entropy") drawEntropyPanel();
    else if (n=="Executable modules") drawExecModulesPanel();
    else if (n=="Referencias") drawReferencesPanel();
    else if (n=="Analysis") drawAnalysisPanel();
    else if (n=="Run trace") drawTracePanel();
    else if (n=="Plugins") drawPluginsPanel();
    else if (n=="MCP Log") drawMcpLogPanel();
    else if (n=="Log") drawLogPanel();
    else if (n=="IA") drawAiPanel();
    else if (n=="Code") drawCodePanel();
    else if (n=="Command") drawCommandBar();
    else if (n=="Watch") drawWatchPanel();
    else if (n=="Struct") drawStructPanel();
    else if (n=="CFG") drawCfgPanel();
    else if (n=="Compare") drawComparePanel();
    else if (n=="Script") drawScriptPanel();
}

// Se llama con el contexto ImGui de la ventana Contenedor activo (segunda ventana nativa).
// Dibuja un DockSpace que llena la ventana y ancla ahi los paneles enviados al Contenedor.
void App::renderContainer() {
    ImGuiID dock = ImGui::DockSpaceOverViewport(0, ImGui::GetMainViewport());
    if (containerDockInit_) {
        containerDockInit_ = false;
        ImGui::DockBuilderRemoveNode(dock);
        ImGui::DockBuilderAddNode(dock, ImGuiDockNodeFlags_DockSpace);
        ImGui::DockBuilderSetNodeSize(dock, ImGui::GetMainViewport()->WorkSize);
        for (auto nm : managedWindows()) if (winContainer_[nm]) ImGui::DockBuilderDockWindow(nm, dock);
        ImGui::DockBuilderFinish(dock);
    }
    for (auto nm : managedWindows())
        if (showInContainer(nm)) drawManagedPanel(nm);
}

static std::string containerStatePath() {
    wchar_t exe[MAX_PATH]={0}; GetModuleFileNameW(nullptr, exe, MAX_PATH);
    std::wstring w(exe); auto p=w.find_last_of(L"\\/");
    std::wstring dir=(p==std::wstring::npos)?L".":w.substr(0,p);
    std::wstring path=dir+L"\\container_state.txt";
    return std::string(path.begin(), path.end());
}
void App::setContainerScreenRect(int x, int y, int w, int h, bool valid) { contRectX_=x; contRectY_=y; contRectW_=w; contRectH_=h; contRectValid_=valid; }
void App::setMainScreenRect(int x, int y, int w, int h) { mainRectX_=x; mainRectY_=y; mainRectW_=w; mainRectH_=h; }

// Extrae el nombre gestionado de una ventana ImGui (quita el sufijo "###id").
static std::string managedNameOf(ImGuiWindow* w) {
    if (!w) return "";
    std::string n = w->Name;
    auto h = n.find("###");
    if (h != std::string::npos) return n.substr(h + 3);
    return n;
}

// (Contexto main) Si el usuario arrastra una ventana del main y la suelta sobre la ventana
// Contenedor, ese panel se transfiere al Contenedor.
void App::handleContainerDrop() {
    ImGuiContext* g = ImGui::GetCurrentContext();
    // Mientras se arrastra una ventana gestionada, recordar su nombre.
    if (g && g->MovingWindow) {
        std::string nm = managedNameOf(g->MovingWindow->RootWindow ? g->MovingWindow->RootWindow : g->MovingWindow);
        for (auto mnamed : managedWindows()) if (nm == mnamed) {
            if (draggingWin_ != nm) pushLog("[drag] arrastrando: " + nm);
            draggingWin_ = nm; break;
        }
    }
    // Al soltar el boton, si habia un arrastre y el cursor cae sobre el Contenedor, transferir.
    if (ImGui::IsMouseReleased(ImGuiMouseButton_Left) && !draggingWin_.empty()) {
        std::string nm = draggingWin_; draggingWin_.clear();
        POINT pt; GetCursorPos(&pt);
        bool inside = contRectValid_ && pt.x >= contRectX_ && pt.x < contRectX_ + contRectW_ && pt.y >= contRectY_ && pt.y < contRectY_ + contRectH_;
        pushLog("[drop] " + nm + " cursor=(" + std::to_string(pt.x) + "," + std::to_string(pt.y) + ") contRect=(" +
                std::to_string(contRectX_) + "," + std::to_string(contRectY_) + "," + std::to_string(contRectW_) + "," + std::to_string(contRectH_) +
                ") open=" + (containerOpen_?"1":"0") + " valid=" + (contRectValid_?"1":"0") + " inside=" + (inside?"1":"0"));
        if (containerOpen_ && inside) {
            winContainer_[nm] = true; containerDockInit_ = true; saveContainerState();
            pushLog("Panel enviado al Contenedor: " + nm);
        }
    }
}

// (Contexto Contenedor) Si arrastra una ventana del Contenedor y la suelta sobre el main,
// vuelve al main.
void App::handleMainDrop() {
    ImGuiContext* g = ImGui::GetCurrentContext();
    if (g && g->MovingWindow) {
        std::string nm = managedNameOf(g->MovingWindow->RootWindow ? g->MovingWindow->RootWindow : g->MovingWindow);
        for (auto mnamed : managedWindows()) if (nm == mnamed) { draggingWin_ = nm; break; }
        return;
    }
    if (draggingWin_.empty()) return;
    std::string nm = draggingWin_; draggingWin_.clear();
    POINT pt; GetCursorPos(&pt);
    bool overMain = (pt.x >= mainRectX_ && pt.x < mainRectX_ + mainRectW_ && pt.y >= mainRectY_ && pt.y < mainRectY_ + mainRectH_);
    bool overCont = (contRectValid_ && pt.x >= contRectX_ && pt.x < contRectX_ + contRectW_ && pt.y >= contRectY_ && pt.y < contRectY_ + contRectH_);
    if (overMain && !overCont) {
        winContainer_[nm] = false; dockNeedsInit_ = true; saveContainerState();
        pushLog("Panel devuelto al main: " + nm);
    }
}

void App::saveContainerState() {
    std::ofstream f(containerStatePath(), std::ios::trunc);
    if (!f) return;
    f << "open|" << (containerOpen_?1:0) << "\n";
    for (auto& [k,v] : winContainer_) if (v) f << "panel|" << k << "\n";
}
void App::loadContainerState() {
    std::ifstream f(containerStatePath());
    if (!f) return;
    std::string line;
    while (std::getline(f, line)) {
        if (!line.empty() && line.back()=='\r') line.pop_back();
        auto bar=line.find('|'); if (bar==std::string::npos) continue;
        std::string k=line.substr(0,bar), v=line.substr(bar+1);
        if (k=="open") containerOpen_ = (v=="1");
        else if (k=="panel") winContainer_[v] = true;
    }
}

void App::drawEntropyPanel() {
    beginManaged("Entropy");
    if (!fileLoaded_) { ImGui::TextDisabled("Abre un archivo."); ImGui::End(); return; }
    ImGui::Text("Entropia global: %.3f / 8.0", pe_.overallEntropy());
    ImGui::TextDisabled("0 = uniforme, 8 = maxima aleatoriedad. >7.2 suele indicar cifrado/empaquetado.");
    ImGui::Separator();
    for (const auto& s : pe_.sections()) {
        float e = (float)s.entropy;
        float frac = e / 8.0f;
        ImVec4 col = e > 7.2f ? ImVec4(0.9f,0.3f,0.3f,1) : e > 6.0f ? ImVec4(0.9f,0.8f,0.3f,1) : ImVec4(0.4f,0.8f,0.4f,1);
        ImGui::Text("%-10s", s.name.c_str());
        ImGui::SameLine(110);
        ImGui::PushStyleColor(ImGuiCol_PlotHistogram, col);
        char ov[24]; std::snprintf(ov, sizeof(ov), "%.3f", e);
        ImGui::ProgressBar(frac, ImVec2(-1, 0), ov);
        ImGui::PopStyleColor();
    }
    ImGui::End();
}

void App::drawSystemPanel() {
    beginManaged("System");
    if (dbgState_ == DbgState::Idle || dbgState_ == DbgState::Exited || !debugger_.processHandle()) {
        ImGui::TextDisabled("(sin sesion de depuracion)"); ImGui::End(); return;
    }
    njson j; try { j = njson::parse(systemInfoJson()); } catch (...) {}
    if (j.contains("handleCount")) ImGui::Text("Handles abiertos: %d", (int)j["handleCount"]);
    ImGui::Separator();
    if (ImGui::CollapsingHeader("Privilegios del token", ImGuiTreeNodeFlags_DefaultOpen)) {
        for (auto& p : j.value("privileges", njson::array())) {
            bool en = p.value("enabled", false);
            ImGui::TextColored(en ? ImVec4(0.6f,1,0.6f,1) : ImVec4(0.6f,0.6f,0.6f,1), "%s %s",
                               en ? "[on] " : "[off]", p.value("name", "").c_str());
        }
    }
    if (ImGui::CollapsingHeader("Conexiones TCP", ImGuiTreeNodeFlags_DefaultOpen)) {
        if (ImGui::BeginTable("tcp", 3, ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders)) {
            ImGui::TableSetupColumn("Local"); ImGui::TableSetupColumn("Remoto"); ImGui::TableSetupColumn("Estado");
            ImGui::TableHeadersRow();
            for (auto& c : j.value("tcp", njson::array())) {
                ImGui::TableNextRow();
                ImGui::TableSetColumnIndex(0); ImGui::TextUnformatted(c.value("local","").c_str());
                ImGui::TableSetColumnIndex(1); ImGui::TextUnformatted(c.value("remote","").c_str());
                ImGui::TableSetColumnIndex(2); ImGui::TextUnformatted(c.value("state","").c_str());
            }
            ImGui::EndTable();
        }
        if (j.value("tcp", njson::array()).empty()) ImGui::TextDisabled("Sin conexiones TCP IPv4.");
    }
    ImGui::TextDisabled("Enumeracion detallada de handles individuales: pendiente (se muestra el conteo).");
    ImGui::End();
}

void App::drawThreadsPanel() {
    beginManaged("Threads");
    if (dbgState_ == DbgState::Idle || dbgState_ == DbgState::Exited) {
        ImGui::TextDisabled("(sin sesion de depuracion)"); ImGui::End(); return;
    }
    auto threads = debugger_.threads();
    ImGui::Text("%zu hilo(s)", threads.size());
    ImGui::Separator();
    if (ImGui::BeginTable("threads", 4, ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders | ImGuiTableFlags_ScrollY)) {
        ImGui::TableSetupColumn("TID", ImGuiTableColumnFlags_WidthFixed, 80);
        ImGui::TableSetupColumn("Actual", ImGuiTableColumnFlags_WidthFixed, 60);
        ImGui::TableSetupColumn("Prioridad", ImGuiTableColumnFlags_WidthFixed, 80);
        ImGui::TableSetupColumn("Descripcion / estado", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableHeadersRow();
        for (const auto& t : threads) {
            ImGui::TableNextRow();
            if (t.current) ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0, ImGui::GetColorU32(ImVec4(0.25f,0.30f,0.10f,1)));
            ImGui::TableSetColumnIndex(0);
            ImGui::PushID((int)t.id);
            ImGui::Text("%u", t.id);
            if (ImGui::BeginPopupContextItem("thctx")) {
                if (ImGui::MenuItem("Suspender")) debugger_.suspendThread(t.id);
                if (ImGui::MenuItem("Reanudar")) debugger_.resumeThread(t.id);
                if (ImGui::MenuItem("Terminar hilo")) debugger_.killThread(t.id);
                if (ImGui::BeginMenu("Prioridad")) {
                    if (ImGui::MenuItem("Idle (-15)")) debugger_.setThreadPriority(t.id, THREAD_PRIORITY_IDLE);
                    if (ImGui::MenuItem("Below normal (-1)")) debugger_.setThreadPriority(t.id, THREAD_PRIORITY_BELOW_NORMAL);
                    if (ImGui::MenuItem("Normal (0)")) debugger_.setThreadPriority(t.id, THREAD_PRIORITY_NORMAL);
                    if (ImGui::MenuItem("Above normal (+1)")) debugger_.setThreadPriority(t.id, THREAD_PRIORITY_ABOVE_NORMAL);
                    if (ImGui::MenuItem("Highest (+2)")) debugger_.setThreadPriority(t.id, THREAD_PRIORITY_HIGHEST);
                    ImGui::EndMenu();
                }
                ImGui::EndPopup();
            }
            ImGui::PopID();
            ImGui::TableSetColumnIndex(1); ImGui::TextUnformatted(t.current ? "->" : "");
            ImGui::TableSetColumnIndex(2); ImGui::Text("%d", t.priority);
            ImGui::TableSetColumnIndex(3); ImGui::TextUnformatted(t.description.empty() ? "-" : t.description.c_str());
        }
        ImGui::TextDisabled("Clic derecho en un TID: suspender/reanudar/terminar/prioridad.");
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
        cmd == "plugin_run" || cmd == "plugin_reload" || cmd == "symsrv" || cmd == "run_script" || cmd == "thread_ctrl" || cmd == "notes_set" ||
        cmd == "mem_alloc" || cmd == "mem_free" || cmd == "mem_fill" || cmd == "mem_copy" || cmd == "mem_save" || cmd == "page_protect") return 2;
    if (cmd == "attach" || cmd == "detach" || cmd == "launch" || cmd == "restart" || cmd == "go" || cmd == "pause" ||
        cmd == "step_into" || cmd == "step_over" || cmd == "step_to_ret" || cmd == "stop" ||
        cmd == "set_bp" || cmd == "del_bp" || cmd == "set_hwbp" || cmd == "del_hwbp" ||
        cmd == "set_membp" || cmd == "del_membp" ||
        cmd == "add_exc_bp" || cmd == "rm_exc_bp" || cmd == "set_event_breaks" ||
        cmd == "set_bookmark" || cmd == "del_bookmark" || cmd == "clear_analysis" ||
        cmd == "set_follow_children" || cmd == "switch_to_child" || cmd == "run_to" || cmd == "run_until" ||
        cmd == "skip_instruction" || cmd == "undo_instruction" || cmd == "animate" ||
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
    // Fallback de puerto: si el bind falla (p.ej. un socket huerfano ocupa el puerto),
    // prueba los siguientes hasta 10 puertos antes de rendirse.
    int basePort = mcpPort_;
    bool started = false;
    for (int off = 0; off < 10 && !started; ++off) {
        int tryPort = basePort + off;
        started = mcp_.start(tryPort, mcpBindAll_, mcpToken_, mcpAccessLevel_, disp, err, mcpNoAuth_);
        if (started) mcpPort_ = tryPort;
    }
    if (started) {
        mcpStatus_ = "MCP escuchando en " + std::string(mcpBindAll_ ? "0.0.0.0:" : "127.0.0.1:") + std::to_string(mcpPort_) +
                     (mcpNoAuth_ ? " (BYPASS: sin token)" : " (token y permiso de sesion requeridos)") +
                     (mcpPort_ != basePort ? "  [puerto " + std::to_string(basePort) + " ocupado, se uso " + std::to_string(mcpPort_) + "]" : "");
    } else mcpStatus_ = "Error: " + err;
    pushLog(mcpStatus_);
}
void App::stopMcp() { mcp_.stop(); mcpToken_.clear(); mcpStatus_ = "MCP detenido; el token de sesion fue invalidado."; pushLog(mcpStatus_); }
void App::cliStartMcp(int port, bool bindAll) { mcpPort_ = port; mcpBindAll_ = bindAll; startMcp(); }
void App::cliSetNoAuth(bool on) { mcpNoAuth_ = on; }
void App::cliSetAccess(int level) { mcpAccessLevel_ = level < 0 ? 0 : (level > 2 ? 2 : level); }

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
        else {
            std::string fmt = a.value("format", "markdown");
            if (fmt == "json") res["json"] = buildAnalysisReportJson();
            else if (fmt == "sarif") res["sarif"] = buildSarifReport();
            else res["markdown"] = buildAnalysisReport();
        }
    }
    else if (cmd == "run_script") {
        std::string e; res["output"] = runScript(a.value("src", ""), e);
        if (!e.empty()) { res["ok"] = false; res["error"] = e; }
    }
    else if (cmd == "validate_dump") {
        std::string p = a.value("path", "");
        if (p.empty()) { res["ok"] = false; res["error"] = "path requerido"; }
        else { std::string rep; res["valid"] = validateDump(std::wstring(p.begin(), p.end()), rep); res["report"] = rep; }
    }
    else if (cmd == "export_report") {
        const std::string path = a.value("path", "");
        if (path.empty()) { res["ok"] = false; res["error"] = "path requerido"; }
        else {
            std::string error;
            std::wstring wp(path.begin(), path.end());
            bool asJson = a.value("format", "") == "json" || (path.size() > 5 && path.substr(path.size()-5) == ".json");
            res["ok"] = asJson ? saveAnalysisReportJson(wp, error) : saveAnalysisReport(wp, error);
            if (!res["ok"]) res["error"] = error;
        }
    }
    else if (cmd == "diff_files") {
        auto readAll = [](const std::string& p) {
            std::ifstream f(p, std::ios::binary);
            return std::vector<uint8_t>((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
        };
        std::vector<uint8_t> A = readAll(a.value("a","")), B = readAll(a.value("b",""));
        if (A.empty() || B.empty()) { res["ok"] = false; res["error"] = "no se pudo leer a/b"; }
        else {
            size_t n = A.size() < B.size() ? A.size() : B.size(); size_t diffs = 0; int ranges = 0;
            for (size_t k = 0; k < n; ) {
                if (A[k] != B[k]) { size_t s = k; while (k < n && A[k] != B[k]) { k++; diffs++; }
                    if (ranges < 500) res["ranges"].push_back({{"start", s}, {"end", k-1}, {"len", k-s}}); ranges++; }
                else k++;
            }
            res["sizeA"] = A.size(); res["sizeB"] = B.size(); res["diffBytes"] = diffs; res["rangeCount"] = ranges;
        }
    }
    else if (cmd == "infer_struct") {
        uint64_t base = 0; std::string err;
        if (!evalExpr(a.value("addr","0"), base, err)) { res["ok"]=false; res["error"]=err; }
        else { std::snprintf(structBase_, sizeof(structBase_), "0x%llX", (unsigned long long)base);
               inferStructWithAi(); res["queued"] = true; res["addr"] = base; }
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
    else if (cmd == "threads") {
        for (const auto& t : debugger_.threads())
            res["threads"].push_back({{"tid", t.id}, {"current", t.current}, {"priority", t.priority}, {"description", t.description}});
    }
    else if (cmd == "system_info") {
        try { res["system"] = njson::parse(systemInfoJson()); } catch (...) { res["ok"] = false; }
    }
    else if (cmd == "notes_get") {
        std::string h = peContentHash();
        if (!h.empty() && h != notesDebuggeeHash_) loadNotes();
        res["global"] = std::string(notesGlobal_);
        res["debuggee"] = std::string(notesDebuggee_);
    }
    else if (cmd == "notes_set") {
        std::string scope = a.value("scope", "debuggee"), text = a.value("text", "");
        if (scope == "global") { std::snprintf(notesGlobal_, sizeof(notesGlobal_), "%s", text.c_str()); saveNotesGlobal(); }
        else {
            if (notesDebuggeeHash_.empty()) notesDebuggeeHash_ = peContentHash();
            std::snprintf(notesDebuggee_, sizeof(notesDebuggee_), "%s", text.c_str()); saveNotesDebuggee();
        }
    }
    else if (cmd == "run_to") {
        if (!need_paused()) goto done;
        runToAddress(jU64(a["addr"]));
    }
    else if (cmd == "run_until") {
        if (!need_paused()) goto done;
        int mode = a.value("over", false) ? 1 : 0;
        startRunUntil(a.value("expr", ""), mode, (int)a.value("max", 100000));
        res["mode"] = mode ? "over" : "into";
    }
    else if (cmd == "skip_instruction") { if (!need_paused()) goto done; skipInstruction(); }
    else if (cmd == "undo_instruction") { if (!need_paused()) goto done; undoInstruction(); }
    else if (cmd == "animate") {
        if (!need_paused() && a.value("on", true)) goto done;
        animateMode_ = a.value("over", false) ? 1 : 0;
        animateActive_ = a.value("on", true);
        res["active"] = animateActive_;
    }
    else if (cmd == "mem_alloc") {
        if (!need_paused()) goto done;
        size_t size = (size_t)a.value("size", 4096);
        uint32_t prot = (uint32_t)jU64(a.value("protect", njson(0x40)));  // def PAGE_EXECUTE_READWRITE
        uint64_t va = debugger_.allocMemory(size, prot);
        if (va) { res["addr"] = va; res["hex"] = "0x" + hex64(va); } else { res["ok"] = false; res["error"] = "VirtualAllocEx fallo"; }
    }
    else if (cmd == "mem_free") { if (!need_paused()) goto done; res["ok"] = debugger_.freeMemory(jU64(a["addr"])); }
    else if (cmd == "mem_fill") {
        if (!need_paused()) goto done;
        res["ok"] = debugger_.fillMemory(jU64(a["addr"]), (uint8_t)jU64(a.value("value", njson(0))), (size_t)a.value("size", 1));
    }
    else if (cmd == "mem_copy") {
        if (!need_paused()) goto done;
        size_t n = (size_t)a.value("size", 0); if (n > 1048576) n = 1048576;
        std::vector<uint8_t> buf(n);
        size_t got = debugger_.readMemory(jU64(a["src"]), buf.data(), n);
        size_t wr = 0; if (got) wr = debugger_.writeMemory(jU64(a["dst"]), buf.data(), got);
        res["copied"] = wr; res["ok"] = (wr == got && got > 0);
    }
    else if (cmd == "mem_save") {
        size_t n = (size_t)a.value("size", 0); if (n > 67108864) n = 67108864;
        std::string path = a.value("path", "");
        std::vector<uint8_t> buf(n);
        size_t got = (dbgState_==DbgState::Paused) ? debugger_.readMemory(jU64(a["addr"]), buf.data(), n)
                   : (fileLoaded_ ? pe_.readAtRva((uint32_t)(jU64(a["addr"])-pe_.imageBase()), buf.data(), n) : 0);
        std::ofstream f(path, std::ios::binary); if (f) f.write((char*)buf.data(), got);
        res["ok"] = (bool)f && got > 0; res["written"] = got;
    }
    else if (cmd == "page_protect") {
        if (!need_paused()) goto done;
        uint32_t oldp = 0; bool ok = debugger_.setPageProtect(jU64(a["addr"]), (uint32_t)jU64(a["protect"]), oldp);
        res["ok"] = ok; res["old"] = oldp;
    }
    else if (cmd == "thread_ctrl") {
        uint32_t tid = (uint32_t)a.value("tid", 0);
        std::string action = a.value("action", "");
        if (!tid || action.empty()) { res["ok"] = false; res["error"] = "tid y action requeridos"; }
        else if (action == "suspend") res["ok"] = debugger_.suspendThread(tid);
        else if (action == "resume")  res["ok"] = debugger_.resumeThread(tid);
        else if (action == "kill")    res["ok"] = debugger_.killThread(tid, (uint32_t)a.value("value", 0));
        else if (action == "priority") res["ok"] = debugger_.setThreadPriority(tid, (int)a.value("value", 0));
        else if (action == "name")    res["ok"] = debugger_.setThreadName(tid, a.value("name", ""));
        else { res["ok"] = false; res["error"] = "action: suspend|resume|kill|priority|name"; }
    }
    else if (cmd == "list_children") {
        res["follow"] = debugger_.followChildren();
        for (uint32_t p : debugger_.childPids()) res["children"].push_back(p);
    }
    else if (cmd == "switch_to_child") {
        uint32_t pid = static_cast<uint32_t>(a.value("pid", 0));
        if (!pid) { res["ok"] = false; res["error"] = "pid requerido"; }
        else { switchToChild(pid); res["pid"] = pid; res["state"] = "switching"; }
    }
    else if (cmd == "set_follow_children") {
        debugger_.setFollowChildren(a.value("on", true));
        res["follow"] = debugger_.followChildren();
    }
    else if (cmd == "poll_events") {
        uint64_t since = jU64(a.value("since", njson(0)));
        std::lock_guard<std::mutex> lk(eventsMutex_);
        res["last"] = eventSeq_;
        for (auto& e : events_) if (e.seq > since)
            res["events"].push_back({{"seq", e.seq}, {"type", e.type}, {"arg", e.arg}});
    }
    else if (cmd == "var_set") {
        std::string name = a.value("name", "");
        std::string valexpr = a.value("value", "0");
        uint64_t v = 0; std::string e;
        if (name.empty()) { res["ok"] = false; res["error"] = "name requerido"; }
        else if (!evalExpr(valexpr, v, e)) { res["ok"] = false; res["error"] = e; }
        else { std::string ln = name; for (char& c : ln) c = (char)std::tolower((unsigned char)c); globalVars_[ln] = v; res["value"] = v; }
    }
    else if (cmd == "var_get") {
        std::string ln = a.value("name", ""); for (char& c : ln) c = (char)std::tolower((unsigned char)c);
        auto it = globalVars_.find(ln);
        if (it == globalVars_.end()) { res["ok"] = false; res["error"] = "no existe"; }
        else { res["value"] = it->second; res["hex"] = "0x" + hex64(it->second); }
    }
    else if (cmd == "var_list") {
        for (auto& [k, v] : globalVars_) res["vars"].push_back({{"name", k}, {"value", v}});
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
    beginManaged("MCP Log");
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
    beginManaged("Log");
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
    add("eval",        "Evalua una expresion (hex por defecto; byte/dword/ptr(a), reg, mod.base/fromname, dis.len, [mem], variables globales).", obj({{"expr", STR}}, {"expr"}));
    add("var_set",     "Define una variable global (usable en expresiones). value es una expresion.", obj({{"name", STR}, {"value", STR}}, {"name","value"}));
    add("var_get",     "Lee una variable global.", obj({{"name", STR}}, {"name"}));
    add("var_list",    "Lista las variables globales definidas.", obj(EMPTY, {}));
    add("symsrv",      "Configura la ruta de simbolos (symsrv), ej 'srv*C:\\\\symbols*https://msdl.microsoft.com/download/symbols'.", obj({{"path", STR}}, {"path"}));
    add("poll_events", "Sondea el bus de eventos (streaming). Devuelve eventos con seq > 'since' y el ultimo seq.", obj({{"since", INT}}, {}));
    add("diff_files",  "Compara dos archivos byte a byte y devuelve los rangos que difieren.", obj({{"a", STR}, {"b", STR}}, {"a","b"}));
    add("threads",     "Lista los hilos del proceso depurado (TID, actual, prioridad, descripcion).", obj(EMPTY, {}));
    add("system_info", "Info del sistema para el proceso: privilegios del token, conexiones TCP y conteo de handles.", obj(EMPTY, {}));
    add("notes_get",   "Devuelve las notas globales y las del binario actual.", obj(EMPTY, {}));
    add("notes_set",   "Guarda notas. scope: 'global' o 'debuggee' (por binario).", obj({{"scope", STR}, {"text", STR}}, {"text"}));
    add("run_to",      "Ejecuta hasta una direccion (breakpoint temporal + continuar). Requiere pausado.", obj({{"addr", HEX}}, {"addr"}));
    add("run_until",   "Single-step hasta que una expresion sea != 0 (o se agote max). over=true usa step over. Requiere pausado.", obj({{"expr", STR}, {"over", njson{{"type","boolean"}}}, {"max", INT}}, {"expr"}));
    add("skip_instruction", "Avanza RIP/EIP a la siguiente instruccion SIN ejecutar la actual. Requiere pausado.", obj(EMPTY, {}));
    add("undo_instruction", "Restaura los registros previos al ultimo paso (no revierte memoria). Requiere pausado.", obj(EMPTY, {}));
    add("animate",     "Step animado: da un paso periodicamente. on=true/false; over=true para step over.", obj({{"on", njson{{"type","boolean"}}}, {"over", njson{{"type","boolean"}}}}, {}));
    add("thread_ctrl", "Controla un hilo. action: suspend|resume|kill|priority|name; value=prioridad/exitcode; name=nombre.", obj({{"tid", INT}, {"action", STR}, {"value", INT}, {"name", STR}}, {"tid","action"}));
    add("mem_alloc",   "Reserva memoria en el proceso (VirtualAllocEx). size, protect (hex, def 0x40=RWX). Requiere pausado.", obj({{"size", INT}, {"protect", HEX}}, {}));
    add("mem_free",    "Libera memoria reservada (VirtualFreeEx). Requiere pausado.", obj({{"addr", HEX}}, {"addr"}));
    add("mem_fill",    "Rellena memoria con un byte. addr, value (0-255), size. Requiere pausado.", obj({{"addr", HEX}, {"value", INT}, {"size", INT}}, {"addr","size"}));
    add("mem_copy",    "Copia 'size' bytes de src a dst dentro del proceso. Requiere pausado.", obj({{"src", HEX}, {"dst", HEX}, {"size", INT}}, {"src","dst","size"}));
    add("mem_save",    "Guarda 'size' bytes desde addr a un archivo (memoria o PE estatico).", obj({{"addr", HEX}, {"size", INT}, {"path", STR}}, {"addr","size","path"}));
    add("page_protect","Cambia la proteccion de una pagina (VirtualProtectEx). protect en hex. Requiere pausado.", obj({{"addr", HEX}, {"protect", HEX}}, {"addr","protect"}));
    add("list_children","Lista los PIDs de procesos hijos detectados (requiere 'Seguir procesos hijos').", obj(EMPTY, {}));
    add("set_follow_children","Activa/desactiva seguir procesos hijos (fijar antes de lanzar).", obj({{"on", njson{{"type","boolean"}}}}, {}));
    add("switch_to_child","Conmuta el target: desadjunta el actual y adjunta el proceso hijo indicado.", obj({{"pid", INT}}, {"pid"}));
    add("run_script",  "Ejecuta un script (mini-lenguaje: $v=expr, print, log, label:, goto, if..goto, cmd key=val).", obj({{"src", STR}}, {"src"}));
    add("validate_dump","Valida un ejecutable volcado (entrypoint, entropia de codigo, IAT).", obj({{"path", STR}}, {"path"}));
    add("infer_struct","Pide a la IA que infiera la struct en una direccion (resultado en el panel IA).", obj({{"addr", HEX}}, {"addr"}));
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

    std::string skillsPrompt = activeSkillsPrompt();   // skills activos (hilo UI)
    aiThread_ = std::thread([this, hist, userMsg, agentMode, skillsPrompt]() {
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
                "tecnico. Responde en espanol." + skillsPrompt;

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
                "Se conciso y tecnico. Responde en espanol." + skillsPrompt;
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

// ---------------------------------------------------------------------------
// Skills de IA (Fase 1, locales): recetas en skills/*.md que se inyectan en el system
// prompt del agente cuando estan marcadas. Un skill es texto (procedimiento), no codigo.
// ---------------------------------------------------------------------------
static std::string skillsDir() { return exeSiblingDir() + "\\skills"; }
static std::string skillsActivePath() { return exeSiblingDir() + "\\skills_active.txt"; }

void App::loadSkills() {
    skills_.clear();
    // set de skills activos guardados
    std::set<std::string> active;
    { std::ifstream f(skillsActivePath()); std::string l; while (std::getline(f, l)) { if (!l.empty() && l.back()=='\r') l.pop_back(); if(!l.empty()) active.insert(l); } }

    CreateDirectoryA(skillsDir().c_str(), nullptr);
    std::string pattern = skillsDir() + "\\*.md";
    std::wstring wpat(pattern.begin(), pattern.end());
    WIN32_FIND_DATAW fd{};
    HANDLE h = FindFirstFileW(wpat.c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        std::wstring wname(fd.cFileName);
        std::string fname(wname.begin(), wname.end());
        std::ifstream f(skillsDir() + "\\" + fname, std::ios::binary);
        if (!f) continue;
        std::string content((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
        Skill s; s.file = fname; s.name = fname.substr(0, fname.size()-3);
        // frontmatter --- ... ---
        std::string body = content;
        if (content.rfind("---", 0) == 0) {
            size_t end = content.find("\n---", 3);
            if (end != std::string::npos) {
                std::string fm = content.substr(3, end-3);
                body = content.substr(end + 4);
                std::stringstream ss(fm); std::string line;
                while (std::getline(ss, line)) {
                    if (!line.empty() && line.back()=='\r') line.pop_back();
                    auto colon = line.find(':'); if (colon == std::string::npos) continue;
                    std::string k = line.substr(0, colon), v = line.substr(colon+1);
                    auto trim=[&](std::string&x){ while(!x.empty()&&isspace((unsigned char)x.front()))x.erase(x.begin()); while(!x.empty()&&isspace((unsigned char)x.back()))x.pop_back(); };
                    trim(k); trim(v);
                    if (k=="name") s.name=v; else if (k=="description") s.description=v;
                    else if (k=="author") s.author=v; else if (k=="version") s.version=v;
                }
            }
        }
        s.body = body;
        s.active = active.count(s.name) > 0;
        skills_.push_back(std::move(s));
    } while (FindNextFileW(h, &fd));
    FindClose(h);
}

void App::saveActiveSkills() {
    std::ofstream f(skillsActivePath(), std::ios::trunc);
    if (!f) return;
    for (auto& s : skills_) if (s.active) f << s.name << "\n";
}

std::string App::activeSkillsPrompt() {
    std::string out;
    for (auto& s : skills_) if (s.active && !s.body.empty()) {
        out += "\n\n### Skill activo: " + s.name + "\n" + s.body;
    }
    if (!out.empty())
        out = "\n\nEl usuario ha activado los siguientes SKILLS (procedimientos que debes seguir "
              "cuando apliquen a la tarea):" + out;
    return out;
}

void App::createSkillTemplate(const std::string& name, const std::string& desc) {
    if (name.empty()) return;
    std::string safe; for (char c : name) safe += (isalnum((unsigned char)c) ? c : '-');
    CreateDirectoryA(skillsDir().c_str(), nullptr);
    std::string path = skillsDir() + "\\" + safe + ".md";
    std::ofstream f(path, std::ios::binary);
    if (!f) { pushLog("No se pudo crear el skill."); return; }
    f << "---\n"
      << "name: " << name << "\n"
      << "description: " << (desc.empty() ? "Describe que hace este skill" : desc) << "\n"
      << "author: " << "tu-usuario" << "\n"
      << "version: 1.0\n"
      << "tools: [dbg_status, dbg_disasm, dbg_read_mem]\n"
      << "---\n\n"
      << "# Objetivo\n"
      << "Explica en una linea la tarea que resuelve este skill.\n\n"
      << "# Procedimiento\n"
      << "1. Primer paso (usa las tools dbg_* que necesites).\n"
      << "2. Segundo paso...\n"
      << "3. Al terminar, resume el resultado.\n\n"
      << "# Notas\n"
      << "- Direcciones en hex. El proceso debe estar pausado para leer registros/memoria.\n"
      << "- Sé conciso y técnico.\n";
    f.close();
    pushLog("Skill creado: " + path);
    loadSkills();
}

void App::drawSkillBrowser() {
    ImGui::SetNextWindowSize(ImVec2(560, 420), ImGuiCond_FirstUseEver);
    if (!ImGui::Begin("Skill browser", &showSkillBrowser_)) { ImGui::End(); return; }
    ImGui::TextWrapped("Marca los skills que quieres aplicar al agente de IA actual. Sus instrucciones "
                       "se anaden al prompt del sistema. Son recetas de texto, no ejecutan codigo.");
    ImGui::SameLine();
    if (ImGui::SmallButton("Recargar")) loadSkills();
    ImGui::Separator();
    if (skills_.empty()) ImGui::TextDisabled("No hay skills en la carpeta 'skills'. Crea uno en Manage Skills.");
    int activeCount = 0;
    for (int i = 0; i < (int)skills_.size(); ++i) {
        auto& s = skills_[i];
        ImGui::PushID(i);
        if (ImGui::Checkbox("##act", &s.active)) saveActiveSkills();
        ImGui::SameLine();
        if (ImGui::TreeNode(s.name.c_str())) {
            if (!s.description.empty()) ImGui::TextWrapped("%s", s.description.c_str());
            ImGui::TextDisabled("autor: %s   version: %s", s.author.empty()?"-":s.author.c_str(), s.version.empty()?"-":s.version.c_str());
            ImGui::Separator();
            ImGui::TextUnformatted(s.body.substr(0, 1500).c_str());
            ImGui::TreePop();
        } else if (!s.description.empty()) { ImGui::SameLine(); ImGui::TextDisabled("- %s", s.description.c_str()); }
        if (s.active) activeCount++;
        ImGui::PopID();
    }
    ImGui::Separator();
    ImGui::Text("%d skill(s) activo(s) para el agente actual.", activeCount);
    ImGui::End();
}

void App::drawSkillManage() {
    ImGui::SetNextWindowSize(ImVec2(520, 380), ImGuiCond_FirstUseEver);
    if (!ImGui::Begin("Manage Skills", &showSkillManage_)) { ImGui::End(); return; }
    ImGui::TextUnformatted("Crear un skill nuevo (se genera una plantilla .md editable):");
    ImGui::SetNextItemWidth(180); ImGui::InputTextWithHint("##sn", "nombre", skillNewName_, sizeof(skillNewName_));
    ImGui::SameLine();
    ImGui::SetNextItemWidth(220); ImGui::InputTextWithHint("##sd", "descripcion", skillNewDesc_, sizeof(skillNewDesc_));
    ImGui::SameLine();
    if (ImGui::Button("Crear") && skillNewName_[0]) { createSkillTemplate(skillNewName_, skillNewDesc_); skillNewName_[0]=0; skillNewDesc_[0]=0; }
    ImGui::Separator();
    ImGui::TextDisabled("Carpeta: %s", skillsDir().c_str());
    if (skills_.empty()) ImGui::TextDisabled("(sin skills)");
    for (int i = 0; i < (int)skills_.size(); ++i) {
        auto& s = skills_[i];
        ImGui::PushID(i);
        ImGui::TextUnformatted(s.name.c_str());
        ImGui::SameLine(260);
        if (ImGui::SmallButton("Editar")) {
            std::string p = skillsDir() + "\\" + s.file;
            ShellExecuteA(nullptr, "open", p.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
        }
        ImGui::SameLine();
        if (ImGui::SmallButton("Eliminar")) {
            std::string p = skillsDir() + "\\" + s.file;
            DeleteFileA(p.c_str()); loadSkills(); ImGui::PopID(); break;
        }
        ImGui::PopID();
    }
    ImGui::End();
}

void App::drawAiPanel() {
    { bool was = winVisible_["IA"]; ImGui::Begin("IA", &winVisible_["IA"], ImGuiWindowFlags_MenuBar);
      if (was && !winVisible_["IA"]) saveVisibility(); }

    // Menu Skills (Fase 1): browser y gestion de skills que se aplican al agente.
    if (ImGui::BeginMenuBar()) {
        if (ImGui::BeginMenu("Skills")) {
            if (ImGui::MenuItem("Skill browser")) { loadSkills(); showSkillBrowser_ = true; }
            if (ImGui::MenuItem("Manage Skills")) { loadSkills(); showSkillManage_ = true; }
            int act = 0; for (auto& s : skills_) if (s.active) act++;
            ImGui::Separator();
            ImGui::TextDisabled("%d skill(s) activo(s)", act);
            ImGui::EndMenu();
        }
        ImGui::EndMenuBar();
    }

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

// Manda las instrucciones seleccionadas en el CPU a la IA para interpretarlas como
// C++, mostrando el resultado en la ventana Code (clic derecho -> Analyze / AI as C++).
void App::analyzeSelectionAsCpp() {
    if (aiBusy_) { pushLog("La IA esta ocupada."); return; }
    const AiAgent* agent = aiConfig_.current();
    if (!agent) { pushLog("No hay agente de IA configurado (Tools -> Options -> AI)."); return; }
    if (selectedInsn_ < 0 || insns_.empty()) { pushLog("Selecciona una o varias lineas en el CPU."); return; }

    int lo = selAnchor_ >= 0 ? std::min(selAnchor_, selectedInsn_) : selectedInsn_;
    int hi = selAnchor_ >= 0 ? std::max(selAnchor_, selectedInsn_) : selectedInsn_;
    lo = std::max(0, lo); hi = std::min((int)insns_.size()-1, hi);
    bool is64 = (dbgState_ == DbgState::Paused) ? debugger_.is64() : pe_.is64Bit();
    std::string asmText;
    for (int i = lo; i <= hi && i - lo < 400; ++i)
        asmText += vaStr(insns_[i].address, is64) + "  " + insns_[i].bytes + "\t" + insns_[i].text + "\n";

    winVisible_["Code"] = true;
    ai_.setAgent(*agent);
    aiBusy_ = true; aiError_.clear();
    { std::lock_guard<std::mutex> lk(aiMutex_); codeOutput_ = "Analizando " + std::to_string(hi-lo+1) + " instruccion(es) seleccionada(s)..."; }
    if (aiThread_.joinable()) aiThread_.join();
    aiThread_ = std::thread([this, asmText]() {
        std::string sys =
            "Eres un analista experto de ensamblador x86/x64 con fines defensivos. Te dan un "
            "fragmento de codigo desensamblado. Conviertelo en PSEUDOCODIGO C++ legible, marcando "
            "inferencias y nombres tentativos. Explica llamadas API, efectos y posibles intenciones "
            "maliciosas. Responde en espanol: un bloque C++ y luego notas breves.";
        std::vector<ChatMessage> h; h.push_back({"user", "Ensamblador seleccionado:\n" + asmText});
        std::string err;
        std::string resp = ai_.send(sys, h, 4096, err);
        std::lock_guard<std::mutex> lk(aiMutex_);
        codeOutput_ = resp.empty() ? ("[error] " + err) : resp;
        aiBusy_ = false;
    });
    pushLog("Analisis 'AI as C++' del codigo seleccionado enviado (ver ventana Code).");
}

void App::drawCodePanel() {
    beginManaged("Code");
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

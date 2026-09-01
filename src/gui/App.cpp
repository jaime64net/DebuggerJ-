#include "App.h"

#include <windows.h>
#include <commdlg.h>
#include <algorithm>
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
    debugger_.setCallbacks(cb);

    aiConfig_.load();
    if (const AiAgent* a = aiConfig_.current()) ai_.setAgent(*a);
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
    comments_.clear(); labels_.clear(); refs_.clear();
    loadAnnotations();
    refreshDisassembly();
    refreshStaticStrings();
    runPackerScan();
    std::string p(path.begin(), path.end());
    pushLog("Abierto: " + p + (pe_.is64Bit() ? "  [x64]" : "  [x86]") +
            "  EntryPoint VA=0x" + hex64(pe_.entryPointVA()));
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
}

void App::runPackerScan() {
    if (!packerLoaded_) {
        packer_.loadBuiltin();
        packer_.loadSignatures("signatures/userdb.txt"); // opcional
        packerLoaded_ = true;
    }
    if (fileLoaded_) packerMatches_ = packer_.analyze(pe_);
}

void App::gotoAddress(uint64_t va) {
    if (dbgState_ == DbgState::Paused) {
        refreshLiveDisassembly(va);
        selectedInsn_ = 0;
        pendingScroll_ = 0;
    } else {
        for (size_t i = 0; i < insns_.size(); ++i)
            if (insns_[i].address == va) { selectedInsn_ = (int)i; pendingScroll_ = (int)i; break; }
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
    if (debugger_.state() != DbgState::Idle) { pushLog("Ya hay una sesion activa."); return; }
    std::string err;
    std::wstring args(strlen(launchArgs_) ? std::wstring(launchArgs_, launchArgs_ + strlen(launchArgs_)) : L"");
    if (!debugger_.launch(loadedPath_, args, err)) pushLog("No se pudo lanzar: " + err);
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
            // Re-aplicar anti-anti-debug si esta activado (el malware puede re-chequear)
            if (antiReapply_ && antiActive_) {
                std::string lg;
                applyAntiAntiDebug(debugger_, debugger_.is64(), antiOpt_, lg);
            }
        }
    }

    drainMcpQueue();

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
    if (visible("Run trace"))            drawTracePanel();
    if (visible("Plugins"))              drawPluginsPanel();
    if (visible("MCP Log"))              drawMcpLogPanel();
    if (visible("Log"))                  drawLogPanel();
    if (visible("IA"))                   drawAiPanel();
    if (visible("Code"))                 drawCodePanel();
    if (showOptions_)                    drawOptionsWindow();

    drawAddCustomPopup();
    drawStatusBar();
}

// ---------------------------------------------------------------------------
// Gestion de ventanas: mosaico + layouts personalizados
// ---------------------------------------------------------------------------
std::vector<const char*> App::managedWindows() {
    return {
        "CPU",
        "Breakpoints", "Memoria", "Strings & Busqueda", "Modulos & Simbolos",
        "Call stack", "Executable modules", "Referencias", "Run trace",
        "Packers / Proteccion", "Excepciones", "Plugins", "MCP Log", "Log", "IA", "Code"
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
            ImGui::EndMenu();
        }
        if (ImGui::BeginMenu("Depurar")) {
            if (ImGui::MenuItem("Lanzar bajo debug", "F9", false, fileLoaded_)) startDebugSession();
            if (ImGui::MenuItem("Detener", nullptr, false, dbgState_ != DbgState::Idle)) debugger_.stop();
            ImGui::EndMenu();
        }
        if (ImGui::BeginMenu("Tools")) {
            if (ImGui::MenuItem("Options...")) {
                showOptions_ = true;
                optLoadDraft(aiConfig_.selected());
            }
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

    if (ImGui::BeginTable("dis", 4,
            ImGuiTableFlags_ScrollY | ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersInnerV | ImGuiTableFlags_Resizable)) {
        ImGui::TableSetupColumn("BP",  ImGuiTableColumnFlags_WidthFixed, 24);
        ImGui::TableSetupColumn("Direccion", ImGuiTableColumnFlags_WidthFixed, 140);
        ImGui::TableSetupColumn("Bytes", ImGuiTableColumnFlags_WidthFixed, 150);
        ImGui::TableSetupColumn("Instruccion", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableHeadersRow();

        auto bps = debugger_.breakpoints();
        auto hasBp = [&](uint64_t a){ for (auto& b : bps) if (b.address == a) return true; return false; };

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
                        ImGui::EndMenu();
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
                    if (in.hasBranchTarget && ImGui::MenuItem("Ir al destino del salto"))
                        gotoAddress(in.branchTarget);
                    ImGui::EndPopup();
                }
                if (i == pendingScroll_) { ImGui::SetScrollHereY(0.35f); pendingScroll_ = -1; }
                ImGui::PopID();

                ImGui::TableSetColumnIndex(1);
                ImGui::TextColored(isCur ? ImVec4(1,0.9f,0.4f,1) : ImVec4(0.6f,0.8f,1,1),
                                   "%s", vaStr(in.address, dbgState_==DbgState::Paused ? debugger_.is64() : pe_.is64Bit()).c_str());
                ImGui::TableSetColumnIndex(2);
                ImGui::TextDisabled("%s", in.bytes.c_str());
                ImGui::TableSetColumnIndex(3);
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
    auto bps = debugger_.breakpoints();
    ImGui::Text("%zu breakpoints", bps.size());
    ImGui::Separator();
    if (ImGui::BeginTable("bps", 4, ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders)) {
        ImGui::TableSetupColumn("On", ImGuiTableColumnFlags_WidthFixed, 30);
        ImGui::TableSetupColumn("Direccion", ImGuiTableColumnFlags_WidthFixed, 150);
        ImGui::TableSetupColumn("Etiqueta", ImGuiTableColumnFlags_WidthStretch);
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
            ImGui::BeginChild("mods", ImVec2(0, 320), true);
            for (auto& m : mods) ImGui::Text("0x%s  %s", hex64(m.base).c_str(), m.name.c_str());
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
    ImGui::End();
}

void App::drawPluginsPanel() {
    ImGui::Begin("Plugins");
    bool active = (dbgState_ == DbgState::Running || dbgState_ == DbgState::Paused);
    bool paused = (dbgState_ == DbgState::Paused);

    if (!pluginStatus_.empty())
        ImGui::TextColored(ImVec4(0.7f,0.9f,1,1), "%s", pluginStatus_.c_str());
    ImGui::Separator();

    // ---- Plugin 0: Claude MCP ----
    if (ImGui::CollapsingHeader("Claude MCP", ImGuiTreeNodeFlags_DefaultOpen)) {
        ImGui::TextDisabled("Expone el debugger para que Claude lo controle (servidor de control TCP).");
        ImGui::SetNextItemWidth(90);
        ImGui::InputInt("Puerto", &mcpPort_);
        if (mcpPort_ < 1) mcpPort_ = 1; if (mcpPort_ > 65535) mcpPort_ = 65535;
        ImGui::SameLine();
        ImGui::Checkbox("Bind 0.0.0.0 (WSL/red)", &mcpBindAll_);
        if (!mcp_.running()) {
            if (ImGui::Button("Activar Claude MCP")) startMcp();
        } else {
            if (ImGui::Button("Detener MCP")) stopMcp();
            ImGui::SameLine();
            ImGui::TextColored(ImVec4(0.5f,1,0.5f,1), "ACTIVO  puerto %d, %d cliente(s)", mcp_.port(), mcp_.clients());
        }
        if (!mcpStatus_.empty()) ImGui::TextWrapped("%s", mcpStatus_.c_str());
        ImGui::TextDisabled("Registra el MCP en Claude: mcp/README.md");
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

    ImGui::End();
}

// ---------------------------------------------------------------------------
// Anotaciones (comentarios/etiquetas) y referencias
// ---------------------------------------------------------------------------
void App::saveAnnotations() {
    if (loadedPath_.empty()) return;
    std::ofstream f((loadedPath_ + L".annot.txt").c_str());
    if (!f) return;
    for (auto& [a, t] : labels_)   { char h[20]; std::snprintf(h,sizeof(h),"%llX",(unsigned long long)a); f << h << "|L|" << t << "\n"; }
    for (auto& [a, t] : comments_) { char h[20]; std::snprintf(h,sizeof(h),"%llX",(unsigned long long)a); f << h << "|C|" << t << "\n"; }
}
void App::loadAnnotations() {
    if (loadedPath_.empty()) return;
    std::ifstream f((loadedPath_ + L".annot.txt").c_str());
    if (!f) return;
    std::string line;
    while (std::getline(f, line)) {
        if (!line.empty() && line.back()=='\r') line.pop_back();
        size_t p1 = line.find('|'); if (p1==std::string::npos) continue;
        size_t p2 = line.find('|', p1+1); if (p2==std::string::npos) continue;
        uint64_t a = strtoull(line.substr(0,p1).c_str(), nullptr, 16);
        std::string type = line.substr(p1+1, p2-p1-1);
        std::string text = line.substr(p2+1);
        if (type=="L") labels_[a]=text; else comments_[a]=text;
    }
}
void App::findReferences(uint64_t addr) {
    refs_.clear(); refTarget_ = addr;
    for (auto& in : insns_) if (in.hasBranchTarget && in.branchTarget == addr) refs_.push_back(in.address);
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
    pushLog("Referencias a 0x" + hex64(addr) + ": " + std::to_string(refs_.size()));
    winVisible_["Referencias"] = true;
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
    ImGui::Text("%zu modulos cargados", mods.size());
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
            ImGui::TableSetColumnIndex(2); ImGui::TextUnformatted(pos==std::string::npos?p.c_str():p.c_str()+pos+1);
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
            if (ImGui::Selectable(("0x" + hex64(m.base)).c_str(), false, ImGuiSelectableFlags_SpanAllColumns))
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

    size_t ptr = regs_.is64 ? 8 : 4;
    auto mods = debugger_.modules();
    auto modOf = [&](uint64_t va) -> const char* {
        for (auto& m : mods) if (va >= m.base && va < m.base + 0x4000000ull) return m.name.c_str();
        return "";
    };

    if (ImGui::BeginTable("cs", 4, ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders | ImGuiTableFlags_ScrollY)) {
        ImGui::TableSetupColumn("#", ImGuiTableColumnFlags_WidthFixed, 28);
        ImGui::TableSetupColumn("Frame", ImGuiTableColumnFlags_WidthFixed, 150);
        ImGui::TableSetupColumn("Return", ImGuiTableColumnFlags_WidthFixed, 150);
        ImGui::TableSetupColumn("Modulo", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableHeadersRow();

        // Frame 0: RIP actual
        ImGui::TableNextRow();
        ImGui::TableSetColumnIndex(0); ImGui::Text("0");
        ImGui::TableSetColumnIndex(1); ImGui::TextDisabled("%s", vaStr(regs_.rsp, regs_.is64).c_str());
        ImGui::TableSetColumnIndex(2);
        if (ImGui::Selectable(vaStr(regs_.rip, regs_.is64).c_str(), false)) gotoAddress(regs_.rip);
        ImGui::TableSetColumnIndex(3);
        { std::string sym = debugger_.symbolAt(regs_.rip); ImGui::TextUnformatted(sym.empty() ? modOf(regs_.rip) : sym.c_str()); }

        uint64_t frame = regs_.rbp;
        for (int depth = 1; depth <= 32; ++depth) {
            if (!frame) break;
            uint64_t ret = 0, prev = 0;
            if (debugger_.readMemory(frame + ptr, &ret, ptr) != ptr) break;
            if (debugger_.readMemory(frame, &prev, ptr) != ptr) break;
            if (ret == 0) break;
            ImGui::TableNextRow();
            ImGui::PushID(depth);
            ImGui::TableSetColumnIndex(0); ImGui::Text("%d", depth);
            ImGui::TableSetColumnIndex(1); ImGui::TextDisabled("%s", vaStr(frame, regs_.is64).c_str());
            ImGui::TableSetColumnIndex(2);
            if (ImGui::Selectable(vaStr(ret, regs_.is64).c_str(), false)) gotoAddress(ret);
            ImGui::TableSetColumnIndex(3);
            { std::string sym = debugger_.symbolAt(ret); ImGui::TextUnformatted(sym.empty() ? modOf(ret) : sym.c_str()); }
            ImGui::PopID();
            if (prev <= frame || prev - frame > 0x100000) break; // cadena rota / fuera de rango
            frame = prev;
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
    auto disp = [this](const std::string& line) -> std::string { return execDbgCommand(line); };
    if (mcp_.start(mcpPort_, mcpBindAll_, disp, err)) {
        mcpStatus_ = "MCP escuchando en " + std::string(mcpBindAll_ ? "0.0.0.0:" : "127.0.0.1:") + std::to_string(mcpPort_);
    } else mcpStatus_ = "Error: " + err;
    pushLog(mcpStatus_);
}
void App::stopMcp() { mcp_.stop(); mcpStatus_ = "MCP detenido."; pushLog(mcpStatus_); }
void App::cliStartMcp(int port, bool bindAll) { mcpPort_ = port; mcpBindAll_ = bindAll; startMcp(); }

void App::drainMcpQueue() {
    std::deque<McpReq*> local;
    { std::lock_guard<std::mutex> lk(mcpMutex_); local.swap(mcpQueue_); }
    for (auto* r : local) {
        std::string out;
        try { out = handleMcpCommand(r->req); }
        catch (const std::exception& e) { out = std::string("{\"ok\":false,\"error\":\"") + e.what() + "\"}"; }
        catch (...) { out = "{\"ok\":false,\"error\":\"excepcion\"}"; }
        {
            std::lock_guard<std::mutex> lk(mcpLogMutex_);
            mcpLog_.push_back("> " + (r->req.size() > 220 ? r->req.substr(0, 220) + "..." : r->req));
            mcpLog_.push_back("< " + (out.size() > 220 ? out.substr(0, 220) + "..." : out));
            while (mcpLog_.size() > 600) mcpLog_.pop_front();
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
    else if (cmd == "open") {
        std::string p = a.value("path", "");
        std::wstring w(p.begin(), p.end());
        openFile(w);
        res["ok"] = fileLoaded_; if (!fileLoaded_) res["error"] = openError_;
    }
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
    else if (cmd == "set_bp")  { res["ok"] = debugger_.addBreakpoint(jU64(a["addr"]), a.value("label","mcp")); }
    else if (cmd == "del_bp")  { res["ok"] = debugger_.removeBreakpoint(jU64(a["addr"])); }
    else if (cmd == "list_bp") { for (auto& b : debugger_.breakpoints()) if (!b.oneShot) res["bps"].push_back({{"addr",b.address},{"enabled",b.enabled},{"label",b.label}}); }
    else if (cmd == "set_hwbp") { int t=(int)a.value("type",0); int l=(int)a.value("len",1); res["ok"]=debugger_.addHwBreakpoint(jU64(a["addr"]), t, l, a.value("label","mcp")); }
    else if (cmd == "del_hwbp") { res["ok"]=debugger_.removeHwBreakpoint(jU64(a["addr"])); }
    else if (cmd == "list_hwbp") { for (auto& h : debugger_.hwBreakpoints()) res["hwbps"].push_back({{"slot",h.slot},{"addr",h.address},{"type",h.type},{"len",h.len},{"hits",h.hits}}); }
    else if (cmd == "add_exc_bp") { res["id"] = debugger_.addExceptionBreak((uint32_t)jU64(a.value("code", njson(0))), jU64(a.value("addr", njson(0))), a.value("label","mcp")); }
    else if (cmd == "list_exc") { for (auto& e : debugger_.exceptionBreaks()) res["exc"].push_back({{"id",e.id},{"code",e.code},{"addr",e.address},{"hits",e.hits}}); }
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
    else if (cmd == "symbol") { res["symbol"] = debugger_.symbolAt(jU64(a["addr"])); }
    else if (cmd == "call_stack") {
        if (!need_paused()) goto done;
        Registers r = debugger_.registers(); size_t ptr = r.is64 ? 8 : 4;
        res["frames"].push_back({{"ret", r.rip}, {"frame", r.rsp}, {"sym", debugger_.symbolAt(r.rip)}});
        uint64_t frame = r.rbp;
        for (int d = 1; d <= 32 && frame; ++d) {
            uint64_t ret = 0, prev = 0;
            if (debugger_.readMemory(frame+ptr,&ret,ptr)!=ptr) break;
            if (debugger_.readMemory(frame,&prev,ptr)!=ptr) break;
            if (!ret) break;
            res["frames"].push_back({{"ret",ret},{"frame",frame},{"sym",debugger_.symbolAt(ret)}});
            if (prev<=frame || prev-frame>0x100000) break; frame=prev;
        }
    }
    else if (cmd == "tls") { for (auto v : pe_.tlsCallbacks()) res["tls"].push_back(v); }
    else if (cmd == "seh") { for (auto& e : debugger_.sehChain()) res["seh"].push_back({{"record",e.first},{"handler",e.second}}); }
    else if (cmd == "exports") { for (auto& e : pe_.exports()) res["exports"].push_back({{"name",e.name},{"ordinal",e.ordinal},{"rva",e.rva}}); }
    else if (cmd == "mem_map") { for (auto& r : debugger_.memoryMap()) res["regions"].push_back({{"base",r.base},{"size",r.size},{"protect",r.protectStr},{"type",r.typeStr},{"module",r.moduleName}}); }
    else if (cmd == "set_comment") { uint64_t addr=jU64(a["addr"]); std::string t=a.value("text",""); if(t.empty())comments_.erase(addr); else comments_[addr]=t; saveAnnotations(); }
    else if (cmd == "set_label") { uint64_t addr=jU64(a["addr"]); std::string t=a.value("text",""); if(t.empty())labels_.erase(addr); else labels_[addr]=t; saveAnnotations(); }
    else if (cmd == "list_annotations") { for(auto&[k,v]:labels_) res["labels"].push_back({{"addr",k},{"text",v}}); for(auto&[k,v]:comments_) res["comments"].push_back({{"addr",k},{"text",v}}); }
    else if (cmd == "find_refs") { findReferences(jU64(a["addr"])); for(auto x:refs_) res["refs"].push_back(x); }
    else if (cmd == "run_trace") { if(!need_paused()) goto done; debugger_.runTrace(); }
    else if (cmd == "get_trace") { auto t=debugger_.traceLog(); res["count"]=t.size(); size_t lim=t.size()>5000?5000:t.size(); for(size_t i=0;i<lim;++i) res["trace"].push_back(t[i]); }
    else if (cmd == "rm_exc_bp") { debugger_.removeExceptionBreak((uint32_t)jU64(a["id"])); }
    else { res["ok"] = false; res["error"] = "comando desconocido: " + cmd; }

done:
    return res.dump();
}

void App::drawMcpLogPanel() {
    ImGui::Begin("MCP Log");
    if (mcp_.running())
        ImGui::TextColored(ImVec4(0.5f,1,0.5f,1), "MCP activo: puerto %d, %d cliente(s)", mcp_.port(), mcp_.clients());
    else
        ImGui::TextDisabled("MCP inactivo (actívalo en Plugins -> Claude MCP)");
    ImGui::SameLine();
    if (ImGui::SmallButton("Limpiar")) { std::lock_guard<std::mutex> lk(mcpLogMutex_); mcpLog_.clear(); }
    ImGui::Separator();
    ImGui::BeginChild("mcplog", ImVec2(0, 0), false, ImGuiWindowFlags_HorizontalScrollbar);
    {
        std::lock_guard<std::mutex> lk(mcpLogMutex_);
        for (auto& l : mcpLog_) {
            bool req = (!l.empty() && l[0] == '>');
            ImGui::TextColored(req ? ImVec4(0.6f,0.85f,1,1) : ImVec4(0.7f,1,0.7f,1), "%s", l.c_str());
        }
    }
    if (ImGui::GetScrollY() >= ImGui::GetScrollMaxY() - 5) ImGui::SetScrollHereY(1.0f);
    ImGui::EndChild();
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
    add("open",        "Abre un .exe/.dll para analizar (parsea PE, desensambla).", obj({{"path", STR}}, {"path"}));
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
    add("goto_module", "Lleva la vista CPU a la base de un modulo/DLL cargado. name acepta nombre parcial.", obj({{"name", STR}}, {"name"}));
    add("stack",       "Lee la pila desde RSP/ESP. count=n entradas.", obj({{"count", INT}}, {}));
    add("set_bp",      "Pone un breakpoint de software.", obj({{"addr", HEX}, {"label", STR}}, {"addr"}));
    add("del_bp",      "Quita un breakpoint.", obj({{"addr", HEX}}, {"addr"}));
    add("list_bp",     "Lista los breakpoints.", obj(EMPTY, {}));
    add("set_hwbp",    "Hardware breakpoint (DR0-3). type=0 exec/1 write/3 rw, len=1/2/4/8.", obj({{"addr", HEX}, {"type", INT}, {"len", INT}}, {"addr"}));
    add("del_hwbp",    "Quita un hardware breakpoint.", obj({{"addr", HEX}}, {"addr"}));
    add("list_hwbp",   "Lista los hardware breakpoints.", obj(EMPTY, {}));
    add("add_exc_bp",  "Breakpoint de excepcion. code=0 (cualquiera) o codigo hex.", obj({{"code", HEX}, {"addr", HEX}}, {}));
    add("list_exc",    "Lista los breakpoints de excepcion.", obj(EMPTY, {}));
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
    add("symbol",      "Resuelve el simbolo (DbgHelp) de una direccion.", obj({{"addr", HEX}}, {"addr"}));
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
                "dbg_status", "dbg_get_regs", "dbg_read_mem", "dbg_disasm", "dbg_stack",
                "dbg_modules", "dbg_sections", "dbg_imports", "dbg_exports", "dbg_packers",
                "dbg_search_hex", "dbg_get_oep", "dbg_symbol", "dbg_call_stack", "dbg_tls",
                "dbg_seh", "dbg_mem_map", "dbg_list_annotations", "dbg_find_refs", "dbg_get_trace"
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
        ImGui::EndTabBar();
    }
    ImGui::End();
}

} // namespace dbg

#include "PluginManager.h"

#include <filesystem>
#include <fstream>
#include <windows.h>
#include <nlohmann/json.hpp>

namespace fs = std::filesystem;
using json = nlohmann::json;

namespace dbg {

static PluginManifest manifestFromJson(const json& j, const std::string& path, PluginKind kind) {
    PluginManifest p;
    p.id = j.value("id", ""); p.name = j.value("name", p.id);
    p.version = j.value("version", ""); p.description = j.value("description", "");
    p.enabled = j.value("enabled", true); p.sourcePath = path; p.kind = kind;
    if (p.id.empty()) throw std::runtime_error("falta id");
    for (const auto& a : j.value("actions", json::array())) {
        PluginAction action;
        action.id = a.value("id", ""); action.label = a.value("label", action.id);
        action.description = a.value("description", ""); action.command = a.value("command", "");
        action.argsJson = a.value("args", json::object()).dump();
        action.inputSchema = a.value("input_schema", json{{"type","object"},{"properties",json::object()}}).dump();
        if (action.id.empty()) throw std::runtime_error("accion sin id");
        if (kind == PluginKind::Json && action.command.empty()) throw std::runtime_error("accion JSON sin command");
        p.actions.push_back(std::move(action));
    }
    if (p.actions.empty()) throw std::runtime_error("no define actions");
    return p;
}

PluginManager::~PluginManager() { clear(); }
void PluginManager::clear() { for (auto& p : plugins_) if (p.nativeModule) FreeLibrary((HMODULE)p.nativeModule); plugins_.clear(); errors_.clear(); }

void PluginManager::load(const std::string& directory, bool loadNativeDlls) {
    clear(); std::error_code ec;
    if (!fs::exists(directory, ec)) return;
    for (const auto& entry : fs::directory_iterator(directory, ec)) {
        if (ec) { errors_.push_back("No se pudo leer el directorio de plugins."); break; }
        if (!entry.is_regular_file()) continue;
        try {
            if (entry.path().extension() == ".json") {
                std::ifstream f(entry.path());
                plugins_.push_back(manifestFromJson(json::parse(f), entry.path().string(), PluginKind::Json));
            } else if (entry.path().extension() == ".dll") {
                if (!loadNativeDlls) { errors_.push_back(entry.path().filename().string() + ": DLL no cargada (activa plugins DLL nativos)."); continue; }
                HMODULE m = LoadLibraryExW(entry.path().c_str(), nullptr, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
                if (!m) throw std::runtime_error("LoadLibraryEx fallo " + std::to_string(GetLastError()));
                using VersionFn = unsigned int (DBGJPP_PLUGIN_CALL *)(void);
                auto version = reinterpret_cast<VersionFn>(GetProcAddress(m, "DebuggerJppPluginGetApiVersion"));
                auto info = reinterpret_cast<DbgPluginGetInfoFn>(GetProcAddress(m, "DebuggerJppPluginGetInfo"));
                auto run = reinterpret_cast<DbgPluginRunFn>(GetProcAddress(m, "DebuggerJppPluginRun"));
                if (!version || !info || !run || version() != DBGJPP_PLUGIN_API_VERSION) { FreeLibrary(m); throw std::runtime_error("ABI/exportaciones incompatibles"); }
                const char* raw = info(); if (!raw) { FreeLibrary(m); throw std::runtime_error("GetInfo devolvio null"); }
                PluginManifest p = manifestFromJson(json::parse(raw), entry.path().string(), PluginKind::NativeDll);
                p.nativeModule = (uintptr_t)m; p.nativeRun = run; plugins_.push_back(std::move(p));
            }
        } catch (const std::exception& e) { errors_.push_back(entry.path().filename().string() + ": " + e.what()); }
    }
}

const PluginManifest* PluginManager::find(const std::string& id) const { for (const auto& p : plugins_) if (p.id == id) return &p; return nullptr; }
const PluginAction* PluginManager::findAction(const std::string& pluginId, const std::string& actionId) const {
    const PluginManifest* p = find(pluginId); if (!p || !p->enabled) return nullptr;
    for (const auto& a : p->actions) if (a.id == actionId) return &a; return nullptr;
}
bool PluginManager::runNative(const PluginManifest& p, const std::string& actionId, const std::string& argsJson,
                              const DbgPluginHostApi& host, std::string& output) const {
    if (!p.nativeRun) return false;
    std::vector<char> buffer(65536, '\0');
    int rc = p.nativeRun(actionId.c_str(), argsJson.c_str(), &host, buffer.data(), buffer.size());
    output.assign(buffer.data());
    if (output.empty()) output = "{\"ok\":false,\"error\":\"plugin DLL no devolvio resultado\"}";
    return rc == 0;
}

} // namespace dbg

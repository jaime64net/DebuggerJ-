#pragma once

#include <string>
#include <vector>
#include <cstdint>

#include "../../sdk/DebuggerJppPluginApi.h"

namespace dbg {

enum class PluginKind { Json, NativeDll };

// JSON declara flujos simples; una DLL nativa declara las mismas acciones y
// recibe una API C controlada del host al ejecutarse.
struct PluginAction {
    std::string id;
    std::string label;
    std::string description;
    std::string command;
    std::string argsJson;
    std::string inputSchema = "{\"type\":\"object\",\"properties\":{}}";
};

struct PluginManifest {
    std::string id;
    std::string name;
    std::string version;
    std::string description;
    std::string sourcePath;
    PluginKind kind = PluginKind::Json;
    uintptr_t nativeModule = 0;
    DbgPluginRunFn nativeRun = nullptr;
    bool enabled = true;
    std::vector<PluginAction> actions;
};

class PluginManager {
public:
    ~PluginManager();
    void load(const std::string& directory, bool loadNativeDlls);

    const std::vector<PluginManifest>& plugins() const { return plugins_; }
    const PluginManifest* find(const std::string& id) const;
    const PluginAction* findAction(const std::string& pluginId, const std::string& actionId) const;
    bool runNative(const PluginManifest& plugin, const std::string& actionId,
                   const std::string& argsJson, const DbgPluginHostApi& host, std::string& output) const;
    const std::vector<std::string>& errors() const { return errors_; }

private:
    void clear();
    std::vector<PluginManifest> plugins_;
    std::vector<std::string> errors_;
};

} // namespace dbg

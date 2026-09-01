#include "AiConfig.h"

#include <windows.h>
#include <fstream>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

namespace dbg {

const std::vector<AiPreset>& aiPresets() {
    static const std::vector<AiPreset> presets = {
        { "Anthropic",        ApiStyle::Anthropic, "api.anthropic.com", 443, true,  "/v1/messages", true, true,
          { "claude-fable-5", "claude-opus-5", "claude-sonnet-5", "claude-haiku-4-5-20251001" } },
        { "ChatGPT (OpenAI)", ApiStyle::OpenAI, "api.openai.com", 443, true,  "/v1/chat/completions", true, true,
          { "gpt-5", "gpt-5-mini", "gpt-4o", "gpt-4o-mini" } },
        { "DeepSeek",         ApiStyle::OpenAI, "api.deepseek.com", 443, true,  "/chat/completions", true, true,
          { "deepseek-chat", "deepseek-reasoner" } },
        { "Google Gemini",    ApiStyle::OpenAI, "generativelanguage.googleapis.com", 443, true,
          "/v1beta/openai/chat/completions", true, true,
          { "gemini-2.5-pro", "gemini-2.5-flash" } },
        { "xAI (Grok)",       ApiStyle::OpenAI, "api.x.ai", 443, true,  "/v1/chat/completions", true, true,
          { "grok-4", "grok-3", "grok-3-mini" } },
        { "Mistral",          ApiStyle::OpenAI, "api.mistral.ai", 443, true,  "/v1/chat/completions", true, true,
          { "mistral-large-latest", "codestral-latest", "mistral-small-latest" } },
        { "Groq",             ApiStyle::OpenAI, "api.groq.com", 443, true,  "/openai/v1/chat/completions", true, true,
          { "llama-3.3-70b-versatile", "llama-3.1-8b-instant" } },
        { "OpenRouter",       ApiStyle::OpenAI, "openrouter.ai", 443, true,  "/api/v1/chat/completions", true, true,
          { "anthropic/claude-sonnet-4.5", "openai/gpt-5", "deepseek/deepseek-chat" } },
        { "Ollama (athena)",  ApiStyle::OpenAI, "100.121.36.106", 11434, false, "/v1/chat/completions", false, true,
          { "qwen2.5:3b" } },
        { "Ollama (local)",   ApiStyle::OpenAI, "127.0.0.1", 11434, false, "/v1/chat/completions", false, true,
          { "qwen2.5:3b", "llama3.2:3b" } },
        { "LM Studio (local)", ApiStyle::OpenAI, "127.0.0.1", 1234, false, "/v1/chat/completions", false, true,
          { } },
    };
    return presets;
}

static std::string configFilePath() {
    wchar_t exe[MAX_PATH] = {0};
    GetModuleFileNameW(nullptr, exe, MAX_PATH);
    std::wstring w(exe);
    auto pos = w.find_last_of(L"\\/");
    std::wstring dir = (pos == std::wstring::npos) ? L"." : w.substr(0, pos);
    std::wstring path = dir + L"\\ai_config.json";
    return std::string(path.begin(), path.end());
}

static AiAgent agentFromPreset(const AiPreset& p, const std::string& name,
                               const std::string& model, const std::string& key) {
    AiAgent a;
    a.name = name; a.style = p.style; a.host = p.host; a.port = p.port;
    a.https = p.https; a.path = p.path; a.model = model; a.apiKey = key;
    a.supportsTools = p.tools;
    return a;
}

void AiConfigStore::load() {
    agents_.clear();
    selected_ = -1;
    std::ifstream f(configFilePath());
    if (f) {
        try {
            json j = json::parse(f);
            for (auto& e : j.value("agents", json::array())) {
                AiAgent a;
                a.name   = e.value("name", "");
                a.style  = e.value("style", "openai") == "anthropic" ? ApiStyle::Anthropic : ApiStyle::OpenAI;
                a.host   = e.value("host", "");
                a.port   = e.value("port", 443);
                a.https  = e.value("https", true);
                a.path   = e.value("path", "/v1/chat/completions");
                a.apiKey = e.value("apiKey", "");
                a.model  = e.value("model", "");
                a.supportsTools = e.value("supportsTools", true);
                if (!a.name.empty()) agents_.push_back(a);
            }
            std::string sel = j.value("selected", "");
            for (int i = 0; i < (int)agents_.size(); ++i)
                if (agents_[i].name == sel) { selected_ = i; break; }
        } catch (...) { agents_.clear(); }
    }

    if (agents_.empty()) {
        // Primera vez: sembrar los agentes locales y los proveedores cloud cuyas
        // llaves esten disponibles en el entorno.
        char buf[512] = {0};
        DWORD n = GetEnvironmentVariableA("ANTHROPIC_API_KEY", buf, sizeof(buf));
        std::string anthropicKey = (n > 0 && n < sizeof(buf)) ? std::string(buf, n) : "";
        memset(buf, 0, sizeof(buf));
        n = GetEnvironmentVariableA("OPENAI_API_KEY", buf, sizeof(buf));
        std::string openaiKey = (n > 0 && n < sizeof(buf)) ? std::string(buf, n) : "";
        const auto& ps = aiPresets();
        agents_.push_back(agentFromPreset(ps[0], "Claude (Anthropic)", "claude-opus-5", anthropicKey));
        agents_.push_back(agentFromPreset(ps[1], "ChatGPT (OpenAI)", "gpt-5", openaiKey));
        agents_.push_back(agentFromPreset(ps[8], "Qwen (athena)", "qwen2.5:3b", ""));
        selected_ = !anthropicKey.empty() ? 0 : (!openaiKey.empty() ? 1 : 2);
        save();
    }
    // Actualiza configuraciones creadas antes de que ChatGPT fuera un agente
    // predeterminado. No sobrescribimos una configuracion OpenAI existente.
    bool hasOpenAI = false;
    for (const auto& a : agents_) if (a.host == "api.openai.com") { hasOpenAI = true; break; }
    if (!hasOpenAI) {
        char buf[512] = {0};
        DWORD n = GetEnvironmentVariableA("OPENAI_API_KEY", buf, sizeof(buf));
        std::string key = (n > 0 && n < sizeof(buf)) ? std::string(buf, n) : "";
        agents_.push_back(agentFromPreset(aiPresets()[1], "ChatGPT (OpenAI)", "gpt-5", key));
        save();
    }
    if (selected_ < 0 || selected_ >= (int)agents_.size()) selected_ = 0;
}

void AiConfigStore::save() {
    json j;
    j["selected"] = (selected_ >= 0 && selected_ < (int)agents_.size()) ? agents_[selected_].name : "";
    json arr = json::array();
    for (auto& a : agents_) {
        arr.push_back({
            {"name",   a.name},
            {"style",  a.style == ApiStyle::Anthropic ? "anthropic" : "openai"},
            {"host",   a.host},
            {"port",   a.port},
            {"https",  a.https},
            {"path",   a.path},
            {"apiKey", a.apiKey},
            {"model",  a.model},
            {"supportsTools", a.supportsTools},
        });
    }
    j["agents"] = arr;
    std::ofstream f(configFilePath());
    if (f) f << j.dump(2);
}

void AiConfigStore::setSelected(int idx) {
    if (idx < 0 || idx >= (int)agents_.size()) return;
    if (idx == selected_) return;
    selected_ = idx;
    save();
}

const AiAgent* AiConfigStore::current() const {
    if (selected_ < 0 || selected_ >= (int)agents_.size()) return nullptr;
    return &agents_[selected_];
}

} // namespace dbg

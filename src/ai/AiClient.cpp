#include "AiClient.h"

#include <tuple>
#include <windows.h>
#include <winhttp.h>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

namespace dbg {

static std::wstring toW(const std::string& s) {
    if (s.empty()) return L"";
    int len = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    std::wstring w(len, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), w.data(), len);
    return w;
}

std::string AiClient::postJson(const std::string& payload, long& status, std::string& err) {
    status = 0;
    HINTERNET hSession = WinHttpOpen(L"DebuggerJ++/1.0",
        WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) { err = "WinHttpOpen fallo."; return ""; }

    HINTERNET hConnect = WinHttpConnect(hSession, toW(agent_.host).c_str(), (INTERNET_PORT)agent_.port, 0);
    if (!hConnect) { err = "WinHttpConnect fallo."; WinHttpCloseHandle(hSession); return ""; }

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", toW(agent_.path).c_str(),
        nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
        agent_.https ? WINHTTP_FLAG_SECURE : 0);
    if (!hRequest) { err = "WinHttpOpenRequest fallo."; WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return ""; }

    // Los modelos locales tardan; subir los timeouts (resolve/connect/send/receive, ms).
    WinHttpSetTimeouts(hRequest, 15000, 15000, 30000, 300000);

    std::wstring headers = L"content-type: application/json\r\n";
    if (agent_.style == ApiStyle::Anthropic) {
        headers += L"anthropic-version: 2023-06-01\r\n";
        headers += L"x-api-key: " + toW(agent_.apiKey) + L"\r\n";
    } else if (!agent_.apiKey.empty()) {
        headers += L"Authorization: Bearer " + toW(agent_.apiKey) + L"\r\n";
    }

    BOOL ok = WinHttpSendRequest(hRequest, headers.c_str(), (DWORD)-1L,
        (LPVOID)payload.data(), (DWORD)payload.size(), (DWORD)payload.size(), 0);
    if (ok) ok = WinHttpReceiveResponse(hRequest, nullptr);

    std::string response;
    if (ok) {
        DWORD avail = 0;
        do {
            avail = 0;
            if (!WinHttpQueryDataAvailable(hRequest, &avail) || avail == 0) break;
            std::string chunk(avail, '\0');
            DWORD read = 0;
            if (WinHttpReadData(hRequest, chunk.data(), avail, &read))
                response.append(chunk.data(), read);
        } while (avail > 0);
    } else {
        err = "Fallo en la peticion HTTP a " + agent_.host + ":" + std::to_string(agent_.port) +
              ", error " + std::to_string(GetLastError());
    }

    DWORD st = 0, sz = sizeof(st);
    WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX, &st, &sz, WINHTTP_NO_HEADER_INDEX);
    status = (long)st;

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return response;
}

// Extrae el mensaje de error de un cuerpo JSON de error (ambos estilos).
static std::string errorFromBody(const json& r, const std::string& raw) {
    if (r.contains("error")) {
        if (r["error"].is_object() && r["error"].contains("message"))
            return r["error"]["message"].get<std::string>();
        if (r["error"].is_string())
            return r["error"].get<std::string>();
    }
    return raw;
}

std::string AiClient::send(const std::string& systemPrompt,
                           const std::vector<ChatMessage>& history,
                           int maxTokens, std::string& err) {
    if (agent_.host.empty())  { err = "No hay agente de IA configurado (Tools -> Options -> AI)."; return ""; }
    if (agent_.model.empty()) { err = "El agente '" + agent_.name + "' no tiene modelo asignado."; return ""; }

    json body;
    body["model"] = agent_.model;
    json msgs = json::array();
    if (agent_.style == ApiStyle::Anthropic) {
        body["max_tokens"] = maxTokens;
        if (!systemPrompt.empty()) body["system"] = systemPrompt;
    } else {
        if (!systemPrompt.empty()) msgs.push_back({{"role", "system"}, {"content", systemPrompt}});
    }
    for (const auto& m : history)
        msgs.push_back({{"role", m.role}, {"content", m.content}});
    body["messages"] = msgs;

    long status = 0;
    std::string response = postJson(body.dump(), status, err);
    if (response.empty()) { if (err.empty()) err = "Respuesta vacia."; return ""; }

    try {
        json r = json::parse(response);
        if (status != 200) { err = "HTTP " + std::to_string(status) + ": " + errorFromBody(r, response); return ""; }
        std::string out;
        if (agent_.style == ApiStyle::Anthropic) {
            if (r.contains("content") && r["content"].is_array())
                for (auto& block : r["content"])
                    if (block.value("type", "") == "text") out += block.value("text", "");
            if (r.value("stop_reason", "") == "refusal")
                out += "\n\n[El modelo declino responder (refusal).]";
        } else {
            if (r.contains("choices") && r["choices"].is_array() && !r["choices"].empty()) {
                auto& msg = r["choices"][0]["message"];
                if (msg.contains("content") && msg["content"].is_string())
                    out = msg["content"].get<std::string>();
            }
        }
        if (out.empty()) err = "La respuesta no trae texto.";
        return out;
    } catch (const std::exception& e) {
        err = std::string("No se pudo parsear la respuesta: ") + e.what();
        return "";
    }
}

// Arma el arreglo de tools en el formato que espera cada estilo de API.
static json toolsForStyle(ApiStyle style, const std::vector<ToolDef>& tools) {
    json arr = json::array();
    for (const auto& t : tools) {
        json schema;
        try { schema = json::parse(t.paramsSchema); }
        catch (...) { schema = json::object(); schema["type"] = "object"; }
        if (style == ApiStyle::Anthropic) {
            arr.push_back({{"name", t.name}, {"description", t.description}, {"input_schema", schema}});
        } else {
            arr.push_back({{"type", "function"},
                           {"function", {{"name", t.name}, {"description", t.description}, {"parameters", schema}}}});
        }
    }
    return arr;
}

std::string AiClient::runAgent(const std::string& systemPrompt,
                               const std::vector<ChatMessage>& history,
                               const std::string& userMsg,
                               const std::vector<ToolDef>& tools,
                               int maxTokens, int maxIters,
                               const AiCallbacks& cb, std::string& err) {
    if (agent_.host.empty())  { err = "No hay agente de IA configurado (Tools -> Options -> AI)."; return ""; }
    if (agent_.model.empty()) { err = "El agente '" + agent_.name + "' no tiene modelo asignado."; return ""; }

    const bool anthropic = (agent_.style == ApiStyle::Anthropic);
    json toolsArr = toolsForStyle(agent_.style, tools);

    // Semilla del historial (mensajes de texto previos + el nuevo del usuario).
    json msgs = json::array();
    if (!anthropic && !systemPrompt.empty())
        msgs.push_back({{"role", "system"}, {"content", systemPrompt}});
    for (const auto& m : history)
        msgs.push_back({{"role", m.role}, {"content", m.content}});
    msgs.push_back({{"role", "user"}, {"content", userMsg}});

    std::string lastText;
    for (int iter = 0; iter < maxIters; ++iter) {
        if (cb.cancelled && cb.cancelled()) { err = "cancelado"; return lastText; }

        json body;
        body["model"] = agent_.model;
        body["messages"] = msgs;
        body["tools"] = toolsArr;
        if (anthropic) {
            body["max_tokens"] = maxTokens;
            if (!systemPrompt.empty()) body["system"] = systemPrompt;
        } else {
            body["tool_choice"] = "auto";
        }

        long status = 0;
        std::string response = postJson(body.dump(), status, err);
        if (response.empty()) { if (err.empty()) err = "Respuesta vacia."; return lastText; }

        json r;
        try { r = json::parse(response); }
        catch (const std::exception& e) { err = std::string("No se pudo parsear la respuesta: ") + e.what(); return lastText; }
        if (status != 200) { err = "HTTP " + std::to_string(status) + ": " + errorFromBody(r, response); return lastText; }

        if (anthropic) {
            // Recolectar bloques de texto y de tool_use.
            std::string text;
            std::vector<std::tuple<std::string,std::string,json>> calls; // id, name, input
            if (r.contains("content") && r["content"].is_array()) {
                for (auto& b : r["content"]) {
                    std::string type = b.value("type", "");
                    if (type == "text") text += b.value("text", "");
                    else if (type == "tool_use")
                        calls.emplace_back(b.value("id",""), b.value("name",""), b.value("input", json::object()));
                }
            }
            if (!text.empty()) lastText = text;
            if (calls.empty() || r.value("stop_reason","") != "tool_use") return text.empty() ? lastText : text;

            if (!text.empty() && cb.onEvent) cb.onEvent("text", text);
            msgs.push_back({{"role", "assistant"}, {"content", r["content"]}});
            json toolResults = json::array();
            for (auto& [id, name, input] : calls) {
                std::string argsJson = input.dump();
                std::string result = cb.execTool ? cb.execTool(name, argsJson) : "{\"ok\":false,\"error\":\"sin ejecutor\"}";
                if (cb.onEvent) cb.onEvent("tool", name + " " + argsJson + " -> " + result);
                toolResults.push_back({{"type","tool_result"}, {"tool_use_id", id}, {"content", result}});
            }
            msgs.push_back({{"role", "user"}, {"content", toolResults}});
        } else {
            if (!(r.contains("choices") && r["choices"].is_array() && !r["choices"].empty())) {
                err = "Respuesta sin choices."; return lastText;
            }
            json msg = r["choices"][0]["message"];
            std::string text = (msg.contains("content") && msg["content"].is_string()) ? msg["content"].get<std::string>() : "";
            if (!text.empty()) lastText = text;

            if (!msg.contains("tool_calls") || !msg["tool_calls"].is_array() || msg["tool_calls"].empty())
                return text;   // respuesta final

            if (!text.empty() && cb.onEvent) cb.onEvent("text", text);
            msgs.push_back(msg);   // el mensaje del asistente con sus tool_calls, verbatim
            for (auto& tc : msg["tool_calls"]) {
                std::string id   = tc.value("id", "");
                std::string name = tc.contains("function") ? tc["function"].value("name", "") : "";
                std::string argsJson = tc.contains("function") ? tc["function"].value("arguments", "{}") : "{}";
                if (argsJson.empty()) argsJson = "{}";
                std::string result = cb.execTool ? cb.execTool(name, argsJson) : "{\"ok\":false,\"error\":\"sin ejecutor\"}";
                if (cb.onEvent) cb.onEvent("tool", name + " " + argsJson + " -> " + result);
                msgs.push_back({{"role","tool"}, {"tool_call_id", id}, {"content", result}});
            }
        }
    }
    err = "Se agoto el maximo de iteraciones (" + std::to_string(maxIters) + ").";
    return lastText;
}

} // namespace dbg

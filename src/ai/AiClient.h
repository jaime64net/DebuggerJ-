#pragma once
#include <functional>
#include <string>
#include <vector>

// Cliente generico de chat-completions sobre WinHTTP, con tool-calling.
// Soporta dos estilos de API:
//   - Anthropic : POST /v1/messages (header x-api-key + anthropic-version)
//   - OpenAI    : POST /v1/chat/completions (header Authorization: Bearer)
// El estilo OpenAI cubre OpenAI, DeepSeek, Groq, Mistral, xAI, OpenRouter,
// Gemini (endpoint compatible) y servidores locales como Ollama o LM Studio.

namespace dbg {

struct ChatMessage {
    std::string role;    // "user" | "assistant"
    std::string content;
};

enum class ApiStyle { Anthropic = 0, OpenAI = 1 };

// Parametros completos de un agente configurado (ventana Tools/Options -> AI).
struct AiAgent {
    std::string name;                 // nombre visible del agente
    ApiStyle    style = ApiStyle::OpenAI;
    std::string host;                 // dominio o IP (sin esquema)
    int         port  = 443;
    bool        https = true;
    std::string path  = "/v1/chat/completions";
    std::string apiKey;               // vacia para servidores locales
    std::string model;
    bool        supportsTools = true; // el modelo soporta function calling
};

// Definicion neutral de una herramienta que el agente puede invocar.
// paramsSchema es un objeto JSON-schema (como string) con type/properties/required.
struct ToolDef {
    std::string name;
    std::string description;
    std::string paramsSchema;
};

// Callbacks del bucle agentico. Corren en el hilo de la IA.
struct AiCallbacks {
    // Ejecuta una tool y devuelve su resultado (JSON como string).
    std::function<std::string(const std::string& name, const std::string& argsJson)> execTool;
    // Notifica al UI un evento intermedio (texto del modelo o accion de tool).
    std::function<void(const std::string& kind, const std::string& text)> onEvent;
    // Devuelve true si hay que abortar el bucle.
    std::function<bool()> cancelled;
};

class AiClient {
public:
    void setAgent(const AiAgent& a) { agent_ = a; }
    const AiAgent& agent() const { return agent_; }
    bool configured() const { return !agent_.host.empty() && !agent_.model.empty(); }

    // Chat simple (sin tools). Bloqueante: llamalo desde un hilo de trabajo.
    std::string send(const std::string& systemPrompt,
                     const std::vector<ChatMessage>& history,
                     int maxTokens, std::string& err);

    // Bucle agentico: el modelo puede pedir tools; se ejecutan y se le
    // devuelven los resultados hasta que responde texto final (o se agota
    // maxIters). Devuelve el texto final. Bloqueante.
    std::string runAgent(const std::string& systemPrompt,
                         const std::vector<ChatMessage>& history,
                         const std::string& userMsg,
                         const std::vector<ToolDef>& tools,
                         int maxTokens, int maxIters,
                         const AiCallbacks& cb, std::string& err);

private:
    // POST del payload al endpoint del agente. Devuelve el body de respuesta;
    // 'status' recibe el codigo HTTP. 'err' se llena en caso de fallo de red.
    std::string postJson(const std::string& payload, long& status, std::string& err);

    AiAgent agent_;
};

} // namespace dbg

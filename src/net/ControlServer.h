#pragma once
#include <atomic>
#include <cstdint>
#include <functional>
#include <string>
#include <thread>

// Servidor TCP local: recibe una peticion JSON por linea y responde con una linea
// JSON. Lo consume el servidor MCP para que Claude controle el debugger.
// El dispatch corre en el hilo de UI (via cola en App) para acceso seguro al estado.

namespace dbg {

class ControlServer {
public:
    using Dispatch = std::function<std::string(const std::string&)>;
    ~ControlServer();

    bool start(int port, bool bindAll, Dispatch d, std::string& err);
    void stop();

    bool running() const { return running_.load(); }
    int  port()    const { return port_; }
    int  clients() const { return clients_.load(); }

private:
    void acceptLoop();
    void handleClient(uintptr_t sock);

    Dispatch          dispatch_;
    std::thread       acceptThread_;
    std::atomic<bool> running_{false};
    std::atomic<int>  clients_{0};
    uintptr_t         listenSock_ = (uintptr_t)~0ull;
    int               port_ = 0;
    bool              wsaUp_ = false;
};

} // namespace dbg

#include "ControlServer.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <string>

namespace dbg {

ControlServer::~ControlServer() { stop(); }

bool ControlServer::start(int port, bool bindAll, Dispatch d, std::string& err) {
    if (running_.load()) { err = "El servidor ya esta corriendo."; return false; }
    dispatch_ = std::move(d);
    port_ = port;

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) { err = "WSAStartup fallo."; return false; }
    wsaUp_ = true;

    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) { err = "socket() fallo."; WSACleanup(); wsaUp_ = false; return false; }
    BOOL yes = TRUE;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char*)&yes, sizeof(yes));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons((u_short)port);
    addr.sin_addr.s_addr = bindAll ? INADDR_ANY : inet_addr("127.0.0.1");
    if (bind(s, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        err = "bind() fallo en el puerto " + std::to_string(port);
        closesocket(s); WSACleanup(); wsaUp_ = false; return false;
    }
    if (listen(s, 4) == SOCKET_ERROR) {
        err = "listen() fallo."; closesocket(s); WSACleanup(); wsaUp_ = false; return false;
    }
    listenSock_ = (uintptr_t)s;
    running_.store(true);
    acceptThread_ = std::thread([this]() { acceptLoop(); });
    return true;
}

void ControlServer::stop() {
    if (!running_.exchange(false)) { if (wsaUp_) { WSACleanup(); wsaUp_ = false; } return; }
    if (listenSock_ != (uintptr_t)~0ull) { closesocket((SOCKET)listenSock_); listenSock_ = (uintptr_t)~0ull; }
    if (acceptThread_.joinable()) acceptThread_.join();
    if (wsaUp_) { WSACleanup(); wsaUp_ = false; }
}

void ControlServer::acceptLoop() {
    while (running_.load()) {
        sockaddr_in cli{}; int len = sizeof(cli);
        SOCKET c = accept((SOCKET)listenSock_, (sockaddr*)&cli, &len);
        if (c == INVALID_SOCKET) { if (!running_.load()) break; continue; }
        std::thread([this, c]() { handleClient((uintptr_t)c); }).detach();
    }
}

void ControlServer::handleClient(uintptr_t sockV) {
    SOCKET sock = (SOCKET)sockV;
    clients_.fetch_add(1);
    std::string buf;
    char tmp[4096];
    while (running_.load()) {
        int n = recv(sock, tmp, sizeof(tmp), 0);
        if (n <= 0) break;
        buf.append(tmp, n);
        size_t nl;
        while ((nl = buf.find('\n')) != std::string::npos) {
            std::string line = buf.substr(0, nl);
            buf.erase(0, nl + 1);
            if (!line.empty() && line.back() == '\r') line.pop_back();
            if (line.empty()) continue;
            std::string resp = dispatch_ ? dispatch_(line) : "{\"ok\":false,\"error\":\"sin dispatch\"}";
            resp.push_back('\n');
            send(sock, resp.data(), (int)resp.size(), 0);
        }
    }
    closesocket(sock);
    clients_.fetch_sub(1);
}

} // namespace dbg

#include "DieClient.h"
#include <nlohmann/json.hpp>
#include <windows.h>
#include <algorithm>

namespace dbg {

static bool fileExistsW(const std::wstring& p) {
    if (p.empty()) return false;
    DWORD a = GetFileAttributesW(p.c_str());
    return a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY);
}

static std::wstring exeDirW() {
    wchar_t exe[MAX_PATH] = {};
    GetModuleFileNameW(nullptr, exe, MAX_PATH);
    std::wstring p(exe);
    auto pos = p.find_last_of(L"\\/");
    return pos == std::wstring::npos ? L"." : p.substr(0, pos);
}

static std::string wtoU8(const std::wstring& w) {
    if (w.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), nullptr, 0, nullptr, nullptr);
    std::string s(n, 0);
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), s.data(), n, nullptr, nullptr);
    return s;
}

std::wstring DieClient::locate(const std::wstring& override_) {
    if (fileExistsW(override_)) return override_;
    std::wstring dir = exeDirW();
    std::wstring c1 = dir + L"\\die\\diec.exe";
    if (fileExistsW(c1)) return c1;
    std::wstring c2 = dir + L"\\diec.exe";
    if (fileExistsW(c2)) return c2;
    wchar_t found[MAX_PATH] = {};
    if (SearchPathW(nullptr, L"diec", L".exe", MAX_PATH, found, nullptr)) return found;
    return L"";
}

// Ejecuta un proceso capturando su stdout/stderr en 'out'. Sin ventana de consola.
// La salida esperada (JSON de un archivo) es pequena (<64KB), asi que esperamos a
// que el proceso termine y luego drenamos el pipe sin bloquear.
static bool runCapture(std::wstring cmdline, std::string& out, DWORD timeoutMs, std::string& err) {
    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    HANDLE rd = nullptr, wr = nullptr;
    if (!CreatePipe(&rd, &wr, &sa, 0)) { err = "CreatePipe fallo"; return false; }
    SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = wr;
    si.hStdError  = wr;
    si.hStdInput  = nullptr;
    PROCESS_INFORMATION pi{};

    BOOL ok = CreateProcessW(nullptr, cmdline.data(), nullptr, nullptr, TRUE,
                             CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
    CloseHandle(wr); // el padre no escribe
    if (!ok) { CloseHandle(rd); err = "No se pudo ejecutar diec (CreateProcess)."; return false; }

    bool timedOut = false;
    if (WaitForSingleObject(pi.hProcess, timeoutMs) == WAIT_TIMEOUT) {
        TerminateProcess(pi.hProcess, 1);
        WaitForSingleObject(pi.hProcess, 2000);
        timedOut = true;
    }

    char buf[4096];
    for (;;) {
        DWORD avail = 0;
        if (!PeekNamedPipe(rd, nullptr, 0, nullptr, &avail, nullptr) || avail == 0) break;
        DWORD n = 0;
        DWORD want = avail < sizeof(buf) ? avail : (DWORD)sizeof(buf);
        if (!ReadFile(rd, buf, want, &n, nullptr) || n == 0) break;
        out.append(buf, n);
    }

    DWORD code = 0;
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(rd);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    if (timedOut) { err = "diec excedio el tiempo limite."; return false; }
    return true;
}

DieResult DieClient::analyze(const std::wstring& diecExe, const std::wstring& targetPath) {
    DieResult r;
    r.dieExe = wtoU8(diecExe);
    if (diecExe.empty()) { r.error = "diec.exe no encontrado."; return r; }
    if (!fileExistsW(targetPath)) { r.error = "El archivo objetivo no existe en disco."; return r; }

    std::wstring cmd = L"\"" + diecExe + L"\" -j \"" + targetPath + L"\"";
    std::string out, err;
    if (!runCapture(cmd, out, 20000, err)) {
        r.error = err.empty() ? "Fallo al ejecutar diec." : err;
        r.rawJson = out;
        return r;
    }
    r.rawJson = out;

    size_t b = out.find('{');
    if (b == std::string::npos) {
        r.error = "diec no devolvio JSON. Salida: " + out.substr(0, 200);
        return r;
    }

    auto pushVal = [&](const nlohmann::json& v) {
        if (!v.is_object()) return;
        DieDetect d;
        d.type    = v.value("type", "");
        d.name    = v.value("name", "");
        d.version = v.value("version", "");
        d.options = v.value("options", "");
        d.string  = v.value("string", "");
        if (d.name.empty() && !d.string.empty()) d.name = d.string;
        if (!d.type.empty() || !d.name.empty()) r.detects.push_back(std::move(d));
    };

    try {
        auto j = nlohmann::json::parse(out.substr(b));
        if (j.contains("detects") && j["detects"].is_array()) {
            for (auto& el : j["detects"]) {
                if (el.is_object()) {
                    if (r.filetype.empty()) r.filetype = el.value("filetype", "");
                    if (el.contains("values") && el["values"].is_array())
                        for (auto& v : el["values"]) pushVal(v);
                    else if (el.contains("detects") && el["detects"].is_array())
                        for (auto& v : el["detects"]) pushVal(v);
                    else if (el.contains("type") || el.contains("name"))
                        pushVal(el);
                } else if (el.is_array()) {
                    for (auto& v : el) pushVal(v);
                }
            }
        }
        r.ok = true;
    } catch (const std::exception& e) {
        r.error = std::string("JSON invalido de diec: ") + e.what();
    }
    return r;
}

} // namespace dbg

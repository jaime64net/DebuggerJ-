#include "Debugger.h"
#include "Disassembler.h"

#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <dbghelp.h>

namespace dbg {

static const uint8_t INT3 = 0xCC;

const char* protectToStr(uint32_t p) {
    switch (p & 0xFF) {
        case PAGE_NOACCESS:          return "----";
        case PAGE_READONLY:          return "R---";
        case PAGE_READWRITE:         return "RW--";
        case PAGE_WRITECOPY:         return "RWC-";
        case PAGE_EXECUTE:           return "--X-";
        case PAGE_EXECUTE_READ:      return "R-X-";
        case PAGE_EXECUTE_READWRITE: return "RWX-";
        case PAGE_EXECUTE_WRITECOPY: return "RWXC";
        default:                     return "????";
    }
}
const char* memTypeToStr(uint32_t t) {
    switch (t) {
        case MEM_IMAGE:   return "IMG";
        case MEM_MAPPED:  return "MAP";
        case MEM_PRIVATE: return "PRV";
        default:          return "   ";
    }
}

Debugger::Debugger() {}
Debugger::~Debugger() { detachAndStop(); }

void Debugger::setState(DbgState s) {
    state_.store(s);
    if (cb_.onState) cb_.onState(s);
}
void Debugger::log(const std::string& m) { if (cb_.onLog) cb_.onLog(m); }

// ---------------------------------------------------------------------------
// Lanzamiento / attach. El hilo worker es el DUENO del debuggee: crea el
// proceso y es el unico que llama a WaitForDebugEvent/ContinueDebugEvent.
// ---------------------------------------------------------------------------
bool Debugger::launch(const std::wstring& exePath, const std::wstring& args, std::string& err) {
    if (state_.load() != DbgState::Idle) { err = "Ya hay una sesion activa."; return false; }
    quit_.store(false);
    attached_ = false;
    std::wstring cmd = L"\"" + exePath + L"\"";
    if (!args.empty()) cmd += L" " + args;

    setState(DbgState::Launching);
    worker_ = std::thread([this, exePath, cmd]() {
        STARTUPINFOW si{}; si.cb = sizeof(si);
        PROCESS_INFORMATION pi{};
        std::wstring cmdMut = cmd;
        BOOL ok = CreateProcessW(exePath.c_str(), cmdMut.data(), nullptr, nullptr, FALSE,
                                 DEBUG_ONLY_THIS_PROCESS | CREATE_NEW_CONSOLE,
                                 nullptr, nullptr, &si, &pi);
        if (!ok) {
            log("CreateProcess fallo, error " + std::to_string(GetLastError()));
            setState(DbgState::Exited);
            return;
        }
        hProcess_ = pi.hProcess;
        pid_ = pi.dwProcessId;
        log("Proceso lanzado, PID " + std::to_string(pid_));
        debugLoop();
        CloseHandle(pi.hThread);
    });
    return true;
}

bool Debugger::attach(uint32_t pid, std::string& err) {
    if (state_.load() != DbgState::Idle) { err = "Ya hay una sesion activa."; return false; }
    quit_.store(false);
    attached_ = true;
    pid_ = pid;
    setState(DbgState::Launching);
    worker_ = std::thread([this, pid]() {
        if (!DebugActiveProcess(pid)) {
            log("DebugActiveProcess fallo, error " + std::to_string(GetLastError()));
            setState(DbgState::Exited);
            return;
        }
        hProcess_ = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        log("Enganchado al PID " + std::to_string(pid));
        debugLoop();
    });
    return true;
}

void Debugger::detachAndStop() {
    quit_.store(true);
    pending_.store(Cmd::Stop);
    resumeSignaled_.store(true);
    if (worker_.joinable()) worker_.join();
    if (symReady_ && hProcess_) { SymCleanup(hProcess_); symReady_ = false; }
    if (hProcess_) { CloseHandle(hProcess_); hProcess_ = nullptr; }
    state_.store(DbgState::Idle);
}

std::string Debugger::symbolAt(uint64_t va) {
    if (!symReady_ || !hProcess_ || !va) return "";
    char buf[sizeof(SYMBOL_INFO) + 256] = {0};
    PSYMBOL_INFO si = (PSYMBOL_INFO)buf;
    si->SizeOfStruct = sizeof(SYMBOL_INFO);
    si->MaxNameLen = 255;
    DWORD64 disp = 0;
    if (!SymFromAddr(hProcess_, va, &disp, si)) return "";
    std::string s;
    IMAGEHLP_MODULE64 mi{}; mi.SizeOfStruct = sizeof(mi);
    if (SymGetModuleInfo64(hProcess_, va, &mi)) { s = mi.ModuleName; s += "!"; }
    s += si->Name;
    if (disp) { char d[32]; sprintf_s(d, "+0x%llX", (unsigned long long)disp); s += d; }
    return s;
}

std::vector<std::pair<uint64_t, uint64_t>> Debugger::sehChain() {
    std::vector<std::pair<uint64_t, uint64_t>> out;
    if (is64_ || !pid_ || !curTid_) return out; // cadena FS:[0] solo en x86
    HANDLE h = OpenThread(THREAD_QUERY_INFORMATION, FALSE, curTid_);
    if (!h) return out;
    typedef LONG(NTAPI * Fn)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    auto f = (Fn)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationThread");
    struct TBI { LONG ExitStatus; PVOID TebBaseAddress; struct { HANDLE p, t; } Cid;
                 ULONG_PTR Aff; LONG Prio, BasePrio; } tbi{};
    uint64_t teb = 0;
    if (f && f(h, 0, &tbi, sizeof(tbi), nullptr) == 0) teb = (uint64_t)tbi.TebBaseAddress;
    CloseHandle(h);
    if (!teb) return out;
    uint32_t node = 0; readMemory(teb, &node, 4); // TEB.NtTib.ExceptionList (offset 0)
    for (int i = 0; i < 64 && node && node != 0xFFFFFFFF; ++i) {
        uint32_t prev = 0, handler = 0;
        readMemory(node, &prev, 4);
        readMemory(node + 4, &handler, 4);
        out.push_back({ node, handler });
        if (prev <= node) break;
        node = prev;
    }
    return out;
}

// ---------------------------------------------------------------------------
// Controles
// ---------------------------------------------------------------------------
void Debugger::go()       { pending_.store(Cmd::Go);       resumeSignaled_.store(true); }
void Debugger::stepInto() { pending_.store(Cmd::StepInto); resumeSignaled_.store(true); }
void Debugger::stepOver() { pending_.store(Cmd::StepOver); resumeSignaled_.store(true); }
void Debugger::stepToRet(){ pending_.store(Cmd::StepToRet);resumeSignaled_.store(true); }
void Debugger::runTrace() {
    { std::lock_guard<std::mutex> lk(traceMutex_); traceLog_.clear(); }
    pending_.store(Cmd::RunTrace); resumeSignaled_.store(true);
}
std::vector<uint64_t> Debugger::traceLog() {
    std::lock_guard<std::mutex> lk(traceMutex_);
    return traceLog_;
}
void Debugger::findOEP(uint64_t stubLo, uint64_t stubHi, uint64_t imgLo, uint64_t imgHi) {
    oepStubLo_ = stubLo; oepStubHi_ = stubHi; oepImgLo_ = imgLo; oepImgHi_ = imgHi;
    foundOEP_ = 0; oepSteps_ = 0;
    pending_.store(Cmd::FindOEP); resumeSignaled_.store(true);
}
void Debugger::pause()    { pending_.store(Cmd::Pause); }   // se atiende en el loop
void Debugger::stop()     { quit_.store(true); pending_.store(Cmd::Stop); resumeSignaled_.store(true); }
void Debugger::rewind() {
    if (history_.size() >= 2) {
        history_.pop_back();
        log("Rewind logico -> ultimo breakpoint 0x" + std::to_string(history_.back()));
    } else {
        log("Rewind: no hay historial suficiente (esto no revierte la ejecucion, es navegacion).");
    }
}

// ---------------------------------------------------------------------------
// Breakpoints
// ---------------------------------------------------------------------------
bool Debugger::addBreakpoint(uint64_t va, const std::string& label) {
    std::lock_guard<std::mutex> lk(bpMutex_);
    Breakpoint bp; bp.address = va; bp.label = label; bp.enabled = true;
    auto [it, inserted] = bps_.emplace(va, bp);
    if (!inserted) return false;
    if (state_.load() == DbgState::Paused || state_.load() == DbgState::Running)
        installBreakpoint(it->second);
    log("Breakpoint agregado en 0x" + [&]{ char b[32]; sprintf_s(b,"%llX",(unsigned long long)va); return std::string(b);}());
    return true;
}
bool Debugger::removeBreakpoint(uint64_t va) {
    std::lock_guard<std::mutex> lk(bpMutex_);
    auto it = bps_.find(va);
    if (it == bps_.end()) return false;
    uninstallBreakpoint(it->second);
    bps_.erase(it);
    return true;
}
void Debugger::toggleBreakpoint(uint64_t va, bool enabled) {
    std::lock_guard<std::mutex> lk(bpMutex_);
    auto it = bps_.find(va);
    if (it == bps_.end()) return;
    it->second.enabled = enabled;
    if (enabled) installBreakpoint(it->second);
    else uninstallBreakpoint(it->second);
}
std::vector<Breakpoint> Debugger::breakpoints() {
    std::lock_guard<std::mutex> lk(bpMutex_);
    std::vector<Breakpoint> v;
    for (auto& [k, b] : bps_) v.push_back(b);
    return v;
}
uint32_t Debugger::addExceptionBreak(uint32_t code, uint64_t address, const std::string& label) {
    std::lock_guard<std::mutex> lk(excMutex_);
    ExceptionBreak e; e.id = nextExcId_++; e.code = code; e.address = address; e.label = label;
    excBreaks_.push_back(e);
    char b[96]; sprintf_s(b, "Exception BP #%u (code 0x%08X) agregado", e.id, code);
    log(b);
    return e.id;
}
void Debugger::removeExceptionBreak(uint32_t id) {
    std::lock_guard<std::mutex> lk(excMutex_);
    for (auto it = excBreaks_.begin(); it != excBreaks_.end(); ++it)
        if (it->id == id) { excBreaks_.erase(it); return; }
}
void Debugger::toggleExceptionBreak(uint32_t id, bool enabled) {
    std::lock_guard<std::mutex> lk(excMutex_);
    for (auto& e : excBreaks_) if (e.id == id) { e.enabled = enabled; return; }
}
std::vector<ExceptionBreak> Debugger::exceptionBreaks() {
    std::lock_guard<std::mutex> lk(excMutex_);
    return excBreaks_;
}

// --------- Hardware breakpoints (DR0-DR3) ---------
static uint32_t readDr6(HANDLE h, bool is64) {
    if (is64) { CONTEXT c{}; c.ContextFlags = CONTEXT_DEBUG_REGISTERS; if (GetThreadContext(h, &c)) return (uint32_t)c.Dr6; }
    else { WOW64_CONTEXT c{}; c.ContextFlags = WOW64_CONTEXT_DEBUG_REGISTERS; if (Wow64GetThreadContext(h, &c)) return c.Dr6; }
    return 0;
}
static void clearDr6(HANDLE h, bool is64) {
    if (is64) { CONTEXT c{}; c.ContextFlags = CONTEXT_DEBUG_REGISTERS; if (GetThreadContext(h, &c)) { c.Dr6 = 0; SetThreadContext(h, &c); } }
    else { WOW64_CONTEXT c{}; c.ContextFlags = WOW64_CONTEXT_DEBUG_REGISTERS; if (Wow64GetThreadContext(h, &c)) { c.Dr6 = 0; Wow64SetThreadContext(h, &c); } }
}
static void setResumeFlag(HANDLE h, bool is64) {
    if (is64) { CONTEXT c{}; c.ContextFlags = CONTEXT_CONTROL; if (GetThreadContext(h, &c)) { c.EFlags |= 0x10000; SetThreadContext(h, &c); } }
    else { WOW64_CONTEXT c{}; c.ContextFlags = WOW64_CONTEXT_CONTROL; if (Wow64GetThreadContext(h, &c)) { c.EFlags |= 0x10000; Wow64SetThreadContext(h, &c); } }
}
static uint64_t buildDr7(const HwBreakpoint bps[4], uint64_t drOut[4]) {
    uint64_t dr7 = 0;
    for (int i = 0; i < 4; ++i) {
        drOut[i] = 0;
        if (!bps[i].address || !bps[i].enabled) continue;
        drOut[i] = bps[i].address;
        dr7 |= (1ull << (i * 2));                       // Local enable
        int rw = bps[i].type & 3;                       // 0 exec,1 write,3 rw
        int lenBits = 0;
        if (rw != 0) { int L = bps[i].len; lenBits = (L == 2) ? 1 : (L == 8) ? 2 : (L == 4) ? 3 : 0; }
        dr7 |= ((uint64_t)rw << (16 + i * 4));
        dr7 |= ((uint64_t)lenBits << (18 + i * 4));
    }
    return dr7;
}
void Debugger::applyHwToThread(void* hThreadV) {
    HANDLE h = (HANDLE)hThreadV;
    uint64_t dr[4]; uint64_t dr7;
    { std::lock_guard<std::mutex> lk(hwMutex_); dr7 = buildDr7(hwBps_, dr); }
    if (is64_) {
        CONTEXT c{}; c.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        if (!GetThreadContext(h, &c)) return;
        c.Dr0 = dr[0]; c.Dr1 = dr[1]; c.Dr2 = dr[2]; c.Dr3 = dr[3]; c.Dr6 = 0; c.Dr7 = dr7;
        SetThreadContext(h, &c);
    } else {
        WOW64_CONTEXT c{}; c.ContextFlags = WOW64_CONTEXT_DEBUG_REGISTERS;
        if (!Wow64GetThreadContext(h, &c)) return;
        c.Dr0 = (DWORD)dr[0]; c.Dr1 = (DWORD)dr[1]; c.Dr2 = (DWORD)dr[2]; c.Dr3 = (DWORD)dr[3];
        c.Dr6 = 0; c.Dr7 = (DWORD)dr7;
        Wow64SetThreadContext(h, &c);
    }
}
void Debugger::applyHwToAllThreads() {
    if (!pid_) return;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return;
    THREADENTRY32 te{}; te.dwSize = sizeof(te);
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID != pid_) continue;
            HANDLE h = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
            if (h) { SuspendThread(h); applyHwToThread(h); ResumeThread(h); CloseHandle(h); }
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
}
bool Debugger::addHwBreakpoint(uint64_t address, int type, int len, const std::string& label) {
    { std::lock_guard<std::mutex> lk(hwMutex_);
      for (auto& b : hwBps_) if (b.address == address) return false;
      int slot = -1; for (int i = 0; i < 4; ++i) if (!hwBps_[i].address) { slot = i; break; }
      if (slot < 0) return false;
      HwBreakpoint b; b.address = address; b.slot = slot; b.type = type; b.len = len; b.label = label;
      hwBps_[slot] = b;
    }
    if (state_.load() == DbgState::Paused || state_.load() == DbgState::Running) applyHwToAllThreads();
    log("Hardware BP en 0x" + [&]{char x[24];sprintf_s(x,"%llX",(unsigned long long)address);return std::string(x);}());
    return true;
}
bool Debugger::removeHwBreakpoint(uint64_t address) {
    bool found = false;
    { std::lock_guard<std::mutex> lk(hwMutex_);
      for (auto& b : hwBps_) if (b.address == address) { b = HwBreakpoint(); found = true; } }
    if (found && (state_.load() == DbgState::Paused || state_.load() == DbgState::Running)) applyHwToAllThreads();
    return found;
}
std::vector<HwBreakpoint> Debugger::hwBreakpoints() {
    std::lock_guard<std::mutex> lk(hwMutex_);
    std::vector<HwBreakpoint> v;
    for (auto& b : hwBps_) if (b.address) v.push_back(b);
    return v;
}

void Debugger::installBreakpoint(Breakpoint& bp) {
    if (bp.installed || !bp.enabled || !hProcess_) return;
    uint8_t orig = 0; SIZE_T rd = 0;
    if (!ReadProcessMemory(hProcess_, (LPCVOID)bp.address, &orig, 1, &rd) || rd != 1) return;
    bp.original = orig;
    SIZE_T wr = 0;
    if (WriteProcessMemory(hProcess_, (LPVOID)bp.address, &INT3, 1, &wr) && wr == 1) {
        FlushInstructionCache(hProcess_, (LPCVOID)bp.address, 1);
        bp.installed = true;
    }
}
void Debugger::uninstallBreakpoint(Breakpoint& bp) {
    if (!bp.installed || !hProcess_) return;
    SIZE_T wr = 0;
    WriteProcessMemory(hProcess_, (LPVOID)bp.address, &bp.original, 1, &wr);
    FlushInstructionCache(hProcess_, (LPCVOID)bp.address, 1);
    bp.installed = false;
}

// ---------------------------------------------------------------------------
// Contexto de registros (maneja 64 bits nativo y 32 bits WOW64)
// ---------------------------------------------------------------------------
static bool getCtx64(HANDLE hThread, CONTEXT& c) {
    c.ContextFlags = CONTEXT_ALL;
    return GetThreadContext(hThread, &c) != 0;
}
static bool getCtx32(HANDLE hThread, WOW64_CONTEXT& c) {
    c.ContextFlags = WOW64_CONTEXT_ALL;
    return Wow64GetThreadContext(hThread, &c) != 0;
}

Registers Debugger::registers() {
    Registers r; r.is64 = is64_;
    if (!hThread_) return r;
    if (is64_) {
        CONTEXT c{}; if (!getCtx64((HANDLE)hThread_, c)) return r;
        r.rax=c.Rax; r.rbx=c.Rbx; r.rcx=c.Rcx; r.rdx=c.Rdx; r.rsi=c.Rsi; r.rdi=c.Rdi;
        r.rbp=c.Rbp; r.rsp=c.Rsp; r.rip=c.Rip; r.r8=c.R8; r.r9=c.R9; r.r10=c.R10; r.r11=c.R11;
        r.r12=c.R12; r.r13=c.R13; r.r14=c.R14; r.r15=c.R15; r.eflags=(uint32_t)c.EFlags;
        r.cs=(uint16_t)c.SegCs; r.ds=(uint16_t)c.SegDs; r.es=(uint16_t)c.SegEs;
        r.fs=(uint16_t)c.SegFs; r.gs=(uint16_t)c.SegGs; r.ss=(uint16_t)c.SegSs;
    } else {
        WOW64_CONTEXT c{}; if (!getCtx32((HANDLE)hThread_, c)) return r;
        r.rax=c.Eax; r.rbx=c.Ebx; r.rcx=c.Ecx; r.rdx=c.Edx; r.rsi=c.Esi; r.rdi=c.Edi;
        r.rbp=c.Ebp; r.rsp=c.Esp; r.rip=c.Eip; r.eflags=c.EFlags;
        r.cs=(uint16_t)c.SegCs; r.ds=(uint16_t)c.SegDs; r.es=(uint16_t)c.SegEs;
        r.fs=(uint16_t)c.SegFs; r.gs=(uint16_t)c.SegGs; r.ss=(uint16_t)c.SegSs;
    }
    return r;
}

bool Debugger::setRegister(const std::string& name, uint64_t value) {
    if (!hThread_) return false;
    auto lname = name;
    for (auto& ch : lname) ch = (char)tolower((unsigned char)ch);
    if (is64_) {
        CONTEXT c{}; if (!getCtx64((HANDLE)hThread_, c)) return false;
        if      (lname=="rax") c.Rax=value; else if (lname=="rbx") c.Rbx=value;
        else if (lname=="rcx") c.Rcx=value; else if (lname=="rdx") c.Rdx=value;
        else if (lname=="rsi") c.Rsi=value; else if (lname=="rdi") c.Rdi=value;
        else if (lname=="rbp") c.Rbp=value; else if (lname=="rsp") c.Rsp=value;
        else if (lname=="rip") c.Rip=value; else if (lname=="r8") c.R8=value;
        else if (lname=="r9") c.R9=value;   else if (lname=="r10") c.R10=value;
        else if (lname=="r11") c.R11=value; else if (lname=="r12") c.R12=value;
        else if (lname=="r13") c.R13=value; else if (lname=="r14") c.R14=value;
        else if (lname=="r15") c.R15=value; else if (lname=="eflags") c.EFlags=(DWORD)value;
        else return false;
        return SetThreadContext((HANDLE)hThread_, &c) != 0;
    } else {
        WOW64_CONTEXT c{}; if (!getCtx32((HANDLE)hThread_, c)) return false;
        if      (lname=="eax") c.Eax=(DWORD)value; else if (lname=="ebx") c.Ebx=(DWORD)value;
        else if (lname=="ecx") c.Ecx=(DWORD)value; else if (lname=="edx") c.Edx=(DWORD)value;
        else if (lname=="esi") c.Esi=(DWORD)value; else if (lname=="edi") c.Edi=(DWORD)value;
        else if (lname=="ebp") c.Ebp=(DWORD)value; else if (lname=="esp") c.Esp=(DWORD)value;
        else if (lname=="eip") c.Eip=(DWORD)value; else if (lname=="eflags") c.EFlags=(DWORD)value;
        else return false;
        return Wow64SetThreadContext((HANDLE)hThread_, &c) != 0;
    }
}

static void setTrapFlag(HANDLE hThread, bool is64) {
    if (is64) {
        CONTEXT c{}; c.ContextFlags = CONTEXT_CONTROL;
        if (GetThreadContext(hThread, &c)) { c.EFlags |= 0x100; SetThreadContext(hThread, &c); }
    } else {
        WOW64_CONTEXT c{}; c.ContextFlags = WOW64_CONTEXT_CONTROL;
        if (Wow64GetThreadContext(hThread, &c)) { c.EFlags |= 0x100; Wow64SetThreadContext(hThread, &c); }
    }
}
static void setIP(HANDLE hThread, bool is64, uint64_t ip) {
    if (is64) {
        CONTEXT c{}; c.ContextFlags = CONTEXT_CONTROL;
        if (GetThreadContext(hThread, &c)) { c.Rip = ip; SetThreadContext(hThread, &c); }
    } else {
        WOW64_CONTEXT c{}; c.ContextFlags = WOW64_CONTEXT_CONTROL;
        if (Wow64GetThreadContext(hThread, &c)) { c.Eip = (DWORD)ip; Wow64SetThreadContext(hThread, &c); }
    }
}

// ---------------------------------------------------------------------------
// Memoria
// ---------------------------------------------------------------------------
size_t Debugger::readMemory(uint64_t va, void* out, size_t len) {
    if (!hProcess_) return 0;
    SIZE_T rd = 0;
    ReadProcessMemory(hProcess_, (LPCVOID)va, out, len, &rd);
    // Enmascara los 0xCC de nuestros breakpoints con el byte original
    std::lock_guard<std::mutex> lk(bpMutex_);
    auto* bytes = (uint8_t*)out;
    for (auto& [addr, bp] : bps_) {
        if (bp.installed && addr >= va && addr < va + rd)
            bytes[addr - va] = bp.original;
    }
    return rd;
}
size_t Debugger::writeMemory(uint64_t va, const void* in, size_t len) {
    if (!hProcess_) return 0;
    SIZE_T wr = 0;
    WriteProcessMemory(hProcess_, (LPVOID)va, in, len, &wr);
    FlushInstructionCache(hProcess_, (LPCVOID)va, len);
    return wr;
}

std::vector<MemRegion> Debugger::memoryMap() {
    std::vector<MemRegion> out;
    if (!hProcess_) return out;
    MEMORY_BASIC_INFORMATION mbi{};
    uint64_t addr = 0;
    while (VirtualQueryEx(hProcess_, (LPCVOID)addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        if (mbi.State != MEM_FREE) {
            MemRegion r;
            r.base = (uint64_t)mbi.BaseAddress;
            r.size = (uint64_t)mbi.RegionSize;
            r.state = mbi.State;
            r.protect = mbi.Protect;
            r.type = mbi.Type;
            r.protectStr = protectToStr(mbi.Protect);
            r.typeStr = memTypeToStr(mbi.Type);
            if (mbi.Type == MEM_IMAGE) {
                wchar_t name[MAX_PATH] = {0};
                if (GetMappedFileNameW(hProcess_, mbi.BaseAddress, name, MAX_PATH)) {
                    std::wstring w(name);
                    auto pos = w.find_last_of(L"\\/");
                    std::wstring b = pos == std::wstring::npos ? w : w.substr(pos + 1);
                    r.moduleName.assign(b.begin(), b.end());
                }
            }
            out.push_back(std::move(r));
        }
        uint64_t next = (uint64_t)mbi.BaseAddress + (uint64_t)mbi.RegionSize;
        if (next <= addr) break;
        addr = next;
    }
    return out;
}

std::vector<LoadedModule> Debugger::modules() {
    std::lock_guard<std::mutex> lk(modMutex_);
    return modules_;
}

// ---------------------------------------------------------------------------
// Loop de depuracion
// ---------------------------------------------------------------------------
void Debugger::debugLoop() {
    Disassembler dis(true);
    DEBUG_EVENT ev{};
    bool firstBreakpoint = true;

    while (!quit_.load()) {
        if (!WaitForDebugEvent(&ev, 100)) {
            // Timeout: atender Pause pendiente
            if (pending_.load() == Cmd::Pause && state_.load() == DbgState::Running) {
                pending_.store(Cmd::None);
                DebugBreakProcess(hProcess_);
                log("Pausa solicitada...");
            }
            continue;
        }

        curTid_ = ev.dwThreadId;
        HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, ev.dwThreadId);
        hThread_ = hThread;
        DWORD continueStatus = DBG_CONTINUE;
        bool pauseUI = false;
        uint64_t breakVA = 0;

        switch (ev.dwDebugEventCode) {
        case CREATE_PROCESS_DEBUG_EVENT: {
            imageBase_ = (uint64_t)ev.u.CreateProcessInfo.lpBaseOfImage;
            entryPoint_ = (uint64_t)ev.u.CreateProcessInfo.lpStartAddress;
            BOOL wow = FALSE;
            IsWow64Process(hProcess_, &wow);
            is64_ = !wow; // en host x64: WOW64 => target de 32 bits
            dis.setMode(is64_);
            log(std::string("Imagen base 0x") + [&]{char b[32];sprintf_s(b,"%llX",(unsigned long long)imageBase_);return std::string(b);}()
                + (is64_ ? "  (64 bits)" : "  (32 bits)"));
            if (!symReady_) {
                SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_LOAD_LINES);
                if (SymInitialize(hProcess_, nullptr, TRUE)) symReady_ = true;
            }
            if (ev.u.CreateProcessInfo.hThread) applyHwToThread(ev.u.CreateProcessInfo.hThread);
            if (ev.u.CreateProcessInfo.hFile) CloseHandle(ev.u.CreateProcessInfo.hFile);
            break;
        }
        case CREATE_THREAD_DEBUG_EVENT: {
            if (ev.u.CreateThread.hThread) applyHwToThread(ev.u.CreateThread.hThread);
            break;
        }
        case LOAD_DLL_DEBUG_EVENT: {
            LoadedModule m; m.base = (uint64_t)ev.u.LoadDll.lpBaseOfDll;
            HANDLE hf = ev.u.LoadDll.hFile;
            if (hf) {
                wchar_t path[MAX_PATH] = {0};
                if (GetFinalPathNameByHandleW(hf, path, MAX_PATH, FILE_NAME_NORMALIZED)) {
                    std::wstring w(path);
                    if (w.rfind(L"\\\\?\\", 0) == 0) w = w.substr(4);
                    m.path.assign(w.begin(), w.end());
                    auto pos = w.find_last_of(L"\\/");
                    std::wstring b = pos == std::wstring::npos ? w : w.substr(pos + 1);
                    m.name.assign(b.begin(), b.end());
                }
                CloseHandle(hf);
            }
            { std::lock_guard<std::mutex> lk(modMutex_); modules_.push_back(m); }
            if (cb_.onModule) cb_.onModule(m);
            break;
        }
        case EXIT_PROCESS_DEBUG_EVENT:
            log("El proceso termino, codigo " + std::to_string(ev.u.ExitProcess.dwExitCode));
            setState(DbgState::Exited);
            if (hThread) CloseHandle(hThread);
            hThread_ = nullptr;
            return;
        case OUTPUT_DEBUG_STRING_EVENT:
            continueStatus = DBG_CONTINUE;
            break;
        case EXCEPTION_DEBUG_EVENT: {
            const EXCEPTION_RECORD& er = ev.u.Exception.ExceptionRecord;
            uint64_t addr = (uint64_t)er.ExceptionAddress;
            switch (er.ExceptionCode) {
            case EXCEPTION_BREAKPOINT: {
                if (firstBreakpoint) {
                    // Breakpoint del loader: instalar los BPs pendientes y pausar aqui.
                    firstBreakpoint = false;
                    { std::lock_guard<std::mutex> lk(bpMutex_);
                      for (auto& [k, b] : bps_) installBreakpoint(b); }
                    applyHwToAllThreads();
                    log("Breakpoint de sistema (loader). Pon breakpoints y dale Play.");
                    pauseUI = true; breakVA = addr;
                } else {
                    bool ours = false, wasOneShot = false;
                    { std::lock_guard<std::mutex> lk(bpMutex_);
                      auto it = bps_.find(addr);
                      if (it != bps_.end() && it->second.installed) {
                          ours = true; wasOneShot = it->second.oneShot;
                          uninstallBreakpoint(it->second);   // restaurar byte original
                          if (wasOneShot) bps_.erase(it);    // one-shot consumido
                          else pendingRearm_ = addr;         // re-armar tras el siguiente step
                      }
                    }
                    if (ours) {
                        setIP(hThread, is64_, addr);          // retroceder RIP al inicio del opcode
                        if ((runToRet_ || findOEP_) && wasOneShot) {
                            // retorno de un call saltado: seguir el modo sin pausar
                            if (findOEP_) findOEPStep(hThread, addr, &dis);
                            else          runToRetStep(hThread, addr, &dis);
                        } else {
                            pauseUI = true; breakVA = addr;
                            history_.push_back(addr);
                        }
                    } else {
                        // breakpoint no nuestro (p.ej. __debugbreak del propio programa)
                        pauseUI = true; breakVA = addr;
                        history_.push_back(addr);
                    }
                }
                break;
            }
            case EXCEPTION_SINGLE_STEP: {
                // Hardware breakpoint? DR6 bits 0-3 indican el slot.
                uint32_t dr6 = readDr6(hThread, is64_);
                int hwSlot = -1;
                { std::lock_guard<std::mutex> lk(hwMutex_);
                  for (int i = 0; i < 4; ++i)
                      if ((dr6 & (1u << i)) && hwBps_[i].address && hwBps_[i].enabled) { hwSlot = i; break; } }
                if (hwSlot >= 0) {
                    clearDr6(hThread, is64_);
                    { std::lock_guard<std::mutex> lk(hwMutex_); hwBps_[hwSlot].hits++; lastHwHit_ = hwBps_[hwSlot].address; }
                    runToRet_ = false; findOEP_ = false; singleStepping_ = false;
                    hwJustHit_ = true;
                    pauseUI = true; breakVA = addr; history_.push_back(addr);
                    { char b[64]; sprintf_s(b, "Hardware BP en 0x%llX", (unsigned long long)addr); log(b); }
                    break;
                }
                // Termino un single-step. Re-armar el BP si toca.
                if (pendingRearm_) {
                    std::lock_guard<std::mutex> lk(bpMutex_);
                    auto it = bps_.find(pendingRearm_);
                    if (it != bps_.end()) installBreakpoint(it->second);
                    pendingRearm_ = 0;
                }
                if (traceRun_) {
                    Cmd p = pending_.load();
                    if (quit_.load() || p == Cmd::Stop || p == Cmd::Pause) {
                        if (p == Cmd::Pause) pending_.store(Cmd::None);
                        traceRun_ = false; pauseUI = true; breakVA = addr;
                    } else {
                        size_t sz;
                        { std::lock_guard<std::mutex> lk(traceMutex_);
                          if (traceLog_.size() < traceMax_) traceLog_.push_back(addr);
                          sz = traceLog_.size(); }
                        if (sz >= traceMax_) { traceRun_ = false; pauseUI = true; breakVA = addr; log("Run-trace: limite alcanzado."); }
                        else setTrapFlag(hThread, is64_);
                    }
                } else if (findOEP_) {
                    Cmd p = pending_.load();
                    bool hop = (addr >= oepImgLo_ && addr < oepImgHi_ &&
                                !(addr >= oepStubLo_ && addr < oepStubHi_));
                    if (quit_.load() || p == Cmd::Stop) {
                        findOEP_ = false; pauseUI = true; breakVA = addr;
                    } else if (p == Cmd::Pause) {
                        pending_.store(Cmd::None);
                        findOEP_ = false; pauseUI = true; breakVA = addr;
                    } else if (hop) {
                        findOEP_ = false; foundOEP_ = addr;
                        pauseUI = true; breakVA = addr;
                        history_.push_back(addr);
                        char b[64]; sprintf_s(b, "OEP candidato 0x%llX", (unsigned long long)addr);
                        log(b);
                    } else if (++oepSteps_ > 80000000ull) {
                        findOEP_ = false; pauseUI = true; breakVA = addr;
                        log("Find OEP: limite de pasos alcanzado, no encontrado.");
                    } else {
                        findOEPStep(hThread, addr, &dis);
                    }
                } else if (runToRet_) {
                    Cmd p = pending_.load();
                    if (quit_.load() || p == Cmd::Stop) {
                        runToRet_ = false; pauseUI = true; breakVA = addr;
                    } else if (p == Cmd::Pause) {
                        pending_.store(Cmd::None);
                        runToRet_ = false; pauseUI = true; breakVA = addr;
                    } else if (runToRetFinal_) {
                        runToRet_ = false; runToRetFinal_ = false;
                        pauseUI = true; breakVA = addr;   // detenido tras el ret
                        history_.push_back(addr);
                    } else {
                        runToRetStep(hThread, addr, &dis); // seguir avanzando
                    }
                } else if (singleStepping_) {
                    // era un Step-Into explicito: nos detenemos
                    singleStepping_ = false;
                    pauseUI = true; breakVA = addr;
                }
                // si no, era solo para re-armar durante un Go/StepOver: continuar
                break;
            }
            default: {
                // Revisar breakpoints de excepcion: si hay reglas, solo pausamos en las
                // que coincidan; si no hay ninguna, comportamiento por defecto (pausar en
                // primera oportunidad para que el analista decida).
                bool anyRules = false, matched = false;
                {
                    std::lock_guard<std::mutex> lk(excMutex_);
                    anyRules = !excBreaks_.empty();
                    for (auto& e : excBreaks_) {
                        if (!e.enabled) continue;
                        if (e.code == 0 || e.code == er.ExceptionCode) {
                            matched = true; e.address = addr; e.hits++;
                        }
                    }
                }
                if (matched || (!anyRules && ev.u.Exception.dwFirstChance)) {
                    char b[80]; sprintf_s(b, "Excepcion 0x%08X en 0x%llX",
                                          (unsigned)er.ExceptionCode, (unsigned long long)addr);
                    log(b);
                    pauseUI = true; breakVA = addr;
                }
                continueStatus = DBG_EXCEPTION_NOT_HANDLED;
                break;
            }
            }
            break;
        }
        default: break;
        }

        // ---- Si toca pausar la UI, esperamos el proximo comando ----
        if (pauseUI) {
            setState(DbgState::Paused);
            if (cb_.onBreak) cb_.onBreak(breakVA);
            resumeSignaled_.store(false);
            pending_.store(Cmd::None);
            while (!resumeSignaled_.load() && !quit_.load()) Sleep(5);

            Cmd c = pending_.load();
            pending_.store(Cmd::None);
            if (quit_.load() || c == Cmd::Stop) {
                TerminateProcess(hProcess_, 0);
                ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, DBG_CONTINUE);
                if (hThread) CloseHandle(hThread);
                hThread_ = nullptr;
                setState(DbgState::Exited);
                return;
            }

            // Preparar la reanudacion segun el comando.
            bool needRearmStep = (pendingRearm_ != 0);
            if (c == Cmd::StepInto) {
                singleStepping_ = true;
                setTrapFlag(hThread, is64_);
            } else if (c == Cmd::StepOver) {
                // Leer y decodificar la instruccion actual
                uint8_t code[16] = {0};
                readMemory(breakVA, code, sizeof(code));
                Instruction insn;
                if (dis.decodeOne(code, sizeof(code), breakVA, insn) && insn.isCall) {
                    uint64_t ret = breakVA + insn.length;
                    { std::lock_guard<std::mutex> lk(bpMutex_);
                      Breakpoint tmp; tmp.address = ret; tmp.oneShot = true; tmp.enabled = true;
                      auto [it, ins] = bps_.emplace(ret, tmp);
                      if (ins) installBreakpoint(it->second);
                    }
                    if (needRearmStep) setTrapFlag(hThread, is64_); // re-armar el BP actual primero
                } else {
                    singleStepping_ = true;
                    setTrapFlag(hThread, is64_);
                }
            } else if (c == Cmd::StepToRet) {
                runToRet_ = true; runToRetFinal_ = false;
                if (needRearmStep) setTrapFlag(hThread, is64_);   // re-armar; el modo sigue en SINGLE_STEP
                else runToRetStep(hThread, breakVA, &dis);
            } else if (c == Cmd::FindOEP) {
                findOEP_ = true;
                if (needRearmStep) setTrapFlag(hThread, is64_);
                else findOEPStep(hThread, breakVA, &dis);
            } else if (c == Cmd::RunTrace) {
                traceRun_ = true;
                setTrapFlag(hThread, is64_);
            } else { // Go
                if (needRearmStep) setTrapFlag(hThread, is64_);
            }
            if (hwJustHit_) { setResumeFlag(hThread, is64_); hwJustHit_ = false; }
            setState(DbgState::Running);
        }

        ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, continueStatus);
        if (hThread) CloseHandle(hThread);
        hThread_ = nullptr;

        // Limpiar one-shots ya golpeados
        {
            std::lock_guard<std::mutex> lk(bpMutex_);
            for (auto it = bps_.begin(); it != bps_.end();) {
                if (it->second.oneShot && !it->second.installed) it = bps_.erase(it);
                else ++it;
            }
        }
    }
    setState(DbgState::Exited);
}

// Avanza el modo "ejecutar hasta el retorno": decodifica la instruccion en 'rip'.
//  - ret  : la ejecuta (trap) y marca fin -> se pausara en el siguiente step.
//  - call : coloca un one-shot tras el call y continua (step-over, rapido).
//  - otra : single-step normal.
// Devuelve true si hay que pausar la UI (aqui siempre false: nunca pausa por si mismo).
bool Debugger::runToRetStep(void* hThreadV, uint64_t rip, void* disV) {
    HANDLE hThread = (HANDLE)hThreadV;
    Disassembler* dis = (Disassembler*)disV;
    uint8_t code[16] = {0};
    readMemory(rip, code, sizeof(code));
    Instruction insn;
    if (!dis->decodeOne(code, sizeof(code), rip, insn)) {
        setTrapFlag(hThread, is64_);
        return false;
    }
    if (insn.isRet) {
        runToRetFinal_ = true;
        setTrapFlag(hThread, is64_);
        return false;
    }
    if (insn.isCall) {
        uint64_t ret = rip + insn.length;
        std::lock_guard<std::mutex> lk(bpMutex_);
        Breakpoint tmp; tmp.address = ret; tmp.oneShot = true; tmp.enabled = true;
        auto [it, ins] = bps_.emplace(ret, tmp);
        if (ins) installBreakpoint(it->second);
        return false; // continuar sin trap; el one-shot atrapara el retorno del call
    }
    setTrapFlag(hThread, is64_);
    return false;
}

// Un paso del buscador de OEP: salta los call (one-shot al retorno) y hace
// single-step del resto para observar el salto/ret que transfiere al OEP.
void Debugger::findOEPStep(void* hThreadV, uint64_t rip, void* disV) {
    HANDLE hThread = (HANDLE)hThreadV;
    Disassembler* dis = (Disassembler*)disV;
    uint8_t code[16] = {0};
    readMemory(rip, code, sizeof(code));
    Instruction insn;
    if (dis->decodeOne(code, sizeof(code), rip, insn) && insn.isCall) {
        uint64_t ret = rip + insn.length;
        std::lock_guard<std::mutex> lk(bpMutex_);
        Breakpoint tmp; tmp.address = ret; tmp.oneShot = true; tmp.enabled = true;
        auto [it, ins] = bps_.emplace(ret, tmp);
        if (ins) installBreakpoint(it->second);
        return; // continuar sin trap
    }
    setTrapFlag(hThread, is64_);
}

void Debugger::reinstallAfterStep() {}
void Debugger::refreshModulesString(MemRegion&) {}
void Debugger::handleEvent(void*, uint32_t&) {}

} // namespace dbg

#pragma once
#include <atomic>
#include <cstdint>
#include <functional>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

// Motor de depuracion sobre la Windows Debug API.
// Corre un hilo dedicado (el "dueno" del debuggee) y expone comandos thread-safe:
// play / pause / step-into / step-over / stop, mas lectura de memoria y registros.

namespace dbg {

enum class DbgState { Idle, Launching, Running, Paused, Exited };

// Eventos de la Windows Debug API que pueden comportarse como breakpoints de
// sistema. Se combinan como mascara mediante setEventBreakMask().
enum DebugEventBreak : uint32_t {
    BreakOnThreadCreate = 1u << 0,
    BreakOnThreadExit   = 1u << 1,
    BreakOnDllLoad      = 1u << 2,
    BreakOnDllUnload    = 1u << 3,
};

struct Registers {
    bool     is64 = true;
    uint64_t rax=0, rbx=0, rcx=0, rdx=0, rsi=0, rdi=0, rbp=0, rsp=0, rip=0;
    uint64_t r8=0, r9=0, r10=0, r11=0, r12=0, r13=0, r14=0, r15=0;
    uint32_t eflags=0;
    uint16_t cs=0, ds=0, es=0, fs=0, gs=0, ss=0;
    uint64_t ip() const { return rip; }
};

struct MemRegion {
    uint64_t base = 0;
    uint64_t size = 0;
    uint32_t state = 0;       // MEM_COMMIT / MEM_RESERVE / MEM_FREE
    uint32_t protect = 0;     // PAGE_*
    uint32_t type = 0;        // MEM_IMAGE / MEM_MAPPED / MEM_PRIVATE
    std::string protectStr;
    std::string typeStr;
    std::string moduleName;   // si es MEM_IMAGE, nombre del modulo
};

struct LoadedModule {
    uint64_t base = 0;
    std::string name;
    std::string path;
};

struct DebugThread {
    uint32_t id = 0;
    bool current = false;
    uint32_t exitCode = 0;
    int priority = 0;
    std::string description;
};

struct Breakpoint {
    uint64_t address = 0;
    uint8_t  original = 0;    // byte original reemplazado por 0xCC
    bool     enabled = true;
    bool     oneShot = false; // temporal (step-over), se borra al golpear
    bool     installed = false;
    uint64_t hits = 0;        // impactos totales durante la sesion
    uint64_t breakOnHit = 0;  // 0=siempre; N=ignorar hasta el impacto N
    // Expresion booleana simple evaluada en el contexto del hilo que golpea el BP.
    // Vacia = verdadera. Ej.: "rax == 0", "ecx & 1 != 0", "hit >= 5".
    std::string condition;
    bool     logOnly = false; // registra el impacto que cumple, pero no pausa
    std::string label;
};

// Hardware breakpoint (registros de depuracion). Hasta 4 (slots 0-3).
struct HwBreakpoint {
    uint64_t    address = 0;
    int         slot = -1;    // 0..3
    int         type = 0;     // 0=exec, 1=write, 3=readwrite
    int         len = 1;      // 1/2/4/8
    bool        enabled = true;
    uint32_t    hits = 0;
    std::string label;
};

// Breakpoint de memoria basado en PAGE_GUARD. Windows protege paginas completas,
// por lo que el rango solicitado se redondea y puede recibir accesos vecinos.
struct MemoryBreakpoint {
    uint32_t id = 0;
    uint64_t address = 0;
    uint64_t size = 0;
    int type = 0;             // 0=access, 1=write, 8=execute (ExceptionInformation[0])
    bool enabled = true;
    uint64_t hits = 0;
    std::string label;
};

// Breakpoint de excepcion: detiene cuando el proceso lanza una excepcion cuyo
// codigo coincide (code==0 => cualquier excepcion).
struct ExceptionBreak {
    uint32_t    id = 0;
    uint32_t    code = 0;      // 0 = cualquiera; ej 0xC0000005 = ACCESS_VIOLATION
    uint64_t    address = 0;   // ubicacion asociada / donde disparo por ultima vez
    bool        enabled = true;
    uint32_t    hits = 0;
    std::string label;
};

// Callbacks que el motor invoca (desde el hilo de depuracion) para avisar a la UI.
struct DbgCallbacks {
    std::function<void(DbgState)>            onState;      // cambio de estado
    std::function<void(const std::string&)> onLog;        // mensajes al log
    std::function<void(uint64_t)>            onBreak;      // se detuvo en esta VA
    std::function<void(const LoadedModule&)> onModule;     // DLL cargada
    // Bus de eventos estilo x64dbg CB_* (Fase 3). type: "create_process","exit_process",
    // "load_dll","unload_dll","create_thread","exit_thread","exception". arg = VA/base/codigo.
    std::function<void(const std::string& type, uint64_t arg)> onEvent;
};

class Debugger {
public:
    Debugger();
    ~Debugger();

    // Lanza un ejecutable bajo depuracion. cmdLine opcional.
    bool launch(const std::wstring& exePath, const std::wstring& args, std::string& err);
    // Se engancha a un proceso ya en ejecucion.
    bool attach(uint32_t pid, std::string& err);
    // El front-end informa la imagen estatica para relocalizar breakpoints que
    // se colocaron antes del CREATE_PROCESS_DEBUG_EVENT cuando ASLR cambia base.
    void setTargetImageLayout(uint64_t preferredBase, uint32_t imageSize);
    // Libera un attach sin terminar el proceso. Solo aplica a DebugActiveProcess.
    bool detach(std::string& err);
    void detachAndStop();

    void setCallbacks(DbgCallbacks cb) { cb_ = std::move(cb); }

    // --- Controles (no bloqueantes) ---
    void go();          // Play  : continuar ejecucion
    void pause();       // Pause : forzar un break
    void stepInto();    // un paso, entrando a las llamadas
    void stepOver();    // un paso, saltando las llamadas
    void stepToRet();   // ejecuta hasta el 'ret' de la funcion actual (saltando calls)
    void runTrace();    // run-trace: registra cada instruccion ejecutada (single-step)
    std::vector<uint64_t> traceLog();
    void stop();        // Stop  : terminar el proceso
    void rewind();      // "rewind": vuelve al ultimo breakpoint guardado del historial

    DbgState state() const { return state_.load(); }
    bool     is64()  const { return is64_; }
    // M7: seguir procesos hijos. Si esta activo, launch usa DEBUG_PROCESS y el loop
    // detecta/continua los hijos (sin adoptarlos como target). Fijar antes de launch.
    void     setFollowChildren(bool on) { followChildren_ = on; }
    bool     followChildren() const { return followChildren_; }
    std::vector<uint32_t> childPids();   // PIDs de procesos hijos detectados
    uint64_t imageBase() const { return imageBase_; }
    void*    processHandle() const { return hProcess_; }   // HANDLE del proceso
    uint32_t pid() const { return pid_; }

    // Busqueda heuristica del OEP: traza (saltando calls) hasta que la ejecucion
    // salga del rango del stub [stubLo,stubHi) pero siga dentro de la imagen.
    void     findOEP(uint64_t stubLo, uint64_t stubHi, uint64_t imgLo, uint64_t imgHi);
    uint64_t foundOEP() const { return foundOEP_; }
    void setEventBreakMask(uint32_t mask) { eventBreakMask_.store(mask); }
    uint32_t eventBreakMask() const { return eventBreakMask_.load(); }

    // --- Breakpoints ---
    bool addBreakpoint(uint64_t va, const std::string& label = "");
    bool removeBreakpoint(uint64_t va);
    void toggleBreakpoint(uint64_t va, bool enabled);
    bool setBreakpointHitTarget(uint64_t va, uint64_t hit);
    bool setBreakpointCondition(uint64_t va, const std::string& condition);
    bool setBreakpointLogOnly(uint64_t va, bool logOnly);
    std::vector<Breakpoint> breakpoints();

    // --- Breakpoints de excepcion ---
    uint32_t addExceptionBreak(uint32_t code, uint64_t address, const std::string& label = "");
    void     removeExceptionBreak(uint32_t id);
    void     toggleExceptionBreak(uint32_t id, bool enabled);
    std::vector<ExceptionBreak> exceptionBreaks();

    // --- Hardware breakpoints (registros de depuracion DR0-DR3) ---
    // type: 0=ejecucion, 1=escritura, 3=lectura/escritura.  len: 1/2/4/8 bytes.
    bool addHwBreakpoint(uint64_t address, int type, int len, const std::string& label = "");
    bool removeHwBreakpoint(uint64_t address);
    std::vector<HwBreakpoint> hwBreakpoints();

    // --- Breakpoints de memoria (PAGE_GUARD, requiere proceso pausado) ---
    bool addMemoryBreakpoint(uint64_t address, uint64_t size, int type,
                             const std::string& label, std::string& error);
    bool removeMemoryBreakpoint(uint32_t id);
    std::vector<MemoryBreakpoint> memoryBreakpoints();

    // --- Memoria / registros (validos cuando esta Paused) ---
    size_t readMemory(uint64_t va, void* out, size_t len);
    size_t writeMemory(uint64_t va, const void* in, size_t len);
    Registers registers();
    bool setRegister(const std::string& name, uint64_t value);
    std::vector<MemRegion> memoryMap();
    std::vector<LoadedModule> modules();
    std::vector<DebugThread> threads();

    // Control de hilos (paridad x64dbg: suspendthread/resumethread/killthread/priority/name).
    bool suspendThread(uint32_t tid);
    bool resumeThread(uint32_t tid);
    bool killThread(uint32_t tid, uint32_t exitCode = 0);
    bool setThreadPriority(uint32_t tid, int priority);
    bool setThreadName(uint32_t tid, const std::string& name);

    // Symbol server (M5): path de busqueda de simbolos (formato DbgHelp/symsrv),
    // ej. "srv*C:\\sym*https://msdl.microsoft.com/download/symbols". Se aplica en el
    // proximo SymInitialize; si ya hay sesion, refresca de inmediato.
    void setSymbolSearchPath(const std::string& path);
    const std::string& symbolSearchPath() const { return symSearchPath_; }

    // Simbolos (DbgHelp) y cadena SEH.
    std::string symbolAt(uint64_t va);                    // "modulo!nombre+off" o ""
    std::string sourceAt(uint64_t va);                    // archivo(linea) PDB, o ""
    struct StackFrame {
        uint64_t instruction = 0;
        uint64_t frame = 0;
        uint64_t stack = 0;
        std::string symbol;
        std::string source;
    };
    std::vector<StackFrame> walkStack(size_t maxFrames = 64);
    std::vector<std::pair<uint64_t, uint64_t>> sehChain(); // x86: (record, handler)

private:
    void debugLoop();
    void handleEvent(void* dbgEvent /*DEBUG_EVENT*/, uint32_t& continueStatus);
    void installBreakpoint(Breakpoint& bp);
    void uninstallBreakpoint(Breakpoint& bp);
    bool runToRetStep(void* hThread, uint64_t rip, void* disassembler); // avanza el modo step-to-ret
    void reinstallAfterStep();
    void refreshModulesString(MemRegion& r);
    void relocateTargetImageArtifacts();
    bool breakpointConditionMatches(const std::string& expression, uint64_t hits, std::string& error);
    void rearmMemoryPage(uint64_t page);
    void clearMemoryBreakpoints();
    void setState(DbgState s);
    void log(const std::string& m);

    enum class Cmd { None, Go, Pause, StepInto, StepOver, StepToRet, FindOEP, RunTrace, Stop };
    void findOEPStep(void* hThread, uint64_t rip, void* disassembler);

    void* hProcess_ = nullptr;   // HANDLE
    void* hThread_  = nullptr;   // HANDLE del hilo actual detenido
    uint32_t pid_ = 0;
    uint32_t curTid_ = 0;
    bool  is64_ = true;
    uint64_t imageBase_ = 0;
    uint64_t entryPoint_ = 0;
    uint64_t targetPreferredBase_ = 0;
    uint32_t targetImageSize_ = 0;
    std::atomic<uint32_t> eventBreakMask_{0};

    std::thread worker_;
    std::atomic<DbgState> state_{DbgState::Idle};
    std::atomic<Cmd>      pending_{Cmd::None};
    std::atomic<bool>     resumeSignaled_{false};
    std::atomic<bool>     quit_{false};
    std::atomic<bool>     detachRequested_{false};

    std::mutex bpMutex_;
    std::map<uint64_t, Breakpoint> bps_;

    std::mutex excMutex_;
    std::vector<ExceptionBreak> excBreaks_;
    uint32_t   nextExcId_ = 1;

    std::mutex hwMutex_;
    HwBreakpoint hwBps_[4];         // por slot; address==0 => libre
    void applyHwToAllThreads();     // escribe DR0-DR7 en todos los hilos
    void applyHwToThread(void* hThread);
    uint64_t lastHwHit_ = 0;
    bool     hwJustHit_ = false;    // para poner Resume Flag al continuar

    struct MemoryBreakpointEntry {
        MemoryBreakpoint info;
        struct Page { uint64_t base = 0; uint32_t originalProtect = 0; };
        std::vector<Page> pages;
    };
    std::mutex memBpMutex_;
    std::vector<MemoryBreakpointEntry> memBps_;
    std::vector<uint64_t> pendingGuardRearmPages_;
    uint32_t nextMemBpId_ = 1;

    // step-over interno
    uint64_t stepOverReturn_ = 0;
    bool     inStepOver_ = false;
    // breakpoint que estamos re-armando tras un single-step
    uint64_t pendingRearm_ = 0;
    bool     singleStepping_ = false;
    // modo step-to-ret (ejecutar hasta el retorno)
    bool     runToRet_ = false;
    bool     runToRetFinal_ = false;  // el ret ya se ejecuto, pausar en el proximo step
    // modo find-OEP
    bool     findOEP_ = false;
    uint64_t oepStubLo_ = 0, oepStubHi_ = 0, oepImgLo_ = 0, oepImgHi_ = 0;
    uint64_t foundOEP_ = 0;
    uint64_t oepSteps_ = 0;
    // run-trace
    bool     traceRun_ = false;
    std::mutex traceMutex_;
    std::vector<uint64_t> traceLog_;
    size_t   traceMax_ = 200000;

    std::mutex modMutex_;
    std::vector<LoadedModule> modules_;

    std::vector<uint64_t> history_; // VAs de breakpoints golpeados (para rewind logico)
    bool symReady_ = false;         // DbgHelp inicializado
    std::string symSearchPath_;     // path de simbolos (symsrv); vacio = por defecto
    bool followChildren_ = false;   // M7: seguir/detectar procesos hijos
    std::mutex childMutex_;
    std::vector<uint32_t> childPids_;

    DbgCallbacks cb_;
    bool attached_ = false;
};

const char* protectToStr(uint32_t p);
const char* memTypeToStr(uint32_t t);

} // namespace dbg

#pragma once
#include <cstdint>
#include <functional>
#include <map>
#include <string>
#include <vector>

// Motor de expresiones estilo x64dbg (DbgValFromString + funciones de expresion).
// - Constantes enteras en HEX por defecto (como x64dbg); 0x tambien vale; 0n = decimal.
// - Operadores: + - * / % & | ^ ~ << >> con precedencia y parentesis.
// - Registros por nombre (rax, eax, rip, esp, eflags...): via callback.
// - Funciones registrables: name(args) o cat.name(args). Args numericos o string ("...").
//   Predefinidas: byte/word/dword/qword/ptr(a), mod.base/size(a), mod.fromname("dll"),
//   dis.len(a). Un plugin o la IA pueden registrar mas con registerFunction().
//
// El evaluador NO depende de App ni del Debugger: recibe callbacks en EvalContext.

namespace dbg {

// Un valor de expresion: numero o cadena (para args tipo "ntdll.dll").
struct EvalValue {
    bool        isStr = false;
    uint64_t    num = 0;
    std::string str;
    static EvalValue N(uint64_t v) { EvalValue e; e.num = v; return e; }
    static EvalValue S(std::string s) { EvalValue e; e.isStr = true; e.str = std::move(s); return e; }
};

struct EvalContext {
    // Lee un registro por nombre en minusculas ("rax","eip","eflags"...). Devuelve false si no existe.
    std::function<bool(const std::string& name, uint64_t& out)> readReg;
    // Lee 'len' bytes de memoria en 'va'. Devuelve bytes leidos.
    std::function<size_t(uint64_t va, void* out, size_t len)> readMem;
    // Base/size del modulo que contiene 'va' (0 si no se conoce).
    std::function<uint64_t(uint64_t va)> moduleBase;
    std::function<uint64_t(uint64_t va)> moduleSize;
    // Base del modulo por nombre ("ntdll.dll"); 0 si no está.
    std::function<uint64_t(const std::string& name)> moduleFromName;
    // Longitud en bytes de la instruccion en 'va' (0 si no se puede).
    std::function<uint32_t(uint64_t va)> disasmLen;
};

class ExprEval {
public:
    explicit ExprEval(const EvalContext& ctx) : ctx_(ctx) { registerBuiltins(); }

    // Evalua la expresion. Devuelve true y llena 'out'; en error devuelve false y 'err'.
    bool eval(const std::string& expr, uint64_t& out, std::string& err);

    // Registra una funcion de expresion (para plugins / IA). El nombre puede llevar punto
    // ("ai.name"). El handler recibe los argumentos ya evaluados.
    using FnHandler = std::function<bool(const std::vector<EvalValue>& args, EvalValue& out, std::string& err)>;
    void registerFunction(const std::string& name, FnHandler fn) { fns_[name] = std::move(fn); }
    std::vector<std::string> functionNames() const;

private:
    void registerBuiltins();

    // Parser recursivo descendente.
    struct Parser;
    EvalContext ctx_;
    std::map<std::string, FnHandler> fns_;
};

} // namespace dbg

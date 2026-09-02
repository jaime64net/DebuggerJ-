#include "ExprEval.h"

#include <cctype>
#include <cstdlib>
#include <cstring>
#include <stdexcept>

namespace dbg {

// ---------------------------------------------------------------------------
// Tokenizer + parser recursivo. Precedencia (de menor a mayor):
//   |  ^  &  << >>  + -  * / %  unario(- ~)  primario
// ---------------------------------------------------------------------------
struct EvalError { std::string msg; };

struct ExprEval::Parser {
    const std::string& s;
    size_t i = 0;
    ExprEval& owner;
    EvalContext& ctx;

    Parser(const std::string& str, ExprEval& o) : s(str), owner(o), ctx(o.ctx_) {}

    void skip() { while (i < s.size() && std::isspace((unsigned char)s[i])) ++i; }
    bool eof() { skip(); return i >= s.size(); }
    char peek() { skip(); return i < s.size() ? s[i] : '\0'; }

    [[noreturn]] void fail(const std::string& m) { throw EvalError{ m }; }

    bool match(const char* op) {
        skip();
        size_t n = std::strlen(op);
        if (s.compare(i, n, op) == 0) { i += n; return true; }
        return false;
    }

    EvalValue parseExpr() { return parseOr(); }

    EvalValue parseOr() {
        EvalValue a = parseXor();
        for (;;) { skip();
            if (i < s.size() && s[i] == '|' && !(i+1 < s.size() && s[i+1]=='|')) { ++i; EvalValue b = parseXor(); a = EvalValue::N(num(a) | num(b)); }
            else break;
        }
        return a;
    }
    EvalValue parseXor() {
        EvalValue a = parseAnd();
        for (;;) { skip();
            if (i < s.size() && s[i] == '^') { ++i; EvalValue b = parseAnd(); a = EvalValue::N(num(a) ^ num(b)); }
            else break;
        }
        return a;
    }
    EvalValue parseAnd() {
        EvalValue a = parseShift();
        for (;;) { skip();
            if (i < s.size() && s[i] == '&' && !(i+1 < s.size() && s[i+1]=='&')) { ++i; EvalValue b = parseShift(); a = EvalValue::N(num(a) & num(b)); }
            else break;
        }
        return a;
    }
    EvalValue parseShift() {
        EvalValue a = parseAdd();
        for (;;) {
            if (match("<<")) { EvalValue b = parseAdd(); a = EvalValue::N(num(a) << (num(b) & 63)); }
            else if (match(">>")) { EvalValue b = parseAdd(); a = EvalValue::N(num(a) >> (num(b) & 63)); }
            else break;
        }
        return a;
    }
    EvalValue parseAdd() {
        EvalValue a = parseMul();
        for (;;) { skip();
            if (i < s.size() && s[i] == '+') { ++i; EvalValue b = parseMul(); a = EvalValue::N(num(a) + num(b)); }
            else if (i < s.size() && s[i] == '-') { ++i; EvalValue b = parseMul(); a = EvalValue::N(num(a) - num(b)); }
            else break;
        }
        return a;
    }
    EvalValue parseMul() {
        EvalValue a = parseUnary();
        for (;;) { skip();
            if (i < s.size() && s[i] == '*') { ++i; EvalValue b = parseUnary(); a = EvalValue::N(num(a) * num(b)); }
            else if (i < s.size() && s[i] == '/') { ++i; EvalValue b = parseUnary(); uint64_t d = num(b); a = EvalValue::N(d ? num(a) / d : 0); }
            else if (i < s.size() && s[i] == '%') { ++i; EvalValue b = parseUnary(); uint64_t d = num(b); a = EvalValue::N(d ? num(a) % d : 0); }
            else break;
        }
        return a;
    }
    EvalValue parseUnary() {
        skip();
        if (i < s.size() && s[i] == '-') { ++i; return EvalValue::N((uint64_t)0 - num(parseUnary())); }
        if (i < s.size() && s[i] == '~') { ++i; return EvalValue::N(~num(parseUnary())); }
        return parsePrimary();
    }

    uint64_t num(const EvalValue& v) { if (v.isStr) fail("se esperaba un numero, no una cadena"); return v.num; }

    EvalValue parsePrimary() {
        skip();
        if (i >= s.size()) fail("expresion incompleta");
        char c = s[i];
        if (c == '(') { ++i; EvalValue v = parseExpr(); skip(); if (i >= s.size() || s[i] != ')') fail("falta ')'"); ++i; return v; }
        if (c == '"') return parseString();
        // acceso a memoria estilo [expr] -> ptr(expr) del tamano del puntero
        if (c == '[') {
            ++i; EvalValue a = parseExpr(); skip();
            if (i >= s.size() || s[i] != ']') fail("falta ']'"); ++i;
            uint64_t v = 0; size_t got = ctx.readMem ? ctx.readMem(num(a), &v, 8) : 0;
            (void)got; return EvalValue::N(v);
        }
        if (std::isdigit((unsigned char)c)) return parseNumber();
        if (std::isalpha((unsigned char)c) || c == '_' || c == '.') return parseIdent();
        fail(std::string("caracter inesperado '") + c + "'");
    }

    EvalValue parseString() {
        ++i; // "
        std::string out;
        while (i < s.size() && s[i] != '"') {
            if (s[i] == '\\' && i + 1 < s.size()) { out.push_back(s[i+1]); i += 2; }
            else out.push_back(s[i++]);
        }
        if (i >= s.size()) fail("cadena sin cerrar");
        ++i; // "
        return EvalValue::S(out);
    }

    EvalValue parseNumber() {
        size_t start = i;
        // 0n... = decimal ; 0x... = hex ; por defecto HEX (como x64dbg)
        if (s.compare(i, 2, "0n") == 0 || s.compare(i, 2, "0N") == 0) {
            i += 2; size_t b = i;
            while (i < s.size() && std::isdigit((unsigned char)s[i])) ++i;
            return EvalValue::N(strtoull(s.substr(b, i - b).c_str(), nullptr, 10));
        }
        if (s.compare(i, 2, "0x") == 0 || s.compare(i, 2, "0X") == 0) i += 2;
        size_t b = i;
        while (i < s.size() && std::isxdigit((unsigned char)s[i])) ++i;
        if (i == b && i == start) fail("numero invalido");
        return EvalValue::N(strtoull(s.substr(b, i - b).c_str(), nullptr, 16));
    }

    EvalValue parseIdent() {
        size_t b = i;
        while (i < s.size() && (std::isalnum((unsigned char)s[i]) || s[i] == '_' || s[i] == '.')) ++i;
        std::string name = s.substr(b, i - b);
        skip();
        // Llamada a funcion?
        if (i < s.size() && s[i] == '(') {
            ++i;
            std::vector<EvalValue> args;
            skip();
            if (!(i < s.size() && s[i] == ')')) {
                for (;;) {
                    args.push_back(parseExpr());
                    skip();
                    if (i < s.size() && s[i] == ',') { ++i; continue; }
                    break;
                }
            }
            skip();
            if (i >= s.size() || s[i] != ')') fail("falta ')' en " + name);
            ++i;
            auto it = owner.fns_.find(name);
            if (it == owner.fns_.end()) fail("funcion desconocida: " + name);
            EvalValue out; std::string err;
            if (!it->second(args, out, err)) fail(err.empty() ? ("fallo en " + name) : err);
            return out;
        }
        // Registro?
        std::string lower = name; for (char& ch : lower) ch = (char)std::tolower((unsigned char)ch);
        uint64_t rv = 0;
        if (ctx.readReg && ctx.readReg(lower, rv)) return EvalValue::N(rv);
        fail("identificador desconocido: " + name);
    }
};

void ExprEval::registerBuiltins() {
    auto memN = [this](const std::vector<EvalValue>& a, EvalValue& out, std::string& err, int bytes) -> bool {
        if (a.empty()) { err = "falta la direccion"; return false; }
        uint64_t va = a[0].num, v = 0;
        if (ctx_.readMem) ctx_.readMem(va, &v, bytes);
        uint64_t mask = (bytes >= 8) ? ~0ull : ((1ull << (bytes * 8)) - 1);
        out = EvalValue::N(v & mask); return true;
    };
    fns_["byte"]  = [memN](auto& a, auto& o, auto& e){ return memN(a,o,e,1); };
    fns_["word"]  = [memN](auto& a, auto& o, auto& e){ return memN(a,o,e,2); };
    fns_["dword"] = [memN](auto& a, auto& o, auto& e){ return memN(a,o,e,4); };
    fns_["qword"] = [memN](auto& a, auto& o, auto& e){ return memN(a,o,e,8); };
    fns_["ptr"]   = [memN](auto& a, auto& o, auto& e){ return memN(a,o,e,8); };

    fns_["mod.base"] = [this](const std::vector<EvalValue>& a, EvalValue& o, std::string& e){
        if (a.empty()) { e = "falta arg"; return false; }
        o = EvalValue::N(ctx_.moduleBase ? ctx_.moduleBase(a[0].num) : 0); return true; };
    fns_["mod.size"] = [this](const std::vector<EvalValue>& a, EvalValue& o, std::string& e){
        if (a.empty()) { e = "falta arg"; return false; }
        o = EvalValue::N(ctx_.moduleSize ? ctx_.moduleSize(a[0].num) : 0); return true; };
    fns_["mod.fromname"] = [this](const std::vector<EvalValue>& a, EvalValue& o, std::string& e){
        if (a.empty() || !a[0].isStr) { e = "mod.fromname(\"dll\")"; return false; }
        o = EvalValue::N(ctx_.moduleFromName ? ctx_.moduleFromName(a[0].str) : 0); return true; };
    fns_["dis.len"] = [this](const std::vector<EvalValue>& a, EvalValue& o, std::string& e){
        if (a.empty()) { e = "falta arg"; return false; }
        o = EvalValue::N(ctx_.disasmLen ? ctx_.disasmLen(a[0].num) : 0); return true; };
}

std::vector<std::string> ExprEval::functionNames() const {
    std::vector<std::string> v;
    for (auto& kv : fns_) v.push_back(kv.first);
    return v;
}

bool ExprEval::eval(const std::string& expr, uint64_t& out, std::string& err) {
    if (expr.empty()) { err = "expresion vacia"; return false; }
    try {
        Parser p(expr, *this);
        EvalValue v = p.parseExpr();
        if (!p.eof()) { err = "texto sobrante en la expresion"; return false; }
        if (v.isStr) { err = "la expresion resulto en una cadena, no un numero"; return false; }
        out = v.num;
        return true;
    } catch (const EvalError& e) {
        err = e.msg; return false;
    } catch (const std::exception& e) {
        err = e.what(); return false;
    }
}

} // namespace dbg

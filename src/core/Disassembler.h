#pragma once
#include <cstdint>
#include <string>
#include <vector>

// Envuelve a Zydis para desensamblar un buffer de bytes en instrucciones legibles.

namespace dbg {

struct Instruction {
    uint64_t    address = 0;     // VA (virtual address) donde vive la instruccion
    uint32_t    length  = 0;     // bytes que ocupa
    std::string bytes;           // hex "55 8B EC"
    std::string mnemonic;        // "push", "mov", "call"...
    std::string text;            // instruccion completa "push ebp"
    bool        isCall   = false;
    bool        isJump   = false;
    bool        isRet    = false;
    uint64_t    branchTarget = 0; // destino absoluto si es call/jmp con target conocido, si no 0
    bool        hasBranchTarget = false;
};

class Disassembler {
public:
    // is64: modo 64 bits (true) o 32 bits (false).
    explicit Disassembler(bool is64 = true);
    void setMode(bool is64);

    // Desensambla 'size' bytes empezando en la VA 'baseAddress'.
    // maxInstr limita cuantas instrucciones producir (0 = sin limite razonable).
    std::vector<Instruction> disassemble(const uint8_t* data, size_t size,
                                         uint64_t baseAddress, size_t maxInstr = 0) const;

    // Desensambla exactamente una instruccion en 'data' (para el paso a paso en vivo).
    bool decodeOne(const uint8_t* data, size_t size, uint64_t address, Instruction& out) const;

private:
    bool is64_;
};

} // namespace dbg

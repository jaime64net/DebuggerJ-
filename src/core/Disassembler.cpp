#include "Disassembler.h"
#include <Zydis/Zydis.h>
#include <cstdio>

namespace dbg {

Disassembler::Disassembler(bool is64) : is64_(is64) {}
void Disassembler::setMode(bool is64) { is64_ = is64; }

static void fillBranch(const ZydisDecodedInstruction& insn,
                       const ZydisDecodedOperand* ops, uint64_t addr, Instruction& out) {
    out.isCall = (insn.mnemonic == ZYDIS_MNEMONIC_CALL);
    out.isRet  = (insn.mnemonic == ZYDIS_MNEMONIC_RET || insn.mnemonic == ZYDIS_MNEMONIC_IRET);
    out.isJump = (insn.meta.category == ZYDIS_CATEGORY_COND_BR ||
                  insn.meta.category == ZYDIS_CATEGORY_UNCOND_BR);
    if ((out.isCall || out.isJump) && insn.operand_count_visible > 0) {
        ZyanU64 target = 0;
        if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&insn, &ops[0], addr, &target))) {
            out.branchTarget = target;
            out.hasBranchTarget = true;
        }
    }
}

bool Disassembler::decodeOne(const uint8_t* data, size_t size, uint64_t address, Instruction& out) const {
    ZydisDecoder decoder;
    ZydisDecoderInit(&decoder,
        is64_ ? ZYDIS_MACHINE_MODE_LONG_64 : ZYDIS_MACHINE_MODE_LEGACY_32,
        is64_ ? ZYDIS_STACK_WIDTH_64 : ZYDIS_STACK_WIDTH_32);
    ZydisFormatter fmt;
    ZydisFormatterInit(&fmt, ZYDIS_FORMATTER_STYLE_INTEL);

    ZydisDecodedInstruction insn;
    ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
    if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, data, size, &insn, ops)))
        return false;

    out.address = address;
    out.length  = insn.length;

    char buf[256];
    ZydisFormatterFormatInstruction(&fmt, &insn, ops, insn.operand_count_visible,
                                    buf, sizeof(buf), address, nullptr);
    out.text = buf;
    out.mnemonic = ZydisMnemonicGetString(insn.mnemonic);

    char hex[64] = {0}; int p = 0;
    for (uint32_t i = 0; i < insn.length && p < 60; ++i)
        p += std::snprintf(hex + p, sizeof(hex) - p, "%02X ", data[i]);
    out.bytes = hex;

    fillBranch(insn, ops, address, out);
    return true;
}

std::vector<Instruction> Disassembler::disassemble(const uint8_t* data, size_t size,
                                                   uint64_t baseAddress, size_t maxInstr) const {
    std::vector<Instruction> result;
    if (!data || size == 0) return result;

    ZydisDecoder decoder;
    ZydisDecoderInit(&decoder,
        is64_ ? ZYDIS_MACHINE_MODE_LONG_64 : ZYDIS_MACHINE_MODE_LEGACY_32,
        is64_ ? ZYDIS_STACK_WIDTH_64 : ZYDIS_STACK_WIDTH_32);
    ZydisFormatter fmt;
    ZydisFormatterInit(&fmt, ZYDIS_FORMATTER_STYLE_INTEL);

    size_t offset = 0;
    ZydisDecodedInstruction insn;
    ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
    while (offset < size) {
        uint64_t addr = baseAddress + offset;
        Instruction out;
        if (ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, data + offset, size - offset, &insn, ops))) {
            out.address = addr;
            out.length  = insn.length;
            char buf[256];
            ZydisFormatterFormatInstruction(&fmt, &insn, ops, insn.operand_count_visible,
                                            buf, sizeof(buf), addr, nullptr);
            out.text = buf;
            out.mnemonic = ZydisMnemonicGetString(insn.mnemonic);
            char hex[64] = {0}; int pp = 0;
            for (uint32_t i = 0; i < insn.length && pp < 60; ++i)
                pp += std::snprintf(hex + pp, sizeof(hex) - pp, "%02X ", data[offset + i]);
            out.bytes = hex;
            fillBranch(insn, ops, addr, out);
            offset += insn.length;
        } else {
            // byte invalido: lo mostramos como db y avanzamos 1
            out.address = addr;
            out.length  = 1;
            char hex[8]; std::snprintf(hex, sizeof(hex), "%02X ", data[offset]);
            out.bytes = hex;
            out.mnemonic = "db";
            char t[32]; std::snprintf(t, sizeof(t), "db 0x%02X", data[offset]);
            out.text = t;
            offset += 1;
        }
        result.push_back(std::move(out));
        if (maxInstr && result.size() >= maxInstr) break;
    }
    return result;
}

} // namespace dbg

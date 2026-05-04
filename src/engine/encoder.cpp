#include "morphkatz/engine/encoder.hpp"

#include "morphkatz/common/logging.hpp"

#include <Zydis/Zydis.h>

#include <cstring>

namespace morphkatz::engine {

namespace {

void fill_encoder_operand(ZydisEncoderOperand& zo, const ir::Operand& op) {
    switch (op.kind) {
        case ir::Operand::Kind::Register:
            zo.type      = ZYDIS_OPERAND_TYPE_REGISTER;
            zo.reg.value = static_cast<ZydisRegister>(op.reg);
            break;
        case ir::Operand::Kind::Immediate:
            zo.type    = ZYDIS_OPERAND_TYPE_IMMEDIATE;
            zo.imm.s   = op.imm;
            break;
        case ir::Operand::Kind::Memory:
            zo.type        = ZYDIS_OPERAND_TYPE_MEMORY;
            zo.mem.base    = static_cast<ZydisRegister>(op.mem.base);
            zo.mem.index   = static_cast<ZydisRegister>(op.mem.index);
            zo.mem.scale   = op.mem.scale;
            zo.mem.displacement = op.mem.disp;
            zo.mem.size    = static_cast<uint16_t>(op.size_bits / 8);
            break;
        case ir::Operand::Kind::Relative:
            zo.type    = ZYDIS_OPERAND_TYPE_IMMEDIATE;
            zo.imm.s   = op.imm;
            break;
        default:
            zo.type = ZYDIS_OPERAND_TYPE_UNUSED;
            break;
    }
}

}  // namespace

Result<std::vector<uint8_t>> encode_insn(ir::MnemonicId mnemonic,
                                         std::span<const ir::Operand> operands) {
    ZydisEncoderRequest req{};
    req.machine_mode  = ZYDIS_MACHINE_MODE_LONG_64;
    req.mnemonic      = static_cast<ZydisMnemonic>(mnemonic);
    req.operand_count = static_cast<ZyanU8>(std::min<size_t>(operands.size(),
                                                             ZYDIS_ENCODER_MAX_OPERANDS));
    for (size_t i = 0; i < req.operand_count; ++i) {
        fill_encoder_operand(req.operands[i], operands[i]);
    }

    ZyanU8 buf[ZYDIS_MAX_INSTRUCTION_LENGTH];
    ZyanUSize len = sizeof(buf);
    if (ZYAN_FAILED(ZydisEncoderEncodeInstruction(&req, buf, &len))) {
        return Error::make(ErrorKind::Encode, "Zydis encode failed");
    }
    return std::vector<uint8_t>(buf, buf + len);
}

Result<std::vector<uint8_t>> encode_rewrite(const ir::Instruction& source,
                                            const rules::Rule& rule) {
    // Targeted/raw byte rules short-circuit Zydis entirely.
    if (rule.raw_from && rule.raw_to) {
        return *rule.raw_to;
    }

    if (rule.rewrite_mnemonic == 0) {
        return Error::make(ErrorKind::RuleLoad,
                           "rule " + rule.id + " has no rewrite mnemonic",
                           rule.id);
    }

    std::vector<ir::Operand> ops;
    ops.reserve(rule.rewrite_operands.size());
    for (const auto& ro : rule.rewrite_operands) {
        ir::Operand out{};
        switch (ro.source) {
            case rules::Rule::RewriteOperand::Source::CopyFrom:
                if (ro.copy_from_op >= source.op_count) {
                    return Error::make(ErrorKind::Encode,
                                       "rewrite copy_from out of range", rule.id);
                }
                out = source.ops[ro.copy_from_op];
                if (ro.imm_transform ==
                        rules::Rule::RewriteOperand::ImmTransform::Negate) {
                    if (out.kind != ir::Operand::Kind::Immediate) {
                        return Error::make(ErrorKind::Encode,
                            "rewrite transform=negate on non-immediate", rule.id);
                    }
                    // Two's-complement negation in the operand width. We
                    // never widen past 32 bits here because Zydis
                    // doesn't support imm64 forms of ADD/SUB r/m, imm
                    // (the encoders sign-extend imm32). Reject 64-bit
                    // operand sizes that would overflow imm32 after
                    // negation - 0x80000000 is the one int32_t value
                    // whose negation can't be represented.
                    if (out.imm == INT64_C(-0x80000000)) {
                        return Error::make(ErrorKind::Encode,
                            "rewrite transform=negate on imm32 INT_MIN",
                            rule.id);
                    }
                    out.imm = -out.imm;
                }
                break;
            case rules::Rule::RewriteOperand::Source::Immediate:
                out.kind      = ir::Operand::Kind::Immediate;
                out.imm       = ro.imm_value;
                out.size_bits = ro.imm_size_bits ? ro.imm_size_bits : 32;
                break;
            case rules::Rule::RewriteOperand::Source::Register:
                out.kind      = ir::Operand::Kind::Register;
                out.reg       = ro.reg;
                out.size_bits = ro.size_bits ? ro.size_bits : 64;
                break;
        }
        ops.push_back(out);
    }

    return encode_insn(rule.rewrite_mnemonic, ops);
}

}

#include "morphkatz/disasm/decoder.hpp"

#include "morphkatz/common/logging.hpp"

#include <Zydis/Zydis.h>

#include <algorithm>
#include <cstring>
#include <memory>

namespace morphkatz::disasm {

namespace {

// Zydis 4.1 redesigned the flag-access surface: the old
// `cpu_flags->flags[ZydisCPUFlag].action` table is gone. The decoded
// instruction now exposes five bitmasks on `ZydisAccessedFlags`
// (`tested`, `modified`, `set_0`, `set_1`, `undefined`) whose bits match
// the architectural EFLAGS bit positions exposed via the
// `ZYDIS_CPUFLAG_*` macros. We keep our IR's `ir::Flag` layout compact
// (bits 0..8 for the arithmetic + system flags we care about), so this
// helper translates between the two.
constexpr uint32_t zy_mask_to_ir(ZyanU32 m) noexcept {
    uint32_t r = 0;
    if (m & ZYDIS_CPUFLAG_CF) r |= ir::F_CF;
    if (m & ZYDIS_CPUFLAG_PF) r |= ir::F_PF;
    if (m & ZYDIS_CPUFLAG_AF) r |= ir::F_AF;
    if (m & ZYDIS_CPUFLAG_ZF) r |= ir::F_ZF;
    if (m & ZYDIS_CPUFLAG_SF) r |= ir::F_SF;
    if (m & ZYDIS_CPUFLAG_TF) r |= ir::F_TF;
    if (m & ZYDIS_CPUFLAG_IF) r |= ir::F_IF;
    if (m & ZYDIS_CPUFLAG_DF) r |= ir::F_DF;
    if (m & ZYDIS_CPUFLAG_OF) r |= ir::F_OF;
    return r;
}

void populate_flags(const ZydisDecodedInstruction& zi, ir::FlagsEffect& out) {
    // Zydis leaves `cpu_flags` null for instructions that do not touch
    // EFLAGS (MOV, LEA, NOP, RET, CALL, JMP, ...). Dereferencing would
    // crash the decoder for every such instruction; guard and leave
    // `out` zeroed.
    if (!zi.cpu_flags) return;
    out.tested    |= zy_mask_to_ir(zi.cpu_flags->tested);
    out.modified  |= zy_mask_to_ir(zi.cpu_flags->modified);
    out.set_to_0  |= zy_mask_to_ir(zi.cpu_flags->set_0);
    out.set_to_1  |= zy_mask_to_ir(zi.cpu_flags->set_1);
    out.undefined |= zy_mask_to_ir(zi.cpu_flags->undefined);
}

// Canonicalise the flag-effect vector for a handful of common self-operation
// idioms. Zydis reports the *general* behaviour of each mnemonic, so for
// example SUB reports CF/OF/ZF/SF/PF as "modified" even though SUB R,R always
// produces zero (and therefore CF=0 and OF=0 exactly like XOR R,R).
//
// Canonicalising here lets our YAML rules declare `flags_effect: equivalent`
// for the XOR <-> SUB swap and have the RuleMatcher's strict check still
// accept them. Without this pass we'd have to tag them `equivalent_if` and
// require callers to feed live-flags information, which is not practical for
// single-instruction unit tests.
//
// Rule IDs that rely on each canonicalisation:
//   - `x64.zero.xor_to_sub`, `x64.zero.sub_to_xor`
//     -> "zeroing idiom" block (XOR R,R == SUB R,R).
//   - `x64.cmp.reg0_to_test_self`, `x64.test_self.to_cmp_imm0`
//     -> CMP R,0 / TEST R,R block; the AF difference is reported as
//        `undefined` on both sides so the FlagsEffect vectors match
//        bit-for-bit.
//   - `x64.zero.and_imm0_to_xor_self`
//     -> AND R,0 block, which lands in the zeroing-idiom shape.
//   - `x64.encoding.and_self_to_test_self`, `x64.encoding.or_self_to_test_self`
//     -> identity-op block (AND/OR/TEST R,R).
void canonicalise_self_op_flags(const ZydisDecodedInstruction& zi,
                                const ZydisDecodedOperand* zops,
                                ir::FlagsEffect& out) {
    // CMP R, 0 has the same observable flag effect as TEST R,R except for AF,
    // which hardware sets to zero while TEST leaves undefined. We canonicalise
    // CMP R,0 to the TEST form so the rule x64.cmp.reg0_to_test_self qualifies
    // for the strict `equivalent` gate.
    if (zi.mnemonic == ZYDIS_MNEMONIC_CMP && zi.operand_count_visible >= 2) {
        const auto& rhs = zops[1];
        const bool rhs_is_zero =
            rhs.type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
            (rhs.imm.is_signed ? rhs.imm.value.s == 0 : rhs.imm.value.u == 0);
        if (rhs_is_zero) {
            out.tested    = 0;
            out.modified  = ir::F_SF | ir::F_ZF | ir::F_PF;
            out.set_to_0  = ir::F_CF | ir::F_OF;
            out.set_to_1  = 0;
            out.undefined = ir::F_AF;
        }
    }

    // AND R, 0 is a zeroing idiom with exactly the same observable flags as
    // XOR R,R after our canonicalisation above.
    if (zi.mnemonic == ZYDIS_MNEMONIC_AND && zi.operand_count_visible >= 2) {
        const auto& rhs = zops[1];
        const bool rhs_is_zero =
            rhs.type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
            (rhs.imm.is_signed ? rhs.imm.value.s == 0 : rhs.imm.value.u == 0);
        if (rhs_is_zero) {
            out.tested    = 0;
            out.modified  = 0;
            out.set_to_0  = ir::F_CF | ir::F_OF | ir::F_SF;
            out.set_to_1  = ir::F_ZF | ir::F_PF;
            out.undefined = ir::F_AF;
            return;
        }
    }

    if (zi.operand_count_visible < 2) return;
    const auto& d = zops[0];
    const auto& s = zops[1];
    if (d.type != ZYDIS_OPERAND_TYPE_REGISTER) return;
    if (s.type != ZYDIS_OPERAND_TYPE_REGISTER) return;
    if (d.reg.value != s.reg.value) return;

    switch (zi.mnemonic) {
        case ZYDIS_MNEMONIC_XOR:
        case ZYDIS_MNEMONIC_SUB: {
            // Zeroing idiom.
            out.tested    = 0;
            out.modified  = 0;
            out.set_to_0  = ir::F_CF | ir::F_OF | ir::F_SF;
            out.set_to_1  = ir::F_ZF | ir::F_PF;
            out.undefined = ir::F_AF;
            break;
        }
        case ZYDIS_MNEMONIC_AND:
        case ZYDIS_MNEMONIC_OR:
        case ZYDIS_MNEMONIC_TEST: {
            // Identity op: value unchanged, flags set from operand.
            out.tested    = 0;
            out.modified  = ir::F_SF | ir::F_ZF | ir::F_PF;
            out.set_to_0  = ir::F_CF | ir::F_OF;
            out.set_to_1  = 0;
            out.undefined = ir::F_AF;
            break;
        }
        default:
            break;
    }
}

ir::Operand::Kind to_operand_kind(ZydisOperandType t) noexcept {
    switch (t) {
        case ZYDIS_OPERAND_TYPE_REGISTER: return ir::Operand::Kind::Register;
        case ZYDIS_OPERAND_TYPE_IMMEDIATE:return ir::Operand::Kind::Immediate;
        case ZYDIS_OPERAND_TYPE_MEMORY:   return ir::Operand::Kind::Memory;
        case ZYDIS_OPERAND_TYPE_POINTER:  return ir::Operand::Kind::Relative;
        default:                          return ir::Operand::Kind::None;
    }
}

void copy_operand(const ZydisDecodedOperand& zo, ir::Operand& out) {
    out.kind      = to_operand_kind(zo.type);
    out.size_bits = zo.size;
    out.read      = (zo.actions & ZYDIS_OPERAND_ACTION_READ)  != 0;
    out.written   = (zo.actions & ZYDIS_OPERAND_ACTION_WRITE) != 0;
    switch (out.kind) {
        case ir::Operand::Kind::Register:
            out.reg = static_cast<ir::RegisterId>(zo.reg.value);
            break;
        case ir::Operand::Kind::Immediate:
            out.imm = zo.imm.is_signed
                    ? zo.imm.value.s
                    : static_cast<int64_t>(zo.imm.value.u);
            break;
        case ir::Operand::Kind::Memory:
            // ZydisRegister is an `int`-backed enum; our IR stores the
            // arithmetic register ids as uint32_t and the segment register
            // as uint16_t. Be explicit about the narrowing conversion for
            // `segment` so the build doesn't trip /WX on C4244.
            out.mem.base    = static_cast<ir::RegisterId>(zo.mem.base);
            out.mem.index   = static_cast<ir::RegisterId>(zo.mem.index);
            out.mem.scale   = zo.mem.scale;
            out.mem.disp    = zo.mem.disp.has_displacement ? zo.mem.disp.value : 0;
            out.mem.segment = static_cast<uint16_t>(zo.mem.segment);
            break;
        case ir::Operand::Kind::Relative:
            out.imm = zo.ptr.offset;
            break;
        default: break;
    }
}

ZydisDecoder* tl_decoder() {
    thread_local std::unique_ptr<ZydisDecoder> d;
    if (!d) {
        d = std::make_unique<ZydisDecoder>();
        if (ZYAN_FAILED(ZydisDecoderInit(d.get(),
                                         ZYDIS_MACHINE_MODE_LONG_64,
                                         ZYDIS_STACK_WIDTH_64))) {
            d.reset();
            return nullptr;
        }
    }
    return d.get();
}

}  // namespace

Decoder::Decoder() {
    handle_ = tl_decoder();
}
Decoder::~Decoder() = default;

Result<void> Decoder::decode_one(std::span<const uint8_t> code,
                                 uint64_t runtime_va,
                                 uint64_t file_off,
                                 ir::Instruction& out) const {
    return disasm::decode_one(code, runtime_va, file_off, out);
}

Decoder::LinearStats Decoder::linear_sweep(std::span<const uint8_t> code,
                                           uint64_t runtime_va_base,
                                           uint64_t file_off_base,
                                           const std::function<void(const ir::Instruction&)>& visitor) const {
    LinearStats stats;
    size_t i = 0;
    while (i < code.size()) {
        ir::Instruction insn;
        const auto r = disasm::decode_one(code.subspan(i),
                                          runtime_va_base + i,
                                          file_off_base   + i,
                                          insn);
        if (r.ok() && insn.length > 0) {
            visitor(insn);
            i += insn.length;
            ++stats.decoded;
        } else {
            ++stats.skipped;
            ++i;
        }
    }
    return stats;
}

Result<void> decode_one(std::span<const uint8_t> code,
                        uint64_t runtime_va,
                        uint64_t file_off,
                        ir::Instruction& out) {
    auto* dec = tl_decoder();
    if (!dec) {
        return Error::make(ErrorKind::Decode, "Zydis decoder init failed");
    }
    ZydisDecodedInstruction zi{};
    ZydisDecodedOperand     zops[ZYDIS_MAX_OPERAND_COUNT]{};
    const auto status = ZydisDecoderDecodeFull(
        dec, code.data(), code.size(), &zi, zops);
    if (ZYAN_FAILED(status)) {
        return Error::make(ErrorKind::Decode, "Zydis decode failed");
    }

    out.va       = runtime_va;
    out.file_off = file_off;
    out.length   = zi.length;
    out.mnemonic = zi.mnemonic;
    out.category = zi.meta.category;
    std::memcpy(out.bytes.data(), code.data(), zi.length);

    out.op_count = (std::min)(static_cast<uint8_t>(zi.operand_count_visible),
                              static_cast<uint8_t>(ir::kMaxOperands));
    for (uint8_t i = 0; i < out.op_count; ++i) {
        copy_operand(zops[i], out.ops[i]);
    }

    out.flags = {};
    populate_flags(zi, out.flags);
    canonicalise_self_op_flags(zi, zops, out.flags);

    return {};
}

}

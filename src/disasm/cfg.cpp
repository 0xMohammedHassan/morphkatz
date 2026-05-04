#include "morphkatz/disasm/cfg.hpp"

#include "morphkatz/common/logging.hpp"
#include "morphkatz/disasm/decoder.hpp"

#include <Zydis/Zydis.h>

#include <algorithm>
#include <fmt/format.h>
#include <map>
#include <queue>
#include <set>
#include <span>
#include <unordered_map>
#include <unordered_set>

namespace morphkatz::disasm {

std::string BasicBlock::id() const {
    return fmt::format("bb_{:016x}", start_va);
}

size_t Cfg::instruction_count() const noexcept {
    size_t n = 0;
    for (const auto& b : blocks_) n += b.instructions.size();
    return n;
}

namespace {

// Instruction category helpers. We keep these out of the header so users of
// the IR don't need Zydis to inspect a decoded instruction.

bool is_cond_branch(const ir::Instruction& ins) noexcept {
    return ins.category == ZYDIS_CATEGORY_COND_BR;
}

bool is_uncond_branch(const ir::Instruction& ins) noexcept {
    return ins.category == ZYDIS_CATEGORY_UNCOND_BR;
}

bool is_call(const ir::Instruction& ins) noexcept {
    return ins.category == ZYDIS_CATEGORY_CALL;
}

bool is_ret(const ir::Instruction& ins) noexcept {
    return ins.category == ZYDIS_CATEGORY_RET;
}

// Returns direct-branch target VA, or UINT64_MAX for indirect / unresolvable.
uint64_t direct_branch_target(const ir::Instruction& ins) noexcept {
    if (ins.op_count == 0) return UINT64_MAX;
    const auto& op = ins.ops[0];
    if (op.kind == ir::Operand::Kind::Immediate ||
        op.kind == ir::Operand::Kind::Relative) {
        return ins.va + ins.length + static_cast<uint64_t>(op.imm);
    }
    return UINT64_MAX;
}

// Detect jmp qword ptr [rip + disp] and return the pointer VA (the address of
// the 8-byte table entry), or UINT64_MAX if the shape isn't recognised. This
// covers the simplest import-thunk / vtable-style indirect jumps.
uint64_t rip_relative_ptr(const ir::Instruction& ins) noexcept {
    if (ins.op_count == 0) return UINT64_MAX;
    const auto& op = ins.ops[0];
    if (op.kind != ir::Operand::Kind::Memory) return UINT64_MAX;
    // Base register must be RIP, no index, zero scale or scale=1.
    if (op.mem.base != ZYDIS_REGISTER_RIP) return UINT64_MAX;
    if (op.mem.index != 0) return UINT64_MAX;
    return ins.va + ins.length + static_cast<uint64_t>(op.mem.disp);
}

// Read an aligned little-endian uint64 from an image offset. Returns
// UINT64_MAX on out-of-range.
uint64_t read_u64_at_file_off(const format::PeImage& img, uint64_t off) noexcept {
    const auto b = img.bytes();
    if (off + 8 > b.size()) return UINT64_MAX;
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v |= static_cast<uint64_t>(b[off + i]) << (i * 8);
    return v;
}

bool is_within_code_sections(const format::PeImage& img, uint64_t va) noexcept {
    for (const auto& s : img.code_sections()) {
        const uint64_t start = s.image_base + s.virtual_addr;
        const uint64_t end   = start + s.virtual_size;
        if (va >= start && va < end) return true;
    }
    return false;
}

// Try to translate a VA into a file offset using the image's section map. Note
// that `file_to_va` expects the complementary direction; we reproduce the
// forward mapping here to avoid importing extra helpers into this TU.
bool va_to_file(const format::PeImage& img, uint64_t va, uint64_t& out_off) noexcept {
    for (const auto& s : img.code_sections()) {
        const uint64_t start = s.image_base + s.virtual_addr;
        const uint64_t end   = start + s.virtual_size;
        if (va >= start && va < end) {
            out_off = s.raw_offset + (va - start);
            return true;
        }
    }
    return false;
}

// Backward slice across a linear window of already-decoded instructions to
// recover jump tables. We look at up to `kBackwardWindow` preceding
// instructions and match the GCC/MSVC canonical shapes:
//
//    lea  base_reg, [rip + table_disp]
//    ... (movsxd | mov) idx_reg, dword ptr [base_reg + idx*4]
//    add  target_reg, base_reg
//    jmp  target_reg
//
// or the simpler:
//
//    jmp  qword ptr [rip + table_disp + idx*8]
//
// If the sliced window yields a plausible table base and a conservative upper
// bound (from a preceding cmp against an immediate), enumerate entries.
//
// `window` must be contiguous and end with `indirect_jmp`.
constexpr size_t kBackwardWindow = 32;

std::vector<uint64_t> recover_jump_table(const format::PeImage& img,
                                         std::span<const ir::Instruction> window,
                                         const ir::Instruction& indirect_jmp) {
    std::vector<uint64_t> targets;
    if (window.empty()) return targets;

    // Case 1: jmp qword ptr [rip + disp] -> single entry.
    if (const auto ptr_va = rip_relative_ptr(indirect_jmp); ptr_va != UINT64_MAX) {
        uint64_t off = 0;
        if (va_to_file(img, ptr_va, off)) {
            const auto tgt = read_u64_at_file_off(img, off);
            if (tgt != UINT64_MAX && is_within_code_sections(img, tgt)) {
                targets.push_back(tgt);
            }
        }
        return targets;
    }

    // Case 2: indirect register jump. Walk backwards looking for an explicit
    // `lea base_reg, [rip+disp]` and a nearby bound. We only walk within the
    // caller-supplied window (usually the enclosing basic block).
    uint64_t table_base_va = UINT64_MAX;
    uint32_t table_entry_size = 0;
    uint64_t bound = UINT64_MAX;

    // Scan right-to-left (the jump is at window.back()).
    for (size_t i = window.size(); i-- > 0; ) {
        const auto& w = window[i];

        // LEA reg, [rip + disp] => table base.
        if (w.mnemonic == ZYDIS_MNEMONIC_LEA && w.op_count >= 2) {
            const auto& dst = w.ops[0];
            const auto& src = w.ops[1];
            if (dst.kind == ir::Operand::Kind::Register &&
                src.kind == ir::Operand::Kind::Memory   &&
                src.mem.base == ZYDIS_REGISTER_RIP) {
                table_base_va = w.va + w.length + static_cast<uint64_t>(src.mem.disp);
            }
        }

        // MOV reg, dword/qword ptr [base + idx*scale] => entry size.
        if ((w.mnemonic == ZYDIS_MNEMONIC_MOV || w.mnemonic == ZYDIS_MNEMONIC_MOVSXD) &&
            w.op_count >= 2) {
            const auto& src = w.ops[1];
            if (src.kind == ir::Operand::Kind::Memory && src.mem.scale >= 1) {
                table_entry_size = src.mem.scale;
            }
        }

        // CMP reg, imm => upper bound (inclusive in CMP/JA, exclusive in CMP/JAE;
        // we take the larger/safer bound + 1).
        if (w.mnemonic == ZYDIS_MNEMONIC_CMP && w.op_count >= 2) {
            const auto& rhs = w.ops[1];
            if (rhs.kind == ir::Operand::Kind::Immediate &&
                rhs.imm >= 0 && rhs.imm < 8192) {
                bound = static_cast<uint64_t>(rhs.imm) + 1;
            }
        }
    }

    if (table_base_va == UINT64_MAX || table_entry_size == 0 || bound == UINT64_MAX) {
        return targets;
    }

    // Sanity: refuse huge tables to avoid mis-parsing data sections as jump targets.
    if (bound > 4096) bound = 4096;

    uint64_t base_off = 0;
    if (!va_to_file(img, table_base_va, base_off)) return targets;
    const auto bytes = img.bytes();

    for (uint64_t k = 0; k < bound; ++k) {
        const uint64_t entry_off = base_off + k * table_entry_size;
        if (entry_off + table_entry_size > bytes.size()) break;

        uint64_t target = UINT64_MAX;
        if (table_entry_size == 4) {
            uint32_t raw = 0;
            for (int i = 0; i < 4; ++i) raw |= static_cast<uint32_t>(bytes[entry_off + i]) << (i * 8);
            // GCC compact tables store (target - table_base) as int32; add base.
            target = table_base_va + static_cast<int32_t>(raw);
        } else if (table_entry_size == 8) {
            target = read_u64_at_file_off(img, entry_off);
        } else {
            break;  // unusual stride; give up quietly
        }
        if (target != UINT64_MAX && is_within_code_sections(img, target)) {
            targets.push_back(target);
        } else {
            break;  // walked off the end of the table into non-code
        }
    }
    return targets;
}

}  // namespace

std::vector<BasicBlock> linear_sweep_blocks(const format::PeImage& img) {
    std::vector<BasicBlock> out;
    Decoder dec;
    for (const auto& sec : img.code_sections()) {
        if (sec.raw_offset + sec.raw_size > img.bytes().size()) continue;
        BasicBlock bb;
        bb.start_va  = sec.image_base + sec.virtual_addr;
        bb.end_va    = bb.start_va + sec.virtual_size;
        bb.start_off = sec.raw_offset;
        auto body = std::span<const uint8_t>(img.bytes().data() + sec.raw_offset, sec.raw_size);
        dec.linear_sweep(body, bb.start_va, sec.raw_offset,
            [&](const ir::Instruction& ins) { bb.instructions.push_back(ins); });
        out.push_back(std::move(bb));
    }
    return out;
}

Result<std::unique_ptr<Cfg>> build_cfg(const format::PeImage& img) {
    auto seeds = img.code_entry_seeds();
    if (seeds.empty()) {
        auto linear = linear_sweep_blocks(img);
        if (linear.empty()) {
            return Error::make(ErrorKind::Invalid, "no seeds and no executable sections");
        }
        return std::make_unique<Cfg>(std::move(linear));
    }

    // Pass 1: decode everything reachable from seeds, remember leaders.
    std::unordered_map<uint64_t, ir::Instruction> decoded;   // va -> insn
    std::unordered_map<uint64_t, uint64_t>        prev_va;   // fall-through predecessor map
    std::unordered_set<uint64_t>                   leaders;
    std::queue<uint64_t>                           work;
    for (auto s : seeds) { work.push(s); leaders.insert(s); }

    auto va_to_off = [&](uint64_t va, uint64_t& out) -> bool {
        return va_to_file(img, va, out);
    };

    // Walk backwards from `jmp_va` following `prev_va` for up to
    // `kBackwardWindow` hops. Linear time per recovery attempt.
    auto contiguous_window = [&](uint64_t jmp_va) -> std::vector<ir::Instruction> {
        std::vector<uint64_t> back_vas;
        uint64_t cur = jmp_va;
        for (size_t i = 0; i < kBackwardWindow; ++i) {
            auto it = decoded.find(cur);
            if (it == decoded.end()) break;
            back_vas.push_back(cur);
            auto pv = prev_va.find(cur);
            if (pv == prev_va.end()) break;
            cur = pv->second;
        }
        std::reverse(back_vas.begin(), back_vas.end());
        std::vector<ir::Instruction> w;
        w.reserve(back_vas.size());
        for (auto v : back_vas) {
            auto it = decoded.find(v);
            if (it != decoded.end()) w.push_back(it->second);
        }
        return w;
    };

    while (!work.empty()) {
        uint64_t va = work.front(); work.pop();
        uint64_t predecessor = UINT64_MAX;
        while (decoded.find(va) == decoded.end()) {
            uint64_t off = 0;
            if (!va_to_off(va, off)) break;
            if (off >= img.bytes().size()) break;
            const auto remaining = img.bytes().size() - off;
            ir::Instruction ins;
            const auto r = disasm::decode_one(
                std::span<const uint8_t>(img.bytes().data() + off, remaining),
                va, off, ins);
            if (!r.ok() || ins.length == 0) break;
            decoded.emplace(va, ins);
            if (predecessor != UINT64_MAX) prev_va.emplace(va, predecessor);

            const uint64_t fallthrough = va + ins.length;

            if (is_cond_branch(ins)) {
                const auto tgt = direct_branch_target(ins);
                if (tgt != UINT64_MAX) {
                    if (leaders.insert(tgt).second) work.push(tgt);
                }
                if (leaders.insert(fallthrough).second) work.push(fallthrough);
                break;  // end of block via conditional
            }
            if (is_uncond_branch(ins)) {
                const auto tgt = direct_branch_target(ins);
                if (tgt != UINT64_MAX) {
                    if (leaders.insert(tgt).second) work.push(tgt);
                } else {
                    // Indirect jump: try recovery.
                    auto cw = contiguous_window(va);
                    auto tgts = recover_jump_table(img, cw, ins);
                    for (auto t : tgts) {
                        if (leaders.insert(t).second) work.push(t);
                    }
                }
                break;  // end of block via unconditional
            }
            if (is_ret(ins) || ins.category == ZYDIS_CATEGORY_INTERRUPT) {
                break;  // end of block via return/int
            }
            if (is_call(ins)) {
                const auto tgt = direct_branch_target(ins);
                if (tgt != UINT64_MAX) {
                    if (leaders.insert(tgt).second) work.push(tgt);
                }
            }
            predecessor = va;
            va = fallthrough;
        }
    }

    if (decoded.empty()) {
        MK_DEBUG("CFG: seeds decoded no instructions -> linear sweep fallback");
        auto linear = linear_sweep_blocks(img);
        if (linear.empty()) {
            return Error::make(ErrorKind::Invalid, "no seeds and no executable sections");
        }
        return std::make_unique<Cfg>(std::move(linear));
    }

    // Pass 2: collect block leaders from fall-through predecessors so every
    // instruction that is the successor of a terminator becomes a leader.
    // We already pushed conditional/unconditional branch targets above; add
    // the fall-through of every terminator here.
    std::vector<uint64_t> sorted_vas;
    sorted_vas.reserve(decoded.size());
    for (const auto& kv : decoded) sorted_vas.push_back(kv.first);
    std::sort(sorted_vas.begin(), sorted_vas.end());

    // Pass 3: emit blocks. A block starts at a leader and runs until the next
    // leader-or-terminator.
    std::map<uint64_t, BasicBlock> by_va;
    std::set<uint64_t>             leader_set(leaders.begin(), leaders.end());
    if (leader_set.empty()) leader_set.insert(sorted_vas.front());

    for (auto lead : leader_set) {
        auto it = std::lower_bound(sorted_vas.begin(), sorted_vas.end(), lead);
        if (it == sorted_vas.end() || *it != lead) continue;

        BasicBlock bb;
        bb.start_va  = lead;
        uint64_t off = 0;
        va_to_off(lead, off);
        bb.start_off = off;

        uint64_t va = lead;
        while (true) {
            auto ins_it = decoded.find(va);
            if (ins_it == decoded.end()) break;
            bb.instructions.push_back(ins_it->second);
            const uint64_t next_va = va + ins_it->second.length;

            if (is_cond_branch(ins_it->second)) {
                const auto tgt = direct_branch_target(ins_it->second);
                if (tgt != UINT64_MAX) bb.successors.push_back(tgt);
                bb.successors.push_back(next_va);
                va = next_va;
                bb.end_va = next_va;
                break;
            }
            if (is_uncond_branch(ins_it->second)) {
                const auto tgt = direct_branch_target(ins_it->second);
                if (tgt != UINT64_MAX) bb.successors.push_back(tgt);
                bb.end_va = next_va;
                break;
            }
            if (is_ret(ins_it->second) || ins_it->second.category == ZYDIS_CATEGORY_INTERRUPT) {
                bb.end_va = next_va;
                break;
            }
            // If we reach another leader, split here.
            if (next_va != lead && leader_set.count(next_va)) {
                bb.successors.push_back(next_va);
                bb.end_va = next_va;
                break;
            }
            va = next_va;
        }
        if (bb.instructions.empty()) continue;
        if (bb.end_va == 0) bb.end_va = va;
        by_va.emplace(bb.start_va, std::move(bb));
    }

    std::vector<BasicBlock> blocks;
    blocks.reserve(by_va.size());
    for (auto& [k, v] : by_va) blocks.push_back(std::move(v));

    MK_DEBUG("CFG: {} seeds -> {} leaders -> {} blocks ({} total insns)",
              seeds.size(), leader_set.size(), blocks.size(), decoded.size());
    return std::make_unique<Cfg>(std::move(blocks));
}

}

#include "morphkatz/analysis/flag_liveness.hpp"

#include "morphkatz/common/logging.hpp"

#include <algorithm>
#include <unordered_set>

namespace morphkatz::analysis {

namespace {

// Per-block use/def summary. `def` covers every flag that the block definitely
// overwrites before any downstream read, no matter how it overwrites
// (modified, set_to_0, set_to_1, or undefined). `use` is the set of flags
// tested before any def in the block.
struct BlockSummary {
    uint32_t use_ = 0;
    uint32_t def_ = 0;
};

BlockSummary summarise(const disasm::BasicBlock& bb) noexcept {
    BlockSummary s;
    uint32_t defined_so_far = 0;
    for (const auto& ins : bb.instructions) {
        const uint32_t tested_here   = ins.flags.tested;
        const uint32_t modified_here =
            ins.flags.modified | ins.flags.set_to_0 |
            ins.flags.set_to_1 | ins.flags.undefined;

        s.use_         |= (tested_here & ~defined_so_far);
        defined_so_far |= modified_here;
    }
    s.def_ = defined_so_far;
    return s;
}

}  // namespace

uint32_t FlagLiveness::live_out_at(uint64_t insn_va) const noexcept {
    auto it = per_insn.find(insn_va);
    if (it != per_insn.end()) return it->second;
    return ir::F_ALL_ARITH;   // conservative default
}

FlagLiveness compute_flag_liveness(const disasm::Cfg& cfg) {
    FlagLiveness out;
    if (cfg.blocks().empty()) return out;

    // Index blocks by start VA and by VA -> block, so successor VAs resolve.
    std::unordered_map<uint64_t, const disasm::BasicBlock*> by_start;
    by_start.reserve(cfg.blocks().size());
    for (const auto& b : cfg.blocks()) by_start[b.start_va] = &b;

    std::unordered_map<uint64_t, BlockSummary> sums;
    sums.reserve(cfg.blocks().size());
    for (const auto& b : cfg.blocks()) sums[b.start_va] = summarise(b);

    // Iterative fixed-point (worklist) over reverse postorder.
    for (const auto& b : cfg.blocks()) {
        out.live_in[b.start_va]  = 0;
        out.live_out[b.start_va] = 0;
    }

    bool changed = true;
    int iterations = 0;
    while (changed && iterations < 64) {
        changed = false;
        ++iterations;
        for (const auto& b : cfg.blocks()) {
            uint32_t lo = 0;
            if (b.successors.empty()) {
                // No known successor: this is either a return or an
                // unresolved indirect jump. Be conservative: assume all
                // arithmetic flags are live.
                lo = ir::F_ALL_ARITH;
            } else {
                for (auto s : b.successors) {
                    auto it = by_start.find(s);
                    if (it == by_start.end()) {
                        lo |= ir::F_ALL_ARITH;  // unresolved target
                    } else {
                        lo |= out.live_in[it->first];
                    }
                }
            }
            const auto& su = sums[b.start_va];
            const uint32_t li = su.use_ | (lo & ~su.def_);
            if (out.live_out[b.start_va] != lo) {
                out.live_out[b.start_va] = lo;
                changed = true;
            }
            if (out.live_in[b.start_va] != li) {
                out.live_in[b.start_va] = li;
                changed = true;
            }
        }
    }

    // Per-instruction liveness: walk each block backward, with live_out at
    // the tail seeded from the block's live_out.
    out.per_insn.reserve(cfg.instruction_count());
    for (const auto& b : cfg.blocks()) {
        uint32_t live = out.live_out[b.start_va];
        for (auto it = b.instructions.rbegin(); it != b.instructions.rend(); ++it) {
            const auto& ins = *it;
            // The instruction's live-out is `live`. Store that for callers.
            out.per_insn[ins.va] = live;
            const uint32_t modified_here =
                ins.flags.modified | ins.flags.set_to_0 |
                ins.flags.set_to_1 | ins.flags.undefined;
            live = ins.flags.tested | (live & ~modified_here);
        }
    }

    MK_TRACE("flag liveness: {} blocks in {} iterations", cfg.blocks().size(), iterations);
    return out;
}

}

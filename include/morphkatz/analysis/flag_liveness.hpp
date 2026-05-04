#pragma once

#include "morphkatz/disasm/cfg.hpp"
#include "morphkatz/ir/flags_effect.hpp"

#include <cstdint>
#include <unordered_map>
#include <vector>

namespace morphkatz::analysis {

// Per-block flag liveness result. live_out[bb] is the set of EFLAGS bits that
// are read by any downstream instruction reachable from `bb`. live_out[bb]
// drives the per-instruction liveness used by `live_out_at`.
struct FlagLiveness {
    std::unordered_map<uint64_t, uint32_t> live_out;   // bb.start_va -> mask
    std::unordered_map<uint64_t, uint32_t> live_in;    // bb.start_va -> mask

    // Liveness for the instruction at `insn_va`: returns the flags live after
    // this instruction executes. Falls back to the block's live_out when the
    // VA is unknown, which is safe (over-approximation).
    [[nodiscard]] uint32_t live_out_at(uint64_t insn_va) const noexcept;

    // Fully precomputed per-instruction liveness, populated by build().
    // Key: instruction VA. Value: mask of flags live immediately after it.
    std::unordered_map<uint64_t, uint32_t> per_insn;
};

// Compute live-out flag sets for every block in the CFG using an iterative
// backward dataflow pass. Missing successors (tail-calls, unresolved indirect
// jumps, returns) conservatively inherit F_ALL_ARITH so we never under-approx.
[[nodiscard]] FlagLiveness compute_flag_liveness(const disasm::Cfg& cfg);

}

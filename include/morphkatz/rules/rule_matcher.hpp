#pragma once

#include "morphkatz/common/error.hpp"
#include "morphkatz/ir/instruction.hpp"
#include "morphkatz/rules/rule.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace morphkatz::analysis { struct FlagLiveness; }
namespace morphkatz::disasm  { struct BasicBlock; }
namespace morphkatz::yara_target { class PriorityMap; }
namespace morphkatz::scan        { class DefenderTarget; }

namespace morphkatz::rules {

class RulePack;

// A single candidate rewrite: original instruction + rule + expected encoding.
struct Candidate {
    const Rule*      rule          = nullptr;
    ir::Instruction  source;        // the instruction being replaced
    std::vector<uint8_t> new_bytes; // encoded replacement (before padding)
    int32_t          size_delta    = 0;  // len(old) - len(new); positive = need pad
    double           weight        = 1.0;
    // Optional priority boost if the target YARA rule atoms overlap.
    double           priority_boost = 0.0;
};

class RuleMatcher {
public:
    RuleMatcher(const RulePack& pack,
                const yara_target::PriorityMap* yara,
                const analysis::FlagLiveness*   liveness = nullptr,
                const scan::DefenderTarget*     defender = nullptr);

    // Evaluate every instruction in the block; returns a flat list of
    // candidates. The matcher is stateless; all rule-pack lookups happen
    // through `pack_` and per-candidate scoring through `yara_` /
    // `defender_` / `liveness_`.
    [[nodiscard]] std::vector<Candidate> evaluate(const disasm::BasicBlock& block) const;

    // Evaluate a single instruction in isolation. Primarily for unit tests.
    [[nodiscard]] std::vector<Candidate> evaluate_one(const ir::Instruction& insn) const;

private:
    const RulePack&                    pack_;
    const yara_target::PriorityMap*    yara_     = nullptr;
    const analysis::FlagLiveness*      liveness_ = nullptr;
    const scan::DefenderTarget*        defender_ = nullptr;
};

}

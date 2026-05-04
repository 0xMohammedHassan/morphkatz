#include "morphkatz/rules/rule_matcher.hpp"

#include "morphkatz/analysis/flag_liveness.hpp"
#include "morphkatz/common/logging.hpp"
#include "morphkatz/disasm/cfg.hpp"
#include "morphkatz/disasm/decoder.hpp"
#include "morphkatz/engine/encoder.hpp"
#include "morphkatz/rules/rule_loader.hpp"
#include "morphkatz/scan/defender_target.hpp"
#include "morphkatz/yara/yara_target.hpp"

#include <span>

namespace morphkatz::rules {

namespace {

// Decode `bytes` once so the matcher can compare the rewrite's flags effect
// against the source's. Returns a zeroed FlagsEffect when decoding fails so
// conservative rules still get rejected.
ir::FlagsEffect decode_flags(const std::vector<uint8_t>& bytes) {
    ir::FlagsEffect fe{};
    if (bytes.empty()) return fe;
    ir::Instruction tmp;
    auto r = disasm::decode_one(std::span<const uint8_t>(bytes.data(), bytes.size()),
                                0, 0, tmp);
    if (r.ok()) fe = tmp.flags;
    return fe;
}

// Return true iff the rule is safe to apply given the observed flag liveness
// at this instruction.
bool flags_safe(const Rule& rule,
                const ir::FlagsEffect& src,
                const ir::FlagsEffect& dst,
                uint32_t live_out) {
    switch (rule.flags_effect) {
        case FlagsEquivalence::Equivalent:
            // Strict: no value-diff masks allowed in this mode.
            return src.equivalent_to(dst) && rule.flags_value_diff_mask == 0;
        case FlagsEquivalence::EquivalentIfDead: {
            // Both mechanically-different flag effects (decoder-derived)
            // and author-declared value differences must be dead at the
            // use site. Authors declare value differences when the
            // *modified* sets agree but the *computed values* differ -
            // e.g. SUB vs ADD both touching CF/OF/AF.
            const uint32_t diffs =
                src.differences(dst) | rule.flags_value_diff_mask;
            return (diffs & live_out) == 0;
        }
        case FlagsEquivalence::NotVerified:
            // The rule author explicitly opted out of flags checks. Accept.
            return true;
    }
    return false;
}

}  // namespace

RuleMatcher::RuleMatcher(const RulePack& pack,
                         const yara_target::PriorityMap* yara,
                         const analysis::FlagLiveness*   liveness,
                         const scan::DefenderTarget*     defender)
    : pack_(pack), yara_(yara), liveness_(liveness), defender_(defender) {}

std::vector<Candidate> RuleMatcher::evaluate_one(const ir::Instruction& insn) const {
    std::vector<Candidate> out;
    const uint32_t live_out =
        liveness_ ? liveness_->live_out_at(insn.va) : ir::F_ALL_ARITH;

    for (const auto& rule : pack_.rules()) {
        // Raw-byte rules are whole-image Aho-Corasick patterns handled by
        // Patcher::queue_raw() directly out of the orchestrator. They are
        // not per-instruction rewrites and must never be matched here —
        // doing so would splice the raw bytes into arbitrary instruction
        // slots whose `file_off` has no relationship with the pattern.
        if (rule.raw_from) continue;
        if (!rule.compiled_predicate) continue;
        if (!rule.compiled_predicate(insn)) continue;

        auto enc = engine::encode_rewrite(insn, rule);
        if (!enc.ok()) {
            MK_TRACE("rule {} matched but encode failed: {}", rule.id, enc.error().what);
            continue;
        }

        const auto dst_flags = decode_flags(*enc);
        if (!flags_safe(rule, insn.flags, dst_flags, live_out)) {
            MK_TRACE("rule {} rejected by flags gate (live_out=0x{:x})",
                      rule.id, live_out);
            continue;
        }

        Candidate c;
        c.rule       = &rule;
        c.source     = insn;
        c.new_bytes  = std::move(*enc);
        c.size_delta = static_cast<int32_t>(insn.length) - static_cast<int32_t>(c.new_bytes.size());
        c.weight     = rule.weight;
        if (yara_) {
            c.priority_boost = yara_->boost_for(
                insn.va,
                std::span<const uint8_t>(insn.bytes.data(), insn.length),
                c.new_bytes);
        }
        if (defender_) {
            // Defender boost is additive on top of YARA boost; the
            // matcher folds boosts as `weight * (1 + sum)`. Confirmed
            // anchors dominate any YARA contribution for the same VA
            // because they represent a real deployed-engine signature.
            c.priority_boost += defender_->priority_for_va(
                insn.va,
                std::span<const uint8_t>(insn.bytes.data(), insn.length),
                c.new_bytes);
        }
        out.push_back(std::move(c));
    }
    return out;
}

std::vector<Candidate> RuleMatcher::evaluate(const disasm::BasicBlock& block) const {
    std::vector<Candidate> out;
    for (const auto& insn : block.instructions) {
        auto cs = evaluate_one(insn);
        out.insert(out.end(),
                   std::make_move_iterator(cs.begin()),
                   std::make_move_iterator(cs.end()));
    }
    return out;
}

}

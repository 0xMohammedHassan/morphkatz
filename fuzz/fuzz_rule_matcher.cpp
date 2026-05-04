// libFuzzer entry point for the decoder + rule-matcher pipeline.
//
// The harness feeds fuzzer-controlled bytes through decode_one and builds a
// synthetic BasicBlock of whatever decodes cleanly, then runs the matcher
// over it. The goal is to catch:
//   - decoder crashes on malformed x86-64 byte sequences,
//   - rule-predicate crashes on unexpected operand kinds,
//   - flag-liveness dataflow bugs on degenerate single-block CFGs.
//
// The matcher runs against an empty rule pack by design — the production
// YAML rules are covered by unit tests. This harness is a safety net for
// crashes in the decode/predicate scaffolding on adversarial byte input.

#include "morphkatz/analysis/flag_liveness.hpp"
#include "morphkatz/disasm/cfg.hpp"
#include "morphkatz/disasm/decoder.hpp"
#include "morphkatz/ir/instruction.hpp"
#include "morphkatz/rules/rule_matcher.hpp"
#include "morphkatz/rules/rule_loader.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

using namespace morphkatz;

namespace {

rules::RulePack& shared_pack() {
    static rules::RulePack pack(std::vector<rules::Rule>{},
                                std::vector<std::string>{});
    return pack;
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size == 0 || size > 4096) return 0;

    std::span<const uint8_t> code(data, size);

    disasm::BasicBlock bb;
    bb.start_va  = 0x1000;
    bb.end_va    = 0x1000;
    bb.start_off = 0;

    size_t cursor = 0;
    while (cursor < size) {
        ir::Instruction insn;
        auto r = disasm::decode_one(code.subspan(cursor),
                                    bb.start_va + cursor,
                                    bb.start_off + cursor,
                                    insn);
        if (!r.ok() || insn.length == 0) {
            ++cursor;   // mirror the linear-sweep fallback
            continue;
        }
        cursor += insn.length;
        bb.end_va = bb.start_va + cursor;
        bb.instructions.push_back(std::move(insn));
    }

    if (bb.instructions.empty()) return 0;

    disasm::Cfg cfg(std::vector<disasm::BasicBlock>{bb});
    auto live = analysis::compute_flag_liveness(cfg);

    rules::RuleMatcher matcher(shared_pack(), nullptr, &live);
    auto cands = matcher.evaluate(cfg.blocks().front());
    (void)cands;
    return 0;
}

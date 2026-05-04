#pragma once

#include "morphkatz/common/error.hpp"
#include "morphkatz/rules/rule_matcher.hpp"

#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <vector>

namespace morphkatz::format { class PeImage; }
namespace morphkatz::disasm { struct BasicBlock; }
namespace morphkatz::report { class DiffReport; }
namespace morphkatz::engine { class PadPolicy; }

namespace morphkatz::engine {

// Records one successfully applied patch. Consumed by verifier and report.
struct AppliedPatch {
    uint64_t    file_offset = 0;
    uint64_t    va          = 0;
    std::vector<uint8_t> old_bytes;
    std::vector<uint8_t> new_bytes;
    std::string rule_id;
    std::string block_id;
};

// Byte-level patcher. Uses an Aho-Corasick automaton for multi-pattern
// matching across the section when rules produce identical (old,new) pairs.
// For single-offset exact rewrites (the common case when the candidate came
// from our own disassembly) it applies directly at the known file offset.
class Patcher {
public:
    Patcher();
    ~Patcher();

    // Queue the chosen rewrites for a block. Pad policy is applied here.
    void queue_block(const disasm::BasicBlock& block,
                     std::vector<rules::Candidate> chosen,
                     PadPolicy& pad,
                     report::DiffReport& report);

    [[nodiscard]] size_t queued_count() const noexcept;

    // Queue a raw-byte replacement (targeted/* rules with raw_from/raw_to).
    void queue_raw(std::span<const uint8_t> from,
                   std::span<const uint8_t> to,
                   std::string rule_id);

    // Apply every queued patch to the image. Returns the accepted applications.
    // `report` (optional) receives one entry per raw-byte Aho-Corasick hit so
    // the diff report captures targeted rules in addition to per-instruction
    // rewrites (which are recorded at queue_block time).
    [[nodiscard]] std::vector<AppliedPatch> apply(format::PeImage& image,
                                                  report::DiffReport* report = nullptr);

    // Restore the original bytes for every applied patch. Used by the
    // orchestrator when verification fails and the user has opted in to
    // rollback on mismatch. The caller passes the list returned by apply().
    static size_t rollback(format::PeImage& image,
                           std::span<const AppliedPatch> applied);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}

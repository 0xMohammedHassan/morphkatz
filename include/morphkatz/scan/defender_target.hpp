#pragma once

#include "morphkatz/common/error.hpp"
#include "morphkatz/scan/bisect.hpp"
#include "morphkatz/scan/scanner.hpp"

#include <cstdint>
#include <filesystem>
#include <memory>
#include <span>
#include <string>
#include <vector>

namespace morphkatz::scan {

// Orchestrator-side wrapper that mirrors the existing YaraTarget API.
// Constructed once per `morphkatz <input> --target-defender <ref>` run,
// it owns the live `IDefenderScanner`, performs the pre-mutation probe
// (initial scan + per-threat single-anchor bisect), exposes a per-VA
// boost weight that the rule matcher consults alongside YARA, and
// post-mutation evaluates which detections survived.
//
// One DefenderTarget => one reference binary. The orchestrator can have
// at most one (no list) - cloud SLA and wall-clock budget make it
// pointless to chain multiple Defender targets.
class DefenderTarget {
public:
    // Single anchor learned during `probe()`. The CFG-aware rule matcher
    // looks up `priority_for_va` to get a multiplicative weight boost
    // for any candidate rewrite whose target VA falls inside [va, va + size).
    struct Anchor {
        std::vector<uint8_t> bytes;       // verbatim signature bytes
        uint64_t             file_offset = 0;
        uint64_t             rva         = 0;
        uint64_t             va          = 0;
        std::string          section;
        std::string          section_kind;
        std::string          threat_name;  // attribution
        BisectResult::Status status = BisectResult::Status::NoOp;
    };

    // Diff between pre- and post-mutation scans, used by the report.
    struct DiffStats {
        std::vector<std::string> broken;       // gone after mutation
        std::vector<std::string> persisted;    // still flagged
        std::vector<std::string> introduced;   // new detections (regression)
    };

    // Construct a DefenderTarget for `target` using a pre-built scanner.
    // The scanner is moved in; the target owns it for its lifetime.
    [[nodiscard]] static Result<DefenderTarget> from_file(
        std::filesystem::path           target,
        std::shared_ptr<IDefenderScanner> scanner);

    DefenderTarget(const DefenderTarget&) = delete;
    DefenderTarget& operator=(const DefenderTarget&) = delete;
    DefenderTarget(DefenderTarget&&) noexcept;
    DefenderTarget& operator=(DefenderTarget&&) noexcept;
    ~DefenderTarget();

    // Pre-mutation scan + bisect. Populates pre_threats() and anchors().
    // Idempotent; calling twice is a no-op after the first success.
    [[nodiscard]] Result<void> probe();

    // Per-VA additive boost for the orchestrator's rule matcher.
    // Returns 0.0 when the VA doesn't intersect any anchor; > 0.0 when
    // it does. Convention matches `yara_target::PriorityMap::boost_for`:
    // the matcher folds boosts into weight as `weight * (1 + sum)`.
    [[nodiscard]] double priority_for_va(uint64_t va,
                                         std::span<const uint8_t> old_bytes,
                                         std::span<const uint8_t> new_bytes) const noexcept;

    // Post-mutation re-scan against the saved output binary. Computes
    // broken / persisted / introduced relative to `pre_threats()`.
    [[nodiscard]] Result<DiffStats> evaluate_after_mutation(
        const std::filesystem::path& mutated_path);

    [[nodiscard]] const std::vector<Threat>& pre_threats() const noexcept;
    [[nodiscard]] const std::vector<Anchor>& anchors() const noexcept;
    [[nodiscard]] const std::string& engine_label() const noexcept;
    [[nodiscard]] bool probed() const noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;

    DefenderTarget();
};

}

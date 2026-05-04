#pragma once

#include "morphkatz/common/error.hpp"

#include <cstdint>
#include <filesystem>
#include <memory>
#include <span>
#include <string>
#include <vector>

namespace morphkatz::yara_target {

// Result of scanning a YARA rule file: per-rule byte atoms plus a weight
// boost applied by RuleMatcher when a candidate rewrite overlaps an atom.
// Also exposes a one-shot scan() for before/after comparison.
class PriorityMap {
public:
    struct Atom {
        std::vector<uint8_t> bytes;
        std::string          rule_name;
        double               weight = 1.0;
    };

    // Forward declaration of PIMPL; defined in yara_target.cpp so callers
    // do not need to include <yara.h>.
    struct Compiled;

    PriorityMap(std::vector<Atom> atoms,
                size_t rule_count,
                std::unique_ptr<Compiled> compiled);

    // Atoms-only overload: constructs a PriorityMap with no compiled YARA
    // rule context. Intended for tests and for non-YARA-enabled builds that
    // still want boost_for() evaluation. Defined out-of-line so callers do
    // not need the full `Compiled` type (it lives behind a PIMPL).
    PriorityMap(std::vector<Atom> atoms, size_t rule_count);

    ~PriorityMap();
    PriorityMap(PriorityMap&&) noexcept;
    PriorityMap& operator=(PriorityMap&&) noexcept;
    PriorityMap(const PriorityMap&) = delete;
    PriorityMap& operator=(const PriorityMap&) = delete;

    [[nodiscard]] size_t atom_count() const noexcept { return atoms_.size(); }
    [[nodiscard]] size_t rule_count() const noexcept { return rule_count_; }
    [[nodiscard]] const std::vector<Atom>& atoms() const noexcept { return atoms_; }

    // Boost = max over atoms that the candidate patch would break by covering
    // at least one byte of an atom at the given VA. Called once per candidate
    // by RuleMatcher.
    [[nodiscard]] double boost_for(uint64_t va,
                                   std::span<const uint8_t> old_bytes,
                                   std::span<const uint8_t> new_bytes) const noexcept;

    // Scan `data` against the compiled YARA rules. Returns the names of all
    // rules that matched. Returns empty if YARA was not built in.
    [[nodiscard]] std::vector<std::string> scan(std::span<const uint8_t> data) const;

    // One concrete YARA hit: which rule matched, where in `data` it
    // matched, and the literal bytes that matched. Atoms longer than
    // 16 bytes are truncated by libyara's own AC layer; we surface
    // whatever YARA reports and let the consumer trim further.
    struct MatchHit {
        std::string          rule_name;
        size_t               offset = 0;       // file offset into the scanned buffer
        size_t               length = 0;
        std::vector<uint8_t> bytes;            // copy of the matched bytes
    };

    // Like `scan`, but also returns per-string match offsets and the
    // literal bytes that matched. Used by the data-morph atom
    // discovery layer; equivalent to `scan` for backward callers.
    [[nodiscard]] std::vector<MatchHit>
    scan_with_offsets(std::span<const uint8_t> data) const;

private:
    std::vector<Atom>         atoms_;
    size_t                    rule_count_ = 0;
    std::unique_ptr<Compiled> compiled_;
};

Result<std::unique_ptr<PriorityMap>> load(const std::filesystem::path& yar_file);

}

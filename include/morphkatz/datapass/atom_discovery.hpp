#pragma once

#include "morphkatz/common/error.hpp"
#include "morphkatz/datapass/atom.hpp"
#include "morphkatz/scan/bisect.hpp"
#include "morphkatz/yara/yara_target.hpp"

#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace LIEF::PE { class Binary; }
namespace morphkatz::format { class PeImage; }

namespace morphkatz::datapass {

// One atom candidate that didn't pass the filter, with the reason. Used
// only by the `--data-morph plan` output and the report; not consumed
// by the encoding stage.
struct SkippedCandidate {
    uint64_t    file_offset = 0;
    uint32_t    length      = 0;
    std::string section;
    std::string source;
    SkipReason  reason      = SkipReason::None;
};

// Aggregate result of `discover_atoms`. Atoms in `atoms` survived all
// filters and are ready to be handed to the encoder. `skipped` is
// strictly diagnostic.
struct DiscoveryResult {
    std::vector<Atom>             atoms;
    std::vector<SkippedCandidate> skipped;

    // Counters that show up in the diff report. Computed inside
    // `discover_atoms` so callers don't have to recount.
    uint32_t yara_candidates_total   = 0;
    uint32_t bisect_candidates_total = 0;
    uint64_t bytes_total             = 0;     // sum of atoms[*].length
};

// Lower-level entry point: take raw PE bytes plus an optional LIEF
// Binary (used only to walk the base relocation table). When `lief`
// is null, the relocation filter is skipped (atoms can therefore
// inadvertently overlap a fix-up; callers should prefer the
// PeImage-based overload below in production paths).
[[nodiscard]] Result<DiscoveryResult>
discover_atoms_raw(std::span<const uint8_t>            pe_bytes,
                   const LIEF::PE::Binary*             lief,
                   const yara_target::PriorityMap*     yara,
                   std::span<const scan::BisectAnchor> bisect_anchors,
                   const AtomDiscoveryConfig&          cfg);

// Discover signature-bearing atoms in the PE's data sections.
//
// `image` provides the byte buffer + parsed section map.
// `yara` is the optional `--target` PriorityMap. When provided, every
//   YARA match offset inside a data section becomes a candidate atom
//   (using the matched string's literal bytes from the input image).
// `bisect_anchors` carry file-offset-typed fragments produced by the
//   `--target-defender` orchestrator's `bisect_multi`. Each fragment
//   that lands inside a data section becomes a candidate.
//
// Filtering: atoms must be in an allowed section, fit min/max length,
// not overlap base relocations or non-empty non-debug data
// directories, and not be a substring of an earlier accepted atom at
// the same offset. Conservative on purpose - false positives here mean
// silent runtime corruption.
[[nodiscard]] Result<DiscoveryResult>
discover_atoms(const format::PeImage&             image,
               const yara_target::PriorityMap*    yara,
               std::span<const scan::BisectAnchor> bisect_anchors,
               const AtomDiscoveryConfig&         cfg);

}

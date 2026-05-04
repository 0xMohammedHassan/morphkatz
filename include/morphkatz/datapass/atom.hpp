#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace morphkatz::datapass {

// One signature-bearing byte sequence the data pass plans to encode at
// rest and decode at runtime. Atoms live in non-executable sections
// (`.rdata`, `.data`, etc.); discovery is the read-only first half of
// the pass and atom mutation is the second half.
//
// `file_offset` is the absolute byte position in the PE file. `length`
// is `bytes.size()` cached for hot loops. `section` is the parsed name
// from the section table (e.g. ".rdata"); empty when the atom didn't
// fall inside any section (in which case the caller should drop it).
//
// `source` describes which discovery channel produced the atom. Values
// today: "yara", "bisect". Future: "heuristic", "manual".
struct Atom {
    uint64_t              file_offset = 0;
    uint32_t              length      = 0;
    std::string           section;
    std::string           source;
    std::vector<uint8_t>  bytes;
};

// Why an atom candidate was rejected. Mirrored 1:1 by report metrics
// so the user can see the budget-vs-skip tradeoff.
enum class SkipReason : unsigned {
    None              = 0,
    NotInDataSection,         // outside .rdata/.data (or section filter)
    TooSmall,                 // < min_length
    TooLarge,                 // > max_length
    OverlapsRelocation,       // intersects IMAGE_DIRECTORY_ENTRY_BASERELOC target
    OverlapsDirectory,        // intersects another non-empty data directory
    OverlapsTlsCallbackBody,  // bytes are reachable from a TLS callback
    DuplicateOfPrevious,      // already covered by an earlier atom
};

inline const char* skip_reason_name(SkipReason r) noexcept {
    switch (r) {
        case SkipReason::None:                    return "ok";
        case SkipReason::NotInDataSection:        return "not_in_data_section";
        case SkipReason::TooSmall:                return "too_small";
        case SkipReason::TooLarge:                return "too_large";
        case SkipReason::OverlapsRelocation:      return "overlaps_relocation";
        case SkipReason::OverlapsDirectory:       return "overlaps_directory";
        case SkipReason::OverlapsTlsCallbackBody: return "overlaps_tls_callback_body";
        case SkipReason::DuplicateOfPrevious:     return "duplicate";
    }
    return "unknown";
}

// Knobs controlling atom discovery. The defaults are tuned for the
// `amsi_patch_demo.exe` and Mimikatz fixtures we localized via
// `probe_amsi_demo.py` and `probe_mimikatz_*` - they don't need to be
// changed in routine use.
struct AtomDiscoveryConfig {
    bool     include_rdata = true;
    bool     include_data  = true;
    bool     include_other_data_sections = false; // .rsrc/.bss/.gfids/...
    uint32_t min_length    = 4;
    uint32_t max_length    = 4096;

    // Cap on atoms emitted; the rest become DuplicateOfPrevious to keep
    // the report bounded on very chatty YARA packs.
    uint32_t max_atoms     = 256;
};

}

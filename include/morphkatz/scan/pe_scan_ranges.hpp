#pragma once

#include "morphkatz/common/error.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace morphkatz::scan {

// One contiguous file-offset window. Used both as the input "scan range"
// for scoped bisection (regions whose bytes are eligible to be masked
// during the L/R sweeps) and as the output of `compute_pe_scan_ranges`.
struct ScanRange {
    size_t file_offset = 0;
    size_t length      = 0;
};

// PE-aware scopes for `compute_pe_scan_ranges`. `Sections` is the
// recommended default: it lets the bisect mask bytes inside section
// payloads (the byte regions a signature is most likely anchored in)
// while keeping headers and parsed data-directory contents intact, so
// every buffer handed to the scanner remains a structurally valid PE.
enum class ScanScope {
    Sections,        // section raw data MINUS data-directory windows (default)
    SectionsAll,     // section raw data, directories included
    CodeOnly,        // sections with EXECUTE | CNT_CODE
    DataOnly,        // sections with CNT_INITIALIZED_DATA, no EXECUTE
    Raw,             // empty list (legacy slice-and-scan)
};

// Compute the file-offset windows the bisect is allowed to mask.
//
// On non-PE inputs (no MZ / malformed e_lfanew / etc.) returns an empty
// vector, which the caller treats as "fall back to legacy slice-and-scan".
// For `Raw` always returns empty. For the PE-aware scopes, the returned
// list is non-overlapping, sorted by `file_offset`, with adjacent ranges
// coalesced and zero-length entries dropped.
[[nodiscard]] Result<std::vector<ScanRange>>
compute_pe_scan_ranges(std::span<const uint8_t> pe, ScanScope scope);

}

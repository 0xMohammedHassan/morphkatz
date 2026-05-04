#pragma once

#include "morphkatz/common/error.hpp"
#include "morphkatz/scan/pe_scan_ranges.hpp"
#include "morphkatz/scan/scanner.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace morphkatz::scan {

// Outcome of a single-anchor bisection.
//
// Status is the primary discriminant the report writer keys on:
//   Found        - successfully reduced to a sub-window <= max_anchor
//   Clean        - input was not flagged at all (ok-but-no-op)
//   MlDetection  - threat was !ml; bisect refused to recurse
//   MidpointSpan - signature straddled the midpoint, no anchor isolated
//   NoOp         - degenerate input (size <= 1)
struct BisectResult {
    enum class Status {
        Found,
        Clean,
        MlDetection,
        MidpointSpan,
        NoOp,
    };
    Status status = Status::NoOp;

    // Populated when status == Found or MidpointSpan.
    size_t                 offset = 0;
    size_t                 length = 0;
    std::vector<uint8_t>   bytes;            // copy of the anchor window
    std::string            section;          // e.g. ".text" - empty if no PE
    std::string            section_kind;     // "code" / "data" / "rsrc"

    // Scoped-bisect only. The anchor's virtual `[offset, offset+length)`
    // window may map to >1 file ranges when it crosses a section
    // boundary inside the active scan-range list. In legacy slice mode,
    // and in single-fragment scoped runs, this is `[{offset, length}]`.
    std::vector<ScanRange> fragments;

    // Always populated.
    int                       scan_count = 0;
    std::vector<Threat>       threats;        // initial verdict's threats
    std::chrono::milliseconds elapsed{0};
};

struct BisectOptions {
    size_t   min_chunk     = 4;          // stop recursion at this size
    size_t   max_scans     = 64;         // hard cap on scanner calls
    std::string name_hint  = "morphkatz-bisect";

    // When true, additionally re-scan the union [left | right] when a
    // single half doesn't trigger - lets us detect signatures that
    // straddle the midpoint without giving up. Defaults off for v1
    // because it doubles the worst-case scan count.
    bool retry_overlap = false;

    // Optional: the original PE file. When non-empty the bisect result
    // will populate `section` / `section_kind` by looking up the
    // anchor offset in the section header table.
    std::vector<uint8_t> pe_image_for_section_map;

    // Scoped (PE-aware) bisection: when non-empty, every iteration
    // sends the FULL input to the scanner with bytes outside the
    // candidate window (computed in a virtual coordinate space over
    // these ranges) replaced by `mask_byte`. Headers and any
    // file-offset *outside* this list are preserved verbatim, so the
    // PE parser always sees a structurally valid image and can never
    // bail with a false-clean verdict.
    //
    // When empty, the legacy slice-and-scan algorithm is used.
    std::vector<ScanRange> scan_ranges;
    uint8_t mask_byte = 0x00;
};

// Single-anchor bisection. Halves the input until one (and only one)
// half flags the buffer. The algorithm is engine-agnostic - it only
// uses `IDefenderScanner::scan_buffer`. See plan section "Bisection
// algorithm (single-anchor)" for the full state machine.
[[nodiscard]] Result<BisectResult>
    bisect_single(IDefenderScanner&        scanner,
                  std::span<const uint8_t> input,
                  const BisectOptions&     opts);

// One isolated anchor produced by `bisect_multi`. Mirrors the subset
// of `BisectResult` that's specific to a single anchor; the per-call
// scan budget and threat list live on the wrapping `MultiBisectResult`.
struct BisectAnchor {
    BisectResult::Status status = BisectResult::Status::NoOp;
    size_t                offset = 0;
    size_t                length = 0;
    std::vector<uint8_t>  bytes;
    std::string           section;
    std::string           section_kind;
    // Same semantics as BisectResult::fragments. Single-fragment when
    // an anchor stays inside one contiguous scan range.
    std::vector<ScanRange> fragments;
};

struct MultiBisectOptions {
    // Hard cap on the number of distinct anchors `bisect_multi` will
    // emit before returning `ExhaustedAnchors`. 8 covers the worst
    // multi-anchor signatures we have evidence for in the wild.
    size_t  max_anchors          = 8;

    // Total scanner-call budget across all peels. Sized for the
    // worst case of `max_anchors * per_anchor_max_scans` plus slop
    // for the per-iteration "is anything left?" rescan.
    size_t  total_max_scans      = 256;

    // Forwarded to `bisect_single` on each peel. Capped against the
    // remaining slice of `total_max_scans` so a runaway single-peel
    // can't exhaust the global budget on its own.
    size_t  per_anchor_max_scans = 64;

    // Stop recursion at this size inside each peel.
    size_t  min_chunk            = 4;

    // Byte used to mask already-found anchor windows in the working
    // buffer between peels. 0x00 keeps overall size constant so PE
    // section maps and absolute offsets stay valid.
    uint8_t mask_byte            = 0x00;

    std::string name_hint        = "morphkatz-bisect";

    // Optional: original PE bytes for section attribution. Each
    // anchor's `section` / `section_kind` is resolved against this
    // image, not the masked working copy.
    std::vector<uint8_t> pe_image_for_section_map;

    // Scoped (PE-aware) bisection: forwarded into each per-peel
    // `BisectOptions`. See `BisectOptions::scan_ranges` for semantics.
    std::vector<ScanRange> scan_ranges;
};

// Aggregate result of a peel-and-rescan multi-anchor bisection.
//
// Status terminates the loop:
//   Done             - working buffer scans clean after final peel
//   ExhaustedAnchors - max_anchors hit while still flagged
//   ExhaustedScans   - total_max_scans hit; partial anchors returned
//   Clean            - whole-input scan was already clean (no anchors)
//   MlDetection      - any peel observed an !ml threat; refused
//   NoOp             - degenerate input (empty)
struct MultiBisectResult {
    enum class Status {
        Done,
        ExhaustedAnchors,
        ExhaustedScans,
        Clean,
        MlDetection,
        NoOp,
    };
    Status                    status = Status::NoOp;
    std::vector<BisectAnchor> anchors;
    std::vector<Threat>       initial_threats;   // from the first scan
    int                       scan_count = 0;
    std::chrono::milliseconds elapsed{0};
};

// Multi-anchor bisection. Repeatedly calls `bisect_single` on a
// working buffer that has previously-found anchors masked out, so the
// scanner reports the *next* anchor each time. Layout-preserving: the
// working buffer stays the same size, only the bytes inside found
// windows are zeroed. Returns whatever anchors were isolated even if
// any of the budget caps fires - the report writer keys off `status`
// to explain why the run ended.
[[nodiscard]] Result<MultiBisectResult>
    bisect_multi(IDefenderScanner&         scanner,
                 std::span<const uint8_t>  input,
                 const MultiBisectOptions& opts);

}

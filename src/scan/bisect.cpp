#include "morphkatz/scan/bisect.hpp"

#include "morphkatz/common/logging.hpp"
#include "morphkatz/scan/threat_classify.hpp"

#include <algorithm>
#include <chrono>
#include <cstring>

namespace morphkatz::scan {

namespace {

bool any_ml(const std::vector<Threat>& ts) noexcept {
    for (const auto& t : ts) if (is_ml_detection(t)) return true;
    return false;
}

// Lightweight PE section lookup. Avoids a hard LIEF dependency in the
// bisection unit tests by parsing the file headers directly. Returns
// {name, kind} for the section that contains the file offset; empty
// strings if no match (or input isn't a PE).
struct SectionInfo {
    std::string name;
    std::string kind;
};

SectionInfo lookup_section(std::span<const uint8_t> pe, size_t file_offset) {
    if (pe.size() < 0x40) return {};
    // e_lfanew is at offset 0x3c
    const uint32_t e_lfanew = static_cast<uint32_t>(pe[0x3c]) |
        (static_cast<uint32_t>(pe[0x3d]) << 8) |
        (static_cast<uint32_t>(pe[0x3e]) << 16) |
        (static_cast<uint32_t>(pe[0x3f]) << 24);
    if (e_lfanew + 0x18 > pe.size()) return {};
    if (pe[e_lfanew] != 'P' || pe[e_lfanew + 1] != 'E' ||
        pe[e_lfanew + 2] != 0 || pe[e_lfanew + 3] != 0) return {};

    const size_t coff = e_lfanew + 4;
    if (coff + 20 > pe.size()) return {};
    const uint16_t num_sections = static_cast<uint16_t>(pe[coff + 2]) |
        (static_cast<uint16_t>(pe[coff + 3]) << 8);
    const uint16_t opt_size = static_cast<uint16_t>(pe[coff + 16]) |
        (static_cast<uint16_t>(pe[coff + 17]) << 8);
    const size_t sections_off = coff + 20 + opt_size;

    constexpr size_t kSectionEntry = 40;
    for (uint16_t i = 0; i < num_sections; ++i) {
        const size_t off = sections_off + size_t(i) * kSectionEntry;
        if (off + kSectionEntry > pe.size()) break;

        char name_buf[9] = {};
        std::memcpy(name_buf, pe.data() + off, 8);
        name_buf[8] = 0;

        const uint32_t raw_size = static_cast<uint32_t>(pe[off + 16]) |
            (static_cast<uint32_t>(pe[off + 17]) << 8) |
            (static_cast<uint32_t>(pe[off + 18]) << 16) |
            (static_cast<uint32_t>(pe[off + 19]) << 24);
        const uint32_t raw_ptr = static_cast<uint32_t>(pe[off + 20]) |
            (static_cast<uint32_t>(pe[off + 21]) << 8) |
            (static_cast<uint32_t>(pe[off + 22]) << 16) |
            (static_cast<uint32_t>(pe[off + 23]) << 24);
        const uint32_t chars = static_cast<uint32_t>(pe[off + 36]) |
            (static_cast<uint32_t>(pe[off + 37]) << 8) |
            (static_cast<uint32_t>(pe[off + 38]) << 16) |
            (static_cast<uint32_t>(pe[off + 39]) << 24);

        if (file_offset >= raw_ptr &&
            file_offset <  size_t(raw_ptr) + raw_size) {
            SectionInfo si;
            si.name = name_buf;
            constexpr uint32_t IMAGE_SCN_MEM_EXECUTE_LOCAL = 0x20000000u;
            constexpr uint32_t IMAGE_SCN_CNT_CODE_LOCAL    = 0x00000020u;
            constexpr uint32_t IMAGE_SCN_CNT_INIT_DATA_LOCAL = 0x00000040u;
            if (chars & (IMAGE_SCN_MEM_EXECUTE_LOCAL | IMAGE_SCN_CNT_CODE_LOCAL)) {
                si.kind = "code";
            } else if (chars & IMAGE_SCN_CNT_INIT_DATA_LOCAL) {
                si.kind = "data";
            } else {
                si.kind = "other";
            }
            return si;
        }
    }
    return {};
}

// ---------------------------------------------------------------------
// Scoped (PE-aware) helpers.
// ---------------------------------------------------------------------

// Sanitise + sort an externally-supplied scan-range list, dropping
// zero-length entries and collapsing adjacent ranges. Overlap between
// caller-supplied ranges is left as-is - we tolerate it (the virtual
// mapping just visits the byte twice) but coalescing keeps the common
// case (output of `compute_pe_scan_ranges`) tidy.
std::vector<ScanRange>
normalize_scan_ranges(std::vector<ScanRange> in) {
    in.erase(std::remove_if(in.begin(), in.end(),
                            [](const ScanRange& r) noexcept {
                                return r.length == 0;
                            }),
             in.end());
    std::sort(in.begin(), in.end(),
              [](const ScanRange& a, const ScanRange& b) noexcept {
                  return a.file_offset < b.file_offset;
              });
    std::vector<ScanRange> out;
    out.reserve(in.size());
    for (const auto& r : in) {
        if (!out.empty() &&
            out.back().file_offset + out.back().length == r.file_offset) {
            out.back().length += r.length;
        } else {
            out.push_back(r);
        }
    }
    return out;
}

// Map a virtual `[v_lo, v_hi)` window onto the file-offset ranges
// implied by `ranges` (sorted, non-overlapping). Returned fragments
// preserve order and never have zero length.
std::vector<ScanRange>
virtual_to_file(const std::vector<ScanRange>& ranges,
                size_t v_lo,
                size_t v_hi) {
    std::vector<ScanRange> out;
    if (v_hi <= v_lo) return out;
    size_t v = 0;
    for (const auto& r : ranges) {
        const size_t r_v_lo = v;
        const size_t r_v_hi = v + r.length;
        v = r_v_hi;
        if (r_v_hi <= v_lo) continue;
        if (r_v_lo >= v_hi) break;
        const size_t take_v_lo = std::max(v_lo, r_v_lo);
        const size_t take_v_hi = std::min(v_hi, r_v_hi);
        const size_t take_len  = take_v_hi - take_v_lo;
        if (take_len == 0) continue;
        const size_t f_off = r.file_offset + (take_v_lo - r_v_lo);
        // Coalesce contiguous fragments produced by adjacent ranges.
        if (!out.empty() &&
            out.back().file_offset + out.back().length == f_off) {
            out.back().length += take_len;
        } else {
            out.push_back({f_off, take_len});
        }
    }
    return out;
}

// Apply the mask: write `mask_byte` into every file-offset that lives
// inside `ranges` but outside the virtual `[keep_lo, keep_hi)` window.
// Bytes outside `ranges` are never touched - that's the whole point of
// scoped mode.
void mask_outside_virtual(std::vector<uint8_t>&         work,
                          const std::vector<ScanRange>& ranges,
                          size_t                        keep_lo,
                          size_t                        keep_hi,
                          uint8_t                       mask_byte) {
    size_t v = 0;
    for (const auto& r : ranges) {
        const size_t r_v_lo = v;
        const size_t r_v_hi = v + r.length;
        v = r_v_hi;
        if (r.length == 0) continue;
        // Two virtual sub-windows of `r` to mask: [r_v_lo, keep_lo)
        // and [keep_hi, r_v_hi). Each maps back via the same offset
        // arithmetic.
        auto mask = [&](size_t v_a, size_t v_b) {
            if (v_b <= v_a) return;
            const size_t a = std::max(v_a, r_v_lo);
            const size_t b = std::min(v_b, r_v_hi);
            if (b <= a) return;
            const size_t f_off = r.file_offset + (a - r_v_lo);
            const size_t f_len = b - a;
            if (f_off >= work.size()) return;
            const size_t end = std::min(work.size(), f_off + f_len);
            std::fill(work.begin() +
                          static_cast<std::ptrdiff_t>(f_off),
                      work.begin() +
                          static_cast<std::ptrdiff_t>(end),
                      mask_byte);
        };
        mask(r_v_lo, keep_lo);
        mask(keep_hi, r_v_hi);
    }
}

}  // namespace

namespace {

// Legacy slice-and-scan implementation. Preserved verbatim for the
// pre-scoped path (caller passes empty `scan_ranges`), and for the
// non-PE case where there are no useful section windows to mask.
Result<BisectResult> bisect_legacy_slice(IDefenderScanner&        scanner,
                                         std::span<const uint8_t> input,
                                         const BisectOptions&     opts) {
    BisectResult res;
    const auto t0 = std::chrono::steady_clock::now();

    if (input.size() <= 1 || opts.min_chunk == 0) {
        res.status = BisectResult::Status::NoOp;
        res.elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - t0);
        return res;
    }

    auto v0 = scanner.scan_buffer(input, opts.name_hint + "-initial");
    if (!v0.ok()) return v0.error();
    res.scan_count++;

    if (!v0->infected) {
        res.status = BisectResult::Status::Clean;
        res.elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - t0);
        return res;
    }
    res.threats = v0->threats;
    if (any_ml(v0->threats)) {
        res.status = BisectResult::Status::MlDetection;
        res.elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - t0);
        MK_DEBUG("Bisect refusing ML detection (threat={})",
                 v0->threats.empty() ? "" : v0->threats.front().name);
        return res;
    }

    size_t lo = 0;
    size_t hi = input.size();
    bool   midpoint_spanned = false;

    while ((hi - lo) > opts.min_chunk &&
           res.scan_count < static_cast<int>(opts.max_scans)) {
        const size_t mid  = lo + (hi - lo) / 2;
        const size_t left_len  = mid - lo;
        const size_t right_len = hi - mid;
        if (left_len == 0 || right_len == 0) break;

        auto vL = scanner.scan_buffer(
            input.subspan(lo, left_len),
            opts.name_hint + "-L");
        if (!vL.ok()) return vL.error();
        res.scan_count++;
        if (vL->infected && !any_ml(vL->threats)) {
            hi = mid;
            continue;
        }

        auto vR = scanner.scan_buffer(
            input.subspan(mid, right_len),
            opts.name_hint + "-R");
        if (!vR.ok()) return vR.error();
        res.scan_count++;
        if (vR->infected && !any_ml(vR->threats)) {
            lo = mid;
            continue;
        }

        if (opts.retry_overlap) {
            // v1.1: reserved overlap retry.
        }
        midpoint_spanned = true;
        break;
    }

    res.offset = lo;
    res.length = hi - lo;
    res.bytes.assign(input.data() + lo, input.data() + lo + res.length);
    res.fragments.push_back({res.offset, res.length});
    res.status = midpoint_spanned ? BisectResult::Status::MidpointSpan
                                  : BisectResult::Status::Found;

    if (!opts.pe_image_for_section_map.empty()) {
        auto si = lookup_section(opts.pe_image_for_section_map, res.offset);
        res.section      = std::move(si.name);
        res.section_kind = std::move(si.kind);
    }

    res.elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - t0);
    MK_DEBUG("Bisect (legacy) status={} offset={} length={} scans={}",
             static_cast<int>(res.status), res.offset, res.length,
             res.scan_count);
    return res;
}

// Scoped (PE-aware) bisection. Always sends the full input to the
// scanner; bytes outside the candidate virtual window are masked, but
// only inside the caller-supplied `scan_ranges`. PE headers, the
// section table, and (when the caller used `Sections` scope) parsed
// data-directory regions are preserved verbatim every iteration, so
// the parser can never bail with a false-clean verdict.
Result<BisectResult> bisect_scoped(IDefenderScanner&        scanner,
                                   std::span<const uint8_t> input,
                                   const BisectOptions&     opts) {
    BisectResult res;
    const auto t0 = std::chrono::steady_clock::now();

    auto ranges = normalize_scan_ranges(opts.scan_ranges);
    size_t virt_total = 0;
    for (const auto& r : ranges) virt_total += r.length;

    // Treat empty / pathological scope as a NoOp. Callers can fall
    // back to legacy slice mode by clearing scan_ranges if they want
    // any signal here.
    if (input.size() <= 1 || opts.min_chunk == 0 || virt_total == 0) {
        res.status = BisectResult::Status::NoOp;
        res.elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - t0);
        return res;
    }

    auto v0 = scanner.scan_buffer(input, opts.name_hint + "-initial");
    if (!v0.ok()) return v0.error();
    res.scan_count++;

    if (!v0->infected) {
        res.status = BisectResult::Status::Clean;
        res.elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - t0);
        return res;
    }
    res.threats = v0->threats;
    if (any_ml(v0->threats)) {
        res.status = BisectResult::Status::MlDetection;
        res.elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - t0);
        MK_DEBUG("Bisect (scoped) refusing ML detection (threat={})",
                 v0->threats.empty() ? "" : v0->threats.front().name);
        return res;
    }

    // Working buffer holds a copy of the full input that we mutate
    // each iteration. Restoring after each scan keeps the L sweep
    // independent of the R sweep.
    std::vector<uint8_t> work(input.begin(), input.end());

    size_t lo = 0;
    size_t hi = virt_total;
    bool   midpoint_spanned = false;

    while ((hi - lo) > opts.min_chunk &&
           res.scan_count < static_cast<int>(opts.max_scans)) {
        const size_t mid = lo + (hi - lo) / 2;
        if (mid == lo || mid == hi) break;

        // Left half: keep [lo, mid), mask [hi-> outside that] inside
        // the active scope. Reset outside scope is automatic - we
        // start each pass from `input`.
        std::copy(input.begin(), input.end(), work.begin());
        mask_outside_virtual(work, ranges, lo, mid, opts.mask_byte);
        auto vL = scanner.scan_buffer(work, opts.name_hint + "-L");
        if (!vL.ok()) return vL.error();
        res.scan_count++;
        if (vL->infected && !any_ml(vL->threats)) {
            hi = mid;
            continue;
        }

        // Right half: keep [mid, hi).
        std::copy(input.begin(), input.end(), work.begin());
        mask_outside_virtual(work, ranges, mid, hi, opts.mask_byte);
        auto vR = scanner.scan_buffer(work, opts.name_hint + "-R");
        if (!vR.ok()) return vR.error();
        res.scan_count++;
        if (vR->infected && !any_ml(vR->threats)) {
            lo = mid;
            continue;
        }

        midpoint_spanned = true;
        break;
    }

    res.fragments = virtual_to_file(ranges, lo, hi);
    if (res.fragments.empty()) {
        // Defensive: shouldn't happen with a non-empty range list, but
        // collapse to NoOp instead of returning bogus offsets.
        res.status = BisectResult::Status::NoOp;
        res.elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - t0);
        return res;
    }

    res.offset = res.fragments.front().file_offset;
    if (res.fragments.size() == 1) {
        res.length = res.fragments.front().length;
    } else {
        // Multi-fragment: report the span from the first to the last
        // fragment; `bytes` and `length` then describe the virtual
        // span the scanner saw, which is what a downstream report
        // wants when the anchor crosses a section boundary.
        const auto& last = res.fragments.back();
        res.length = (last.file_offset + last.length) - res.offset;
    }

    // Copy the actual file bytes covered by the fragments. For the
    // single-fragment common case this is a flat slice; multi-fragment
    // case concatenates the pieces (gaps between fragments are *not*
    // included - they're in the un-masked outside-of-scope region).
    res.bytes.clear();
    res.bytes.reserve(hi - lo);
    for (const auto& f : res.fragments) {
        if (f.file_offset >= input.size()) continue;
        const size_t end = std::min(input.size(), f.file_offset + f.length);
        if (end <= f.file_offset) continue;
        res.bytes.insert(res.bytes.end(),
                         input.data() + f.file_offset,
                         input.data() + end);
    }

    res.status = midpoint_spanned ? BisectResult::Status::MidpointSpan
                                  : BisectResult::Status::Found;

    if (!opts.pe_image_for_section_map.empty()) {
        auto si = lookup_section(opts.pe_image_for_section_map, res.offset);
        res.section      = std::move(si.name);
        res.section_kind = std::move(si.kind);
    }

    res.elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - t0);
    MK_DEBUG("Bisect (scoped) status={} offset={} length={} fragments={} scans={}",
             static_cast<int>(res.status), res.offset, res.length,
             res.fragments.size(), res.scan_count);
    return res;
}

}  // namespace

Result<BisectResult> bisect_single(IDefenderScanner&        scanner,
                                   std::span<const uint8_t> input,
                                   const BisectOptions&     opts) {
    if (opts.scan_ranges.empty()) {
        return bisect_legacy_slice(scanner, input, opts);
    }
    return bisect_scoped(scanner, input, opts);
}

Result<MultiBisectResult> bisect_multi(IDefenderScanner&         scanner,
                                       std::span<const uint8_t>  input,
                                       const MultiBisectOptions& opts) {
    MultiBisectResult res;
    const auto t0 = std::chrono::steady_clock::now();

    if (input.empty() || opts.max_anchors == 0 ||
        opts.total_max_scans == 0) {
        res.status = MultiBisectResult::Status::NoOp;
        res.elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - t0);
        return res;
    }

    // Mutable working copy. Found anchors get masked in this buffer
    // between peels so the next bisect_single sees the residual
    // signature without the layout shifting.
    std::vector<uint8_t> work(input.begin(), input.end());

    bool first_peel = true;
    bool keep_going = true;
    while (keep_going) {
        if (res.anchors.size() >= opts.max_anchors) {
            res.status = MultiBisectResult::Status::ExhaustedAnchors;
            break;
        }

        if (res.scan_count >= static_cast<int>(opts.total_max_scans)) {
            res.status = MultiBisectResult::Status::ExhaustedScans;
            break;
        }
        const size_t remaining =
            opts.total_max_scans - static_cast<size_t>(res.scan_count);
        const size_t per_peel = std::min(remaining, opts.per_anchor_max_scans);
        if (per_peel == 0) {
            res.status = MultiBisectResult::Status::ExhaustedScans;
            break;
        }

        BisectOptions bopts;
        bopts.min_chunk = opts.min_chunk;
        bopts.max_scans = per_peel;
        // No '/' or '\\' in the suffix - downstream scanners use the
        // hint as part of a temp file basename and a path separator
        // there would create an unwanted subdirectory.
        bopts.name_hint = opts.name_hint + "-peel" +
                          std::to_string(res.anchors.size());
        bopts.pe_image_for_section_map = opts.pe_image_for_section_map;
        bopts.scan_ranges = opts.scan_ranges;
        bopts.mask_byte   = opts.mask_byte;

        auto br = bisect_single(scanner, std::span<const uint8_t>(work), bopts);
        if (!br.ok()) return br.error();
        res.scan_count += br->scan_count;

        if (first_peel) {
            res.initial_threats = br->threats;
            first_peel = false;
        }

        switch (br->status) {
            case BisectResult::Status::Clean:
            case BisectResult::Status::NoOp:
                res.status = MultiBisectResult::Status::Done;
                keep_going = false;
                break;
            case BisectResult::Status::MlDetection:
                res.status = MultiBisectResult::Status::MlDetection;
                keep_going = false;
                break;
            case BisectResult::Status::Found:
            case BisectResult::Status::MidpointSpan: {
                BisectAnchor a;
                a.status       = br->status;
                a.offset       = br->offset;
                a.length       = br->length;
                a.bytes        = br->bytes;
                a.section      = br->section;
                a.section_kind = br->section_kind;
                a.fragments    = br->fragments;
                res.anchors.push_back(std::move(a));

                // Mask each fragment of this anchor in the working
                // buffer. In scoped mode, the anchor may span >1
                // file ranges; iterating fragments avoids zeroing
                // bytes in inter-section gaps that we deliberately
                // kept un-masked (e.g. data-directory regions). In
                // legacy slice mode, fragments == [{offset, length}],
                // so this collapses to the previous behaviour.
                std::vector<ScanRange> frags = br->fragments;
                if (frags.empty()) frags.push_back({br->offset, br->length});
                for (const auto& f : frags) {
                    const size_t end = std::min(work.size(),
                                                f.file_offset + f.length);
                    if (f.file_offset < end) {
                        std::fill(work.begin() +
                                    static_cast<std::ptrdiff_t>(f.file_offset),
                                  work.begin() +
                                    static_cast<std::ptrdiff_t>(end),
                                  opts.mask_byte);
                    }
                }
                break;
            }
        }
    }

    res.elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - t0);
    MK_DEBUG("Bisect-multi status={} anchors={} scans={}",
             static_cast<int>(res.status), res.anchors.size(),
             res.scan_count);
    return res;
}

}

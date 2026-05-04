#include "morphkatz/datapass/atom_discovery.hpp"

#include "morphkatz/common/logging.hpp"
#include "morphkatz/format/pe_image.hpp"

#include <LIEF/PE.hpp>

#include <algorithm>
#include <cstring>

namespace morphkatz::datapass {

namespace {

// PE characteristics flags. Locally re-defined to keep this TU compilable
// without <windows.h> on test bots.
constexpr uint32_t kSectInitData = 0x00000040u;
constexpr uint32_t kSectExecute  = 0x20000000u;

inline uint16_t r16(std::span<const uint8_t> p, size_t o) noexcept {
    return static_cast<uint16_t>(p[o]) |
           (static_cast<uint16_t>(p[o + 1]) << 8);
}
inline uint32_t r32(std::span<const uint8_t> p, size_t o) noexcept {
    return static_cast<uint32_t>(p[o]) |
           (static_cast<uint32_t>(p[o + 1]) << 8) |
           (static_cast<uint32_t>(p[o + 2]) << 16) |
           (static_cast<uint32_t>(p[o + 3]) << 24);
}

// One contiguous file-offset range. Different from `scan::ScanRange`
// only in that we ditto-stamp it locally so this TU doesn't need to
// pull the scan public API.
struct FileRange {
    uint64_t lo = 0;   // inclusive
    uint64_t hi = 0;   // exclusive
};

inline bool overlaps(const FileRange& a, uint64_t off, uint32_t len) noexcept {
    if (len == 0) return false;
    const uint64_t ahi = static_cast<uint64_t>(off) + len;
    return !(ahi <= a.lo || off >= a.hi);
}

struct ParsedSection {
    std::string name;
    uint32_t    raw_ptr  = 0;
    uint32_t    raw_size = 0;
    uint32_t    virt_addr= 0;
    uint32_t    virt_size= 0;
    uint32_t    chars    = 0;
};

// Lightweight section-table walk. We can't reuse `compute_pe_scan_ranges`
// because it returns merged maskable ranges; we need per-section name +
// flags so the caller can ask "is this offset inside .rdata?".
std::vector<ParsedSection> parse_sections(std::span<const uint8_t> pe) {
    std::vector<ParsedSection> out;
    if (pe.size() < 0x40) return out;
    const uint32_t e_lfanew = r32(pe, 0x3c);
    if (e_lfanew + 24 > pe.size()) return out;
    if (pe[e_lfanew]     != 'P' || pe[e_lfanew + 1] != 'E' ||
        pe[e_lfanew + 2] != 0   || pe[e_lfanew + 3] != 0) return out;
    const size_t coff = e_lfanew + 4;
    if (coff + 20 > pe.size()) return out;
    const uint16_t num_sections = r16(pe, coff + 2);
    const uint16_t opt_size     = r16(pe, coff + 16);
    const size_t   opt_off      = coff + 20;
    if (opt_off + opt_size > pe.size()) return out;
    const size_t sect_off = opt_off + opt_size;
    if (sect_off + size_t(num_sections) * 40 > pe.size()) return out;

    out.reserve(num_sections);
    for (uint16_t i = 0; i < num_sections; ++i) {
        const size_t off = sect_off + size_t(i) * 40;
        ParsedSection s;
        char nb[9] = {};
        std::memcpy(nb, pe.data() + off, 8);
        nb[8]      = 0;
        s.name     = nb;
        s.virt_size= r32(pe, off + 8);
        s.virt_addr= r32(pe, off + 12);
        s.raw_size = r32(pe, off + 16);
        s.raw_ptr  = r32(pe, off + 20);
        s.chars    = r32(pe, off + 36);
        if (s.raw_ptr >= pe.size()) continue;
        const size_t end = std::min<size_t>(pe.size(),
                                            size_t(s.raw_ptr) + size_t(s.raw_size));
        s.raw_size = static_cast<uint32_t>(end - s.raw_ptr);
        out.push_back(std::move(s));
    }
    return out;
}

bool is_data_section(const ParsedSection& s) noexcept {
    return ((s.chars & kSectInitData) != 0) &&
           ((s.chars & kSectExecute)  == 0);
}

// The whole [off, off+len) window must fit inside a single section.
// Returns nullptr if it crosses a boundary or no section contains it.
const ParsedSection* lookup_section_range(const std::vector<ParsedSection>& secs,
                                          uint64_t off, uint32_t len) noexcept {
    for (const auto& s : secs) {
        const uint64_t lo = s.raw_ptr;
        const uint64_t hi = lo + s.raw_size;
        if (off >= lo && static_cast<uint64_t>(off) + len <= hi) return &s;
    }
    return nullptr;
}

// Translate an RVA window to file offsets, walking the section table.
// `out` is appended to (atoms with discontiguous mapping become
// multiple file ranges; for the discovery layer we just record the
// first contained section's mapping and let the caller decide).
FileRange rva_to_file(const std::vector<ParsedSection>& secs,
                      uint32_t rva, uint32_t size) noexcept {
    if (size == 0) return {0, 0};
    for (const auto& s : secs) {
        const uint64_t va_lo = s.virt_addr;
        const uint64_t va_hi = va_lo + std::max<uint64_t>(s.virt_size, s.raw_size);
        if (rva >= va_lo && rva < va_hi) {
            const uint64_t in = rva - va_lo;
            if (in >= s.raw_size) return {0, 0};
            const uint64_t avail = s.raw_size - in;
            const uint64_t use   = std::min<uint64_t>(size, avail);
            return { s.raw_ptr + in, s.raw_ptr + in + use };
        }
    }
    return {0, 0};
}

// Walk the PE base relocation table and emit one FileRange per page
// block that has at least one non-IMAGE_REL_BASED_ABSOLUTE entry. The
// per-entry granularity is 8 bytes (size of a fixed-up VA on x64), so
// each entry contributes [target_file, target_file+8). We over-bound
// to the whole page block when iterating gets noisy.
std::vector<FileRange> reloc_target_ranges(const LIEF::PE::Binary& pe,
                                           const std::vector<ParsedSection>& secs) {
    std::vector<FileRange> out;
    const auto& relocs = pe.relocations();
    if (relocs.size() == 0) return out;
    for (const auto& r : relocs) {
        const uint32_t page_rva = r.virtual_address();
        for (const auto& e : r.entries()) {
            // type() returns the strongly-typed BASE_TYPES enum on
            // LIEF >= 0.13; ABSOLUTE (==0) is the page-padding marker
            // and not an actual fix-up site, so we skip it.
            const auto type_raw = static_cast<uint32_t>(e.type());
            if (type_raw == 0) continue;
            const uint32_t off  = static_cast<uint32_t>(e.position());
            const uint32_t rva  = page_rva + off;
            const auto fr = rva_to_file(secs, rva, /*x64 fix-up*/ 8);
            if (fr.hi > fr.lo) out.push_back(fr);
        }
    }
    return out;
}

// Walk all 16 data directories (skipping CertificateTable which is a
// file offset, not an RVA) and emit one FileRange per non-empty one.
// Atoms that overlap a directory get OverlapsDirectory.
//
// Special-cases the TLS directory (index 9): in addition to the 40-byte
// IMAGE_TLS_DIRECTORY64 struct itself, we also exclude the array of
// callback pointers it references via AddressOfCallBacks. The Windows
// loader walks that array BEFORE running any of our code (including a
// TLS-callback decoder), so encoding pointers in it would corrupt
// every callback target.
std::vector<FileRange> directory_ranges(std::span<const uint8_t> pe,
                                        const std::vector<ParsedSection>& secs) {
    std::vector<FileRange> out;
    if (pe.size() < 0x40) return out;
    const uint32_t e_lfanew = r32(pe, 0x3c);
    if (e_lfanew + 24 > pe.size()) return out;
    const size_t opt = e_lfanew + 24;
    if (opt + 2 > pe.size()) return out;
    const uint16_t magic = r16(pe, opt);
    size_t dir_off = 0;
    uint64_t image_base = 0;
    if (magic == 0x10b) {
        dir_off    = opt + 96;
        image_base = r32(pe, opt + 28);                          // PE32: 4 bytes
    } else if (magic == 0x20b) {
        dir_off = opt + 112;
        image_base = static_cast<uint64_t>(r32(pe, opt + 24)) |  // low 4
                     (static_cast<uint64_t>(r32(pe, opt + 28)) << 32); // high 4
    } else {
        return out;
    }
    if (dir_off + 16 * 8 > pe.size()) return out;

    constexpr uint32_t kCert    = 4;   // file offset, not RVA
    constexpr uint32_t kBaseRel = 5;   // surfaced separately
    constexpr uint32_t kTls     = 9;
    for (uint32_t i = 0; i < 16; ++i) {
        if (i == kCert)    continue;
        if (i == kBaseRel) continue;
        const uint32_t rva  = r32(pe, dir_off + i * 8);
        const uint32_t size = r32(pe, dir_off + i * 8 + 4);
        if (rva == 0 || size == 0) continue;
        const auto fr = rva_to_file(secs, rva, size);
        if (fr.hi > fr.lo) out.push_back(fr);

        // TLS sub-tables: AddressOfCallBacks is a VA in the IMAGE_TLS_
        // DIRECTORY64 struct (offset 24 on PE32+, 12 on PE32). Walk the
        // null-terminated array of VAs and exclude those bytes.
        if (i == kTls && magic == 0x20b && fr.hi - fr.lo >= 32) {
            const size_t tls_struct_off = static_cast<size_t>(fr.lo);
            const uint64_t cb_va =
                static_cast<uint64_t>(r32(pe, tls_struct_off + 24)) |
                (static_cast<uint64_t>(r32(pe, tls_struct_off + 28)) << 32);
            if (cb_va > image_base) {
                const uint32_t cb_rva = static_cast<uint32_t>(cb_va - image_base);
                // Find the file offset for cb_rva and walk pointers until 0.
                const auto cb_fr_first = rva_to_file(secs, cb_rva, 8);
                if (cb_fr_first.hi > cb_fr_first.lo) {
                    uint32_t walked = 0;
                    while (walked < 4096) {            // cap: paranoid bound
                        const auto cb_fr =
                            rva_to_file(secs, cb_rva + walked, 8);
                        if (cb_fr.hi - cb_fr.lo < 8) break;
                        const uint64_t v =
                            static_cast<uint64_t>(r32(pe, cb_fr.lo)) |
                            (static_cast<uint64_t>(r32(pe, cb_fr.lo + 4)) << 32);
                        out.push_back(cb_fr);
                        if (v == 0) break;
                        walked += 8;
                    }
                }
            }
        }
    }
    return out;
}

// Sort + coalesce a FileRange vector for cheaper overlap checks later.
void coalesce(std::vector<FileRange>& v) {
    if (v.size() < 2) return;
    std::sort(v.begin(), v.end(),
              [](const FileRange& a, const FileRange& b) noexcept {
                  return a.lo < b.lo;
              });
    std::vector<FileRange> out;
    out.reserve(v.size());
    for (const auto& r : v) {
        if (out.empty() || r.lo > out.back().hi) {
            out.push_back(r);
        } else {
            out.back().hi = std::max(out.back().hi, r.hi);
        }
    }
    v = std::move(out);
}

bool any_overlaps(const std::vector<FileRange>& ranges,
                  uint64_t off, uint32_t len) noexcept {
    if (len == 0) return false;
    for (const auto& r : ranges) {
        if (overlaps(r, off, len)) return true;
    }
    return false;
}

bool atom_is_allowed_section(const ParsedSection& s,
                             const AtomDiscoveryConfig& cfg) noexcept {
    const bool data = is_data_section(s);
    if (!data) return false;
    if (s.name == ".rdata") return cfg.include_rdata;
    if (s.name == ".data")  return cfg.include_data;
    return cfg.include_other_data_sections;
}

}  // namespace

Result<DiscoveryResult>
discover_atoms_raw(std::span<const uint8_t>            bytes,
                   const LIEF::PE::Binary*             lief,
                   const yara_target::PriorityMap*    yara,
                   std::span<const scan::BisectAnchor> bisect_anchors,
                   const AtomDiscoveryConfig&         cfg) {
    DiscoveryResult res;
    const auto secs = parse_sections(bytes);
    if (secs.empty()) {
        return Error::make(ErrorKind::ParseFormat,
            "atom discovery: no parseable section table");
    }

    auto dir_ranges = directory_ranges(bytes, secs);
    coalesce(dir_ranges);

    std::vector<FileRange> reloc_ranges;
    if (lief) {
        reloc_ranges = reloc_target_ranges(*lief, secs);
        coalesce(reloc_ranges);
    }

    // Helper: classify + try-emit one candidate. Updates res in place.
    // Atoms that survive are appended to `res.atoms`; everything else
    // ends up in `res.skipped` with a reason.
    auto try_emit = [&](uint64_t off, uint32_t len,
                        std::vector<uint8_t> atom_bytes,
                        std::string source) {
        SkippedCandidate sk{};
        sk.file_offset = off;
        sk.length      = len;
        sk.source      = source;

        if (len < cfg.min_length) {
            sk.reason = SkipReason::TooSmall;
            res.skipped.push_back(std::move(sk));
            return;
        }
        if (len > cfg.max_length) {
            sk.reason = SkipReason::TooLarge;
            res.skipped.push_back(std::move(sk));
            return;
        }
        const auto* s = lookup_section_range(secs, off, len);
        if (!s) {
            sk.reason = SkipReason::NotInDataSection;
            res.skipped.push_back(std::move(sk));
            return;
        }
        sk.section = s->name;
        if (!atom_is_allowed_section(*s, cfg)) {
            sk.reason = SkipReason::NotInDataSection;
            res.skipped.push_back(std::move(sk));
            return;
        }
        if (any_overlaps(reloc_ranges, off, len)) {
            sk.reason = SkipReason::OverlapsRelocation;
            res.skipped.push_back(std::move(sk));
            return;
        }
        if (any_overlaps(dir_ranges, off, len)) {
            sk.reason = SkipReason::OverlapsDirectory;
            res.skipped.push_back(std::move(sk));
            return;
        }

        // Dedup against earlier accepted atoms: drop if fully covered
        // by an existing one (same offset, prefix, or substring).
        for (const auto& a : res.atoms) {
            const uint64_t ahi = a.file_offset + a.length;
            if (off >= a.file_offset && (off + len) <= ahi) {
                sk.reason = SkipReason::DuplicateOfPrevious;
                sk.section = a.section;
                res.skipped.push_back(std::move(sk));
                return;
            }
        }

        if (res.atoms.size() >= cfg.max_atoms) {
            sk.reason = SkipReason::DuplicateOfPrevious;  // budget exhausted
            res.skipped.push_back(std::move(sk));
            return;
        }

        Atom a;
        a.file_offset = off;
        a.length      = len;
        a.section     = s->name;
        a.source      = std::move(source);
        a.bytes       = std::move(atom_bytes);
        res.bytes_total += len;
        res.atoms.push_back(std::move(a));
    };

    // ---- YARA channel -------------------------------------------------
    if (yara) {
        const auto hits = yara->scan_with_offsets(bytes);
        res.yara_candidates_total = static_cast<uint32_t>(hits.size());
        for (const auto& h : hits) {
            std::vector<uint8_t> b;
            b.reserve(h.length);
            const uint8_t* base = bytes.data() + h.offset;
            b.assign(base, base + h.length);
            try_emit(h.offset, static_cast<uint32_t>(h.length),
                     std::move(b), "yara:" + h.rule_name);
        }
    }

    // ---- Bisect channel -----------------------------------------------
    // Each anchor exposes one or more file-offset typed `fragments`.
    // We treat each fragment as one candidate; the section-name filter
    // inside `try_emit` rejects everything that lands in `.text`.
    for (const auto& anchor : bisect_anchors) {
        const auto& frags = anchor.fragments;
        if (frags.empty()) {
            ++res.bisect_candidates_total;
            std::vector<uint8_t> b = anchor.bytes;
            try_emit(anchor.offset, static_cast<uint32_t>(anchor.length),
                     std::move(b), "bisect");
            continue;
        }
        for (const auto& fr : frags) {
            ++res.bisect_candidates_total;
            const uint64_t off = fr.file_offset;
            const uint32_t len = static_cast<uint32_t>(fr.length);
            if (len == 0) continue;
            if (static_cast<uint64_t>(off) + len > bytes.size()) continue;
            std::vector<uint8_t> b(bytes.begin() + static_cast<ptrdiff_t>(off),
                                   bytes.begin() + static_cast<ptrdiff_t>(off + len));
            try_emit(off, len, std::move(b), "bisect");
        }
    }

    MK_INFO("atom discovery: {} atom(s), {} skipped, {} bytes total ("
            "yara cands={}, bisect cands={})",
             res.atoms.size(), res.skipped.size(), res.bytes_total,
             res.yara_candidates_total, res.bisect_candidates_total);
    return res;
}

Result<DiscoveryResult>
discover_atoms(const format::PeImage&             image,
               const yara_target::PriorityMap*    yara,
               std::span<const scan::BisectAnchor> bisect_anchors,
               const AtomDiscoveryConfig&         cfg) {
    if (!image.is_pe()) {
        return Error::make(ErrorKind::NotSupported,
            "atom discovery requires a PE image");
    }
    return discover_atoms_raw(image.bytes(), image.lief(),
                              yara, bisect_anchors, cfg);
}

}

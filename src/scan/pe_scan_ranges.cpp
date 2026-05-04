#include "morphkatz/scan/pe_scan_ranges.hpp"

#include <algorithm>
#include <cstring>

namespace morphkatz::scan {

namespace {

// PE characteristics flags we read from the section table. Locally
// re-defined to avoid pulling <windows.h> into a header that the unit
// tests (and non-Windows tooling) compile.
constexpr uint32_t kSectExecute  = 0x20000000u;
constexpr uint32_t kSectCntCode  = 0x00000020u;
constexpr uint32_t kSectInitData = 0x00000040u;

constexpr size_t kSectionEntry = 40;
constexpr size_t kCoffSize     = 20;

inline uint16_t r16(std::span<const uint8_t> p, size_t off) noexcept {
    return static_cast<uint16_t>(p[off]) |
           (static_cast<uint16_t>(p[off + 1]) << 8);
}

inline uint32_t r32(std::span<const uint8_t> p, size_t off) noexcept {
    return static_cast<uint32_t>(p[off]) |
           (static_cast<uint32_t>(p[off + 1]) << 8) |
           (static_cast<uint32_t>(p[off + 2]) << 16) |
           (static_cast<uint32_t>(p[off + 3]) << 24);
}

struct ParsedSection {
    char     name_buf[9] = {};
    uint32_t raw_ptr  = 0;
    uint32_t raw_size = 0;
    uint32_t virt_addr= 0;
    uint32_t virt_size= 0;
    uint32_t chars    = 0;
};

struct DirEntry {
    uint32_t rva  = 0;
    uint32_t size = 0;
};

struct ParsedPe {
    bool                       valid = false;
    std::vector<ParsedSection> sections;
    std::vector<DirEntry>      dirs;
};

// Lightweight PE header walk. Returns `valid=false` if anything looks
// off; callers treat that as "skip PE-aware scoping". We deliberately
// do not error - non-PE inputs are normal in the bisect codepath
// (raw shellcode, decoy blobs, ...).
ParsedPe parse_pe(std::span<const uint8_t> pe) {
    ParsedPe out;
    if (pe.size() < 0x40) return out;

    const uint32_t e_lfanew = r32(pe, 0x3c);
    if (e_lfanew + 0x18 > pe.size()) return out;
    if (pe[e_lfanew]     != 'P' || pe[e_lfanew + 1] != 'E' ||
        pe[e_lfanew + 2] != 0   || pe[e_lfanew + 3] != 0) {
        return out;
    }

    const size_t coff = e_lfanew + 4;
    if (coff + kCoffSize > pe.size()) return out;
    const uint16_t num_sections = r16(pe, coff + 2);
    const uint16_t opt_size     = r16(pe, coff + 16);

    const size_t opt_off = coff + kCoffSize;
    if (opt_off + opt_size > pe.size()) return out;
    if (opt_size >= 2) {
        const uint16_t magic = r16(pe, opt_off);
        // PE32 (0x10b) or PE32+ (0x20b). Anything else is ROM image
        // or malformed - bail.
        const bool is_pe32_plus = (magic == 0x20b);
        const bool is_pe32      = (magic == 0x10b);
        if (!(is_pe32 || is_pe32_plus)) return out;

        // NumberOfRvaAndSizes lives just before the data directories.
        // Field offsets within the optional header (v1 layouts):
        //   PE32:  92 (0x5c)  -> directories at 96 (0x60)
        //   PE32+: 108 (0x6c) -> directories at 112 (0x70)
        const size_t nrva_off = opt_off + (is_pe32_plus ? 0x6c : 0x5c);
        const size_t dir_off  = opt_off + (is_pe32_plus ? 0x70 : 0x60);
        if (nrva_off + 4 > pe.size()) return out;
        uint32_t nrva = r32(pe, nrva_off);
        if (nrva > 16) nrva = 16;  // PECOFF caps it; defensive clamp.
        if (dir_off + size_t(nrva) * 8 > pe.size()) return out;

        out.dirs.reserve(nrva);
        for (uint32_t i = 0; i < nrva; ++i) {
            DirEntry d;
            d.rva  = r32(pe, dir_off + i * 8);
            d.size = r32(pe, dir_off + i * 8 + 4);
            out.dirs.push_back(d);
        }
    }

    const size_t sect_off = opt_off + opt_size;
    if (sect_off + size_t(num_sections) * kSectionEntry > pe.size()) {
        return out;
    }

    out.sections.reserve(num_sections);
    for (uint16_t i = 0; i < num_sections; ++i) {
        const size_t off = sect_off + size_t(i) * kSectionEntry;
        ParsedSection s;
        std::memcpy(s.name_buf, pe.data() + off, 8);
        s.name_buf[8]  = 0;
        s.virt_size    = r32(pe, off + 8);
        s.virt_addr    = r32(pe, off + 12);
        s.raw_size     = r32(pe, off + 16);
        s.raw_ptr      = r32(pe, off + 20);
        s.chars        = r32(pe, off + 36);

        // A raw_size that walks off the end of the file is a malformed
        // section; ignore rather than fail the whole walk.
        if (s.raw_ptr >= pe.size()) continue;
        const size_t end = std::min<size_t>(pe.size(),
                                            size_t(s.raw_ptr) +
                                            size_t(s.raw_size));
        s.raw_size = static_cast<uint32_t>(end - s.raw_ptr);
        out.sections.push_back(s);
    }

    out.valid = true;
    return out;
}

bool section_is_code(const ParsedSection& s) noexcept {
    return (s.chars & (kSectExecute | kSectCntCode)) != 0;
}

bool section_is_data(const ParsedSection& s) noexcept {
    return ((s.chars & kSectInitData) != 0) &&
           ((s.chars & kSectExecute)  == 0);
}

// Map an RVA window to a file-offset window, walking the section
// table. Returns std::nullopt-ish (length 0) if no section contains
// the entire window.
ScanRange rva_window_to_file(const ParsedPe& pe,
                             uint32_t rva,
                             uint32_t size) noexcept {
    if (size == 0) return {0, 0};
    for (const auto& s : pe.sections) {
        const uint64_t va_lo = s.virt_addr;
        const uint64_t va_hi = uint64_t(s.virt_addr) +
                               std::max<uint64_t>(s.virt_size, s.raw_size);
        if (rva >= va_lo && rva < va_hi) {
            const uint64_t off_in = rva - va_lo;
            if (off_in >= s.raw_size) return {0, 0};
            const uint64_t avail = s.raw_size - off_in;
            const uint64_t use   = std::min<uint64_t>(size, avail);
            return { size_t(s.raw_ptr + off_in), size_t(use) };
        }
    }
    return {0, 0};
}

// Subtract one (excl.offset, excl.length) range from a sorted list of
// non-overlapping kept ranges, splitting entries when the exclude
// punches a hole through the middle of a kept range.
void subtract_range(std::vector<ScanRange>& kept,
                    const ScanRange&        excl) {
    if (excl.length == 0) return;
    std::vector<ScanRange> out;
    out.reserve(kept.size() + 1);
    const size_t e_lo = excl.file_offset;
    const size_t e_hi = excl.file_offset + excl.length;

    for (const auto& k : kept) {
        const size_t k_lo = k.file_offset;
        const size_t k_hi = k.file_offset + k.length;
        if (e_hi <= k_lo || e_lo >= k_hi) {
            out.push_back(k);                    // disjoint
            continue;
        }
        if (e_lo <= k_lo && e_hi >= k_hi) {
            continue;                            // fully consumed
        }
        if (e_lo > k_lo) {
            out.push_back({k_lo, e_lo - k_lo});  // left remnant
        }
        if (e_hi < k_hi) {
            out.push_back({e_hi, k_hi - e_hi});  // right remnant
        }
    }
    kept = std::move(out);
}

void coalesce(std::vector<ScanRange>& v) {
    if (v.size() <= 1) {
        if (!v.empty() && v.front().length == 0) v.clear();
        return;
    }
    std::sort(v.begin(), v.end(),
              [](const ScanRange& a, const ScanRange& b) noexcept {
                  return a.file_offset < b.file_offset;
              });
    std::vector<ScanRange> out;
    out.reserve(v.size());
    for (const auto& r : v) {
        if (r.length == 0) continue;
        if (!out.empty() &&
            out.back().file_offset + out.back().length == r.file_offset) {
            out.back().length += r.length;
        } else {
            out.push_back(r);
        }
    }
    v = std::move(out);
}

}  // namespace

Result<std::vector<ScanRange>>
compute_pe_scan_ranges(std::span<const uint8_t> pe, ScanScope scope) {
    if (scope == ScanScope::Raw) return std::vector<ScanRange>{};

    const auto parsed = parse_pe(pe);
    if (!parsed.valid) return std::vector<ScanRange>{};

    std::vector<ScanRange> kept;
    kept.reserve(parsed.sections.size());
    for (const auto& s : parsed.sections) {
        if (s.raw_size == 0) continue;
        const bool include = (scope == ScanScope::Sections    ||
                              scope == ScanScope::SectionsAll) ? true
                           : (scope == ScanScope::CodeOnly)    ? section_is_code(s)
                           : (scope == ScanScope::DataOnly)    ? section_is_data(s)
                           : false;
        if (!include) continue;
        kept.push_back({size_t(s.raw_ptr), size_t(s.raw_size)});
    }
    coalesce(kept);

    if (scope == ScanScope::SectionsAll) {
        return kept;
    }

    // Subtract data-directory file ranges from `kept` so the parser
    // sees them verbatim during every L/R scan. CertificateTable (idx
    // 4) is intentionally NOT subtracted: its `rva` is actually a file
    // offset (not an RVA), it lives at the file tail, and signature
    // checks happen post-load - parser-bail is not a concern there.
    constexpr uint32_t kCertDir = 4;
    for (uint32_t i = 0; i < parsed.dirs.size(); ++i) {
        if (i == kCertDir) continue;
        const auto& d = parsed.dirs[i];
        if (d.rva == 0 || d.size == 0) continue;
        const ScanRange fr = rva_window_to_file(parsed, d.rva, d.size);
        if (fr.length == 0) continue;
        subtract_range(kept, fr);
    }

    coalesce(kept);
    return kept;
}

}

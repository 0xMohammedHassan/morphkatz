#include "morphkatz/format/pe_section_appender.hpp"

#include "morphkatz/common/logging.hpp"
#include "morphkatz/format/pe_image.hpp"

#include <algorithm>
#include <cstring>

namespace morphkatz::format {

namespace {

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
inline void w16(std::span<uint8_t> p, size_t o, uint16_t v) noexcept {
    p[o]     = static_cast<uint8_t>(v & 0xff);
    p[o + 1] = static_cast<uint8_t>((v >> 8) & 0xff);
}
inline void w32(std::span<uint8_t> p, size_t o, uint32_t v) noexcept {
    p[o]     = static_cast<uint8_t>(v & 0xff);
    p[o + 1] = static_cast<uint8_t>((v >> 8) & 0xff);
    p[o + 2] = static_cast<uint8_t>((v >> 16) & 0xff);
    p[o + 3] = static_cast<uint8_t>((v >> 24) & 0xff);
}

constexpr uint32_t align_up(uint32_t v, uint32_t a) noexcept {
    if (a == 0) return v;
    const uint32_t r = v % a;
    return (r == 0) ? v : v + (a - r);
}

constexpr uint64_t align_up_u64(uint64_t v, uint64_t a) noexcept {
    if (a == 0) return v;
    const uint64_t r = v % a;
    return (r == 0) ? v : v + (a - r);
}

// COFF header offsets relative to the PE signature (PE\0\0):
//   +0..+3   "PE\0\0"
//   +4..+5   Machine
//   +6..+7   NumberOfSections
//   +8..+11  TimeDateStamp
//   +12..+15 PointerToSymbolTable
//   +16..+19 NumberOfSymbols
//   +20..+21 SizeOfOptionalHeader
//   +22..+23 Characteristics
constexpr size_t kCoffMachine          = 4;
constexpr size_t kCoffNumberOfSections = 6;
constexpr size_t kCoffSizeOfOptHdr     = 20;
constexpr size_t kCoffEnd              = 24;

// Optional header field offsets (PE32+; values for PE32 differ for
// some 64-bit fields but we already gate to AMD64 in load_image).
constexpr size_t kOptMagic                  = 0;     // 2
constexpr size_t kOptSizeOfCode             = 4;     // 4
constexpr size_t kOptSizeOfInitializedData  = 8;     // 4
constexpr size_t kOptSizeOfUninitializedData= 12;    // 4
constexpr size_t kOptSectionAlignment       = 32;    // 4
constexpr size_t kOptFileAlignment          = 36;    // 4
constexpr size_t kOptSizeOfImage            = 56;    // 4
constexpr size_t kOptSizeOfHeaders          = 60;    // 4

}  // namespace

Result<AppendedSection>
append_section(PeImage&                 image,
               std::string              name,
               std::span<const uint8_t> raw,
               uint32_t                 characteristics) {
    auto& buf = image.buffer();
    if (buf.size() < 0x40) {
        return Error::make(ErrorKind::ParseFormat,
            "append_section: file too small to be a PE");
    }
    if (buf[0] != 'M' || buf[1] != 'Z') {
        return Error::make(ErrorKind::NotSupported,
            "append_section requires a PE image (no MZ signature)");
    }

    const uint32_t e_lfanew = r32({buf.data(), buf.size()}, 0x3c);
    if (e_lfanew + kCoffEnd > buf.size()) {
        return Error::make(ErrorKind::ParseFormat,
            "append_section: e_lfanew points past EOF");
    }
    if (buf[e_lfanew]     != 'P' || buf[e_lfanew + 1] != 'E' ||
        buf[e_lfanew + 2] != 0   || buf[e_lfanew + 3] != 0) {
        return Error::make(ErrorKind::ParseFormat,
            "append_section: missing PE\\0\\0 signature");
    }

    const std::span<uint8_t> view{buf.data(), buf.size()};
    const uint16_t num_sections = r16(view, e_lfanew + kCoffNumberOfSections);
    const uint16_t opt_size     = r16(view, e_lfanew + kCoffSizeOfOptHdr);
    const size_t   opt_off      = e_lfanew + kCoffEnd;
    if (opt_off + opt_size > buf.size()) {
        return Error::make(ErrorKind::ParseFormat,
            "append_section: optional header truncated");
    }

    const uint16_t magic = r16(view, opt_off + kOptMagic);
    if (magic != 0x20b && magic != 0x10b) {
        return Error::make(ErrorKind::NotSupported,
            "append_section: not a PE32 / PE32+ image");
    }
    const uint32_t section_alignment = r32(view, opt_off + kOptSectionAlignment);
    const uint32_t file_alignment    = r32(view, opt_off + kOptFileAlignment);
    if (section_alignment == 0 || file_alignment == 0) {
        return Error::make(ErrorKind::ParseFormat,
            "append_section: zero alignment fields");
    }

    const size_t sect_table_off = opt_off + opt_size;
    const size_t sect_table_end = sect_table_off + size_t(num_sections) * 40;
    if (sect_table_end > buf.size()) {
        return Error::make(ErrorKind::ParseFormat,
            "append_section: section table runs past EOF");
    }

    // Walk the section table to find:
    //  - the smallest raw_ptr (== first section's file offset)
    //  - the largest virtual_addr + virtual_size (== end of mapped image)
    //  - SizeOfHeaders verification
    uint32_t first_raw_ptr = UINT32_MAX;
    uint64_t end_va        = 0;
    for (uint16_t i = 0; i < num_sections; ++i) {
        const size_t off = sect_table_off + size_t(i) * 40;
        const uint32_t vsz = r32(view, off + 8);
        const uint32_t va  = r32(view, off + 12);
        const uint32_t rsz = r32(view, off + 16);
        const uint32_t rp  = r32(view, off + 20);
        if (rp != 0 && rsz != 0) {
            first_raw_ptr = std::min(first_raw_ptr, rp);
        }
        const uint64_t va_end = uint64_t(va) +
                                std::max<uint64_t>(vsz, rsz);
        end_va = std::max(end_va, va_end);
    }

    // Slack check: do we have room for one more 40-byte header before
    // the first section's raw data starts? If `first_raw_ptr` is
    // UINT32_MAX (no sections with both raw_size and raw_ptr) we
    // conservatively reject - that's an unusual layout.
    if (first_raw_ptr == UINT32_MAX) {
        return Error::make(ErrorKind::Invalid,
            "append_section: no section with raw data; "
            "cannot determine header slack");
    }
    if (sect_table_end + 40 > first_raw_ptr) {
        return Error::make(ErrorKind::Invalid,
            "append_section: insufficient header slack for a new "
            "section header (would have to shift section raw "
            "offsets; not supported in v1). Re-run without "
            "--data-morph or pre-process with editbin /HEADERSIZE.");
    }

    // Virtual layout: place the new section at the next
    // SectionAlignment-rounded RVA after end_va.
    const uint64_t new_va64 = align_up_u64(end_va, section_alignment);
    if (new_va64 > UINT32_MAX) {
        return Error::make(ErrorKind::Invalid,
            "append_section: virtual address would overflow u32");
    }
    const uint32_t new_va = static_cast<uint32_t>(new_va64);
    const uint32_t vsize  = static_cast<uint32_t>(raw.size());

    // File layout: place raw data at the next FileAlignment-rounded
    // offset after the current file size.
    const uint64_t cur_size  = buf.size();
    const uint64_t new_raw64 = align_up_u64(cur_size, file_alignment);
    if (new_raw64 > UINT32_MAX) {
        return Error::make(ErrorKind::Invalid,
            "append_section: raw offset would overflow u32");
    }
    const uint32_t new_raw    = static_cast<uint32_t>(new_raw64);
    const uint32_t rsize      = align_up(static_cast<uint32_t>(raw.size()),
                                          file_alignment);

    // Grow the buffer: add padding (zeros) up to new_raw, then the raw
    // bytes, then padding up to new_raw + rsize.
    buf.resize(static_cast<size_t>(new_raw) + rsize, 0);
    if (!raw.empty()) {
        std::memcpy(buf.data() + new_raw, raw.data(), raw.size());
    }

    // Re-acquire the writeable view after potential reallocation.
    const std::span<uint8_t> view2{buf.data(), buf.size()};

    // Write the new IMAGE_SECTION_HEADER into the slack region.
    char name_buf[8] = {};
    const auto cn = std::min<size_t>(8, name.size());
    std::memcpy(name_buf, name.data(), cn);
    const size_t new_hdr_off = sect_table_end;
    std::memcpy(view2.data() + new_hdr_off, name_buf, 8);
    w32(view2, new_hdr_off +  8, vsize);
    w32(view2, new_hdr_off + 12, new_va);
    w32(view2, new_hdr_off + 16, rsize);
    w32(view2, new_hdr_off + 20, new_raw);
    w32(view2, new_hdr_off + 24, 0);              // PointerToRelocations
    w32(view2, new_hdr_off + 28, 0);              // PointerToLinenumbers
    w16(view2, new_hdr_off + 32, 0);              // NumberOfRelocations
    w16(view2, new_hdr_off + 34, 0);              // NumberOfLinenumbers
    w32(view2, new_hdr_off + 36, characteristics);

    // Bump NumberOfSections.
    w16(view2, e_lfanew + kCoffNumberOfSections,
        static_cast<uint16_t>(num_sections + 1));

    // Update OptionalHeader counters that depend on section payload.
    if (characteristics & SectionChars::kCntCode) {
        const uint32_t cur = r32(view2, opt_off + kOptSizeOfCode);
        w32(view2, opt_off + kOptSizeOfCode, cur + rsize);
    }
    if (characteristics & SectionChars::kCntInitData) {
        const uint32_t cur = r32(view2, opt_off + kOptSizeOfInitializedData);
        w32(view2, opt_off + kOptSizeOfInitializedData, cur + rsize);
    }
    if (characteristics & SectionChars::kCntUninitData) {
        const uint32_t cur = r32(view2, opt_off + kOptSizeOfUninitializedData);
        w32(view2, opt_off + kOptSizeOfUninitializedData, cur + vsize);
    }

    // SizeOfImage: align(new_va + vsize, SectionAlignment).
    const uint64_t new_image_end = align_up_u64(uint64_t(new_va) + vsize,
                                                section_alignment);
    if (new_image_end > UINT32_MAX) {
        return Error::make(ErrorKind::Invalid,
            "append_section: SizeOfImage would overflow u32");
    }
    w32(view2, opt_off + kOptSizeOfImage, static_cast<uint32_t>(new_image_end));

    AppendedSection out;
    out.name            = std::string(name_buf,
                                      strnlen(name_buf, sizeof(name_buf)));
    out.section_index   = num_sections;       // 0-based; new entry's index
    out.raw_offset      = new_raw;
    out.raw_size        = rsize;
    out.virtual_addr    = new_va;
    out.virtual_size    = vsize;
    out.characteristics = characteristics;

    MK_DEBUG("PE: appended section '{}' idx={} raw=[0x{:x}, +0x{:x}) "
             "rva=0x{:x} vsize=0x{:x} chars=0x{:08x} (SoI now 0x{:x})",
             out.name, out.section_index,
             out.raw_offset, out.raw_size,
             out.virtual_addr, out.virtual_size,
             out.characteristics,
             static_cast<uint32_t>(new_image_end));
    return out;
}

}

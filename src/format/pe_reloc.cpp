#include "morphkatz/format/pe_reloc.hpp"

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
inline void w32(std::span<uint8_t> p, size_t o, uint32_t v) noexcept {
    p[o]     = static_cast<uint8_t>(v & 0xff);
    p[o + 1] = static_cast<uint8_t>((v >> 8) & 0xff);
    p[o + 2] = static_cast<uint8_t>((v >> 16) & 0xff);
    p[o + 3] = static_cast<uint8_t>((v >> 24) & 0xff);
}
inline void w16(std::span<uint8_t> p, size_t o, uint16_t v) noexcept {
    p[o]     = static_cast<uint8_t>(v & 0xff);
    p[o + 1] = static_cast<uint8_t>((v >> 8) & 0xff);
}

constexpr uint32_t kImageRelBasedDir64 = 10;

// PE32+ reloc directory location:
//   PE\0\0 (4) + COFF (20) + 24 (offset within OptionalHeader)
//   Reloc dir entry index = 5; each entry is 8 bytes.
size_t reloc_dir_offset(std::span<const uint8_t> data) noexcept {
    if (data.size() < 0x40) return SIZE_MAX;
    const uint32_t e_lfanew = r32(data, 0x3c);
    if (e_lfanew + 24 > data.size()) return SIZE_MAX;
    if (data[e_lfanew]     != 'P' || data[e_lfanew + 1] != 'E' ||
        data[e_lfanew + 2] != 0   || data[e_lfanew + 3] != 0) return SIZE_MAX;
    const size_t opt = e_lfanew + 24;
    if (opt + 2 > data.size()) return SIZE_MAX;
    const uint16_t magic = r16(data, opt);
    size_t dd = 0;
    if (magic == 0x10b)      dd = opt + 96;
    else if (magic == 0x20b) dd = opt + 112;
    else                     return SIZE_MAX;
    if (dd + 6 * 8 > data.size()) return SIZE_MAX;
    return dd + 5 * 8;   // index 5 = BASERELOC
}

struct SectionInfo {
    size_t   header_off = 0;
    uint32_t va         = 0;
    uint32_t vsize      = 0;
    uint32_t raw_ptr    = 0;
    uint32_t raw_size   = 0;
};

// Find the section header that owns a given RVA; returns nullopt-shaped
// SectionInfo (raw_size==0) on miss.
SectionInfo find_section_for_rva(std::span<const uint8_t> data,
                                  uint32_t rva) noexcept {
    SectionInfo s{};
    if (data.size() < 0x40) return s;
    const uint32_t e_lfanew = r32(data, 0x3c);
    if (e_lfanew + 24 > data.size()) return s;
    const size_t coff = e_lfanew + 4;
    const uint16_t num_sections = r16(data, coff + 2);
    const uint16_t opt_size     = r16(data, coff + 16);
    const size_t   opt_off      = coff + 20;
    const size_t   sect_off     = opt_off + opt_size;
    if (sect_off + size_t(num_sections) * 40 > data.size()) return s;
    for (uint16_t i = 0; i < num_sections; ++i) {
        const size_t off = sect_off + size_t(i) * 40;
        const uint32_t va  = r32(data, off + 12);
        const uint32_t vsz = r32(data, off + 8);
        const uint32_t rsz = r32(data, off + 16);
        const uint32_t rp  = r32(data, off + 20);
        const uint32_t end = va + std::max(vsz, rsz);
        if (rva >= va && rva < end) {
            s.header_off = off;
            s.va         = va;
            s.vsize      = vsz;
            s.raw_ptr    = rp;
            s.raw_size   = rsz;
            return s;
        }
    }
    return s;
}

}  // namespace

Result<void>
add_dir64_relocations(PeImage&                  image,
                      std::span<const uint32_t> target_rvas) {
    if (target_rvas.empty()) return {};

    auto& buf = image.buffer();
    const std::span<const uint8_t> view{buf.data(), buf.size()};

    const size_t dir_off = reloc_dir_offset(view);
    if (dir_off == SIZE_MAX) {
        return Error::make(ErrorKind::ParseFormat,
            "add_dir64_relocations: cannot locate base reloc directory");
    }
    const uint32_t reloc_rva  = r32(view, dir_off);
    const uint32_t reloc_size = r32(view, dir_off + 4);
    if (reloc_rva == 0 || reloc_size == 0) {
        return Error::make(ErrorKind::NotSupported,
            "add_dir64_relocations: PE has no .reloc table");
    }

    // The new entries must all be in the same 4 KiB page (v1 limitation).
    // Verify that constraint up-front so we can emit a clean error.
    const uint32_t page_va = target_rvas[0] & ~0xFFFu;
    for (uint32_t rva : target_rvas) {
        if ((rva & ~0xFFFu) != page_va) {
            return Error::make(ErrorKind::NotSupported,
                "add_dir64_relocations: targets span multiple 4 KiB pages "
                "(v1 supports only one page per call)");
        }
    }

    // Locate the section that holds the .reloc directory.
    const auto sect = find_section_for_rva(view, reloc_rva);
    if (sect.raw_size == 0) {
        return Error::make(ErrorKind::ParseFormat,
            "add_dir64_relocations: reloc dir not in any section");
    }

    // Block size: 8-byte header + 2 bytes per entry, aligned up to 4.
    const uint32_t entries = static_cast<uint32_t>(target_rvas.size());
    uint32_t block_size = 8 + entries * 2;
    if (block_size & 3) block_size = (block_size + 3) & ~3u;

    // Slack inside .reloc (raw_size - virtual_size). The current reloc
    // dir Size matches virtual_size in well-formed PEs but we don't
    // assume that: we use the gap between the end of the directory
    // payload and the section's raw_size.
    const uint32_t dir_end_rva = reloc_rva + reloc_size;
    const uint32_t sect_end_rva = sect.va + std::max(sect.vsize, sect.raw_size);
    if (dir_end_rva + block_size > sect_end_rva) {
        return Error::make(ErrorKind::NotSupported,
            "add_dir64_relocations: insufficient slack in .reloc for a "
            "new page block (need " + std::to_string(block_size) +
            " bytes; falling back to EP-thunk decoder placement)");
    }

    // Translate the destination RVA to a file offset.
    if (dir_end_rva < sect.va) {
        return Error::make(ErrorKind::Invalid,
            "add_dir64_relocations: dir_end < section_va");
    }
    const uint32_t in_section = dir_end_rva - sect.va;
    if (in_section >= sect.raw_size) {
        return Error::make(ErrorKind::NotSupported,
            "add_dir64_relocations: new block would land past raw end "
            "of .reloc; v1 doesn't grow the section");
    }
    const uint32_t file_off = sect.raw_ptr + in_section;
    if (file_off + block_size > buf.size()) {
        return Error::make(ErrorKind::ParseFormat,
            "add_dir64_relocations: file truncated");
    }

    // Write the page block in place.
    std::span<uint8_t> wview{buf.data(), buf.size()};
    w32(wview, file_off,     page_va);
    w32(wview, file_off + 4, block_size);
    for (uint32_t i = 0; i < entries; ++i) {
        const uint16_t entry =
            static_cast<uint16_t>(((kImageRelBasedDir64 & 0xF) << 12) |
                                  ((target_rvas[i] - page_va) & 0xFFF));
        w16(wview, file_off + 8 + i * 2, entry);
    }
    // Pad with ABSOLUTE entries so the block is dword-aligned.
    for (uint32_t pad = 8 + entries * 2; pad < block_size; pad += 2) {
        w16(wview, file_off + pad, 0);   // type=0=ABSOLUTE, off=0
    }

    // Grow the directory size.
    w32(wview, dir_off + 4, reloc_size + block_size);

    // Grow the section's virtual_size if the new block extends past it.
    const uint32_t new_in_section = in_section + block_size;
    if (new_in_section > sect.vsize) {
        w32(wview, sect.header_off + 8, new_in_section);
    }

    MK_DEBUG("PE: appended {} reloc entry(ies) for page 0x{:x} into .reloc "
             "(file_off=0x{:x}, +{} bytes; dir size now 0x{:x})",
              entries, page_va, file_off, block_size, reloc_size + block_size);
    return {};
}

}

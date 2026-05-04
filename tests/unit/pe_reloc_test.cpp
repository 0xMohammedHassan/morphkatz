#include "morphkatz/format/pe_reloc.hpp"

#include "morphkatz/format/pe_image.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <memory>
#include <vector>

namespace {

using morphkatz::format::add_dir64_relocations;
using morphkatz::format::PeImage;

inline void w16(std::vector<uint8_t>& b, size_t o, uint16_t v) {
    b[o]     = static_cast<uint8_t>(v & 0xff);
    b[o + 1] = static_cast<uint8_t>((v >> 8) & 0xff);
}
inline void w32(std::vector<uint8_t>& b, size_t o, uint32_t v) {
    b[o]     = static_cast<uint8_t>(v & 0xff);
    b[o + 1] = static_cast<uint8_t>((v >> 8) & 0xff);
    b[o + 2] = static_cast<uint8_t>((v >> 16) & 0xff);
    b[o + 3] = static_cast<uint8_t>((v >> 24) & 0xff);
}
inline uint32_t r32(const std::vector<uint8_t>& b, size_t o) {
    return static_cast<uint32_t>(b[o]) |
           (static_cast<uint32_t>(b[o + 1]) << 8) |
           (static_cast<uint32_t>(b[o + 2]) << 16) |
           (static_cast<uint32_t>(b[o + 3]) << 24);
}
inline uint16_t r16(const std::vector<uint8_t>& b, size_t o) {
    return static_cast<uint16_t>(b[o]) |
           (static_cast<uint16_t>(b[o + 1]) << 8);
}

constexpr size_t kElfanew  = 0x80;
constexpr size_t kSectTbl  = 0x188;
constexpr size_t kFileSize = 0xC00;

// Layout:
//   .text   raw=[0x400, 0x500), va=0x1000, vsz=0x100, rsz=0x100
//   .reloc  raw=[0x500, 0x800), va=0x2000, vsz=initial_dir_size, rsz=0x300
//
// `initial_dir_size` controls how much slack remains in `.reloc` between
// the end of the existing relocation directory payload and the section's
// raw_size. With `rsz=0x300`, picking `initial_dir_size=0x10` leaves
// 0x2F0 bytes of slack - plenty for one new page block.
std::vector<uint8_t> make_pe_with_reloc(uint32_t initial_dir_size,
                                         bool      seed_one_block = true) {
    std::vector<uint8_t> b(kFileSize, 0);

    b[0] = 'M'; b[1] = 'Z';
    w32(b, 0x3c, static_cast<uint32_t>(kElfanew));

    b[kElfanew + 0] = 'P';
    b[kElfanew + 1] = 'E';
    b[kElfanew + 2] = 0;
    b[kElfanew + 3] = 0;

    const size_t coff = kElfanew + 4;
    w16(b, coff +  0, 0x8664);
    w16(b, coff +  2, 2);              // NumberOfSections
    w16(b, coff + 16, 0xF0);           // SizeOfOptionalHeader
    w16(b, coff + 18, 0x22);

    const size_t opt = coff + 20;
    w16(b, opt + 0, 0x20b);            // PE32+
    w32(b, opt + 24,  0x00400000);     // ImageBase low
    w32(b, opt + 32,  0x00001000);     // SectionAlignment
    w32(b, opt + 36,  0x00000200);     // FileAlignment
    w32(b, opt + 56,  0x00004000);     // SizeOfImage
    w32(b, opt + 60,  0x400);          // SizeOfHeaders
    w32(b, opt + 0x6c, 16);            // NumberOfRvaAndSizes

    // Reloc directory entry (index 5, 8 bytes per entry, base = opt + 112).
    const size_t dd_reloc = opt + 112 + 5 * 8;
    w32(b, dd_reloc + 0, 0x2000);              // RVA
    w32(b, dd_reloc + 4, initial_dir_size);    // Size

    // Sections.
    constexpr uint32_t kCode  = 0x60000020u;
    constexpr uint32_t kReloc = 0x42000040u;   // INIT|DISCARDABLE|READ
    auto write_section = [&](size_t off, const char* name,
                             uint32_t vsz, uint32_t va,
                             uint32_t rsz, uint32_t rptr,
                             uint32_t chars) {
        std::memset(b.data() + off, 0, 40);
        std::memcpy(b.data() + off, name, std::min<size_t>(8, std::strlen(name)));
        w32(b, off +  8, vsz);
        w32(b, off + 12, va);
        w32(b, off + 16, rsz);
        w32(b, off + 20, rptr);
        w32(b, off + 36, chars);
    };
    write_section(kSectTbl + 0 * 40, ".text",
                  /*vsz=*/0x100, /*va=*/0x1000,
                  /*rsz=*/0x100, /*raw=*/0x400, kCode);
    write_section(kSectTbl + 1 * 40, ".reloc",
                  /*vsz=*/initial_dir_size, /*va=*/0x2000,
                  /*rsz=*/0x300, /*raw=*/0x500, kReloc);

    // Seed the .reloc section with one valid (but trivial) page block so
    // `add_dir64_relocations` finds a non-zero directory size and can
    // append after it.
    if (seed_one_block && initial_dir_size >= 8) {
        const size_t off = 0x500;
        w32(b, off + 0, 0x3000);   // PageRVA (arbitrary, distinct from new page)
        w32(b, off + 4, initial_dir_size);
        // Pad rest with zeros (ABSOLUTE entries) - already zero from the
        // initial buffer fill.
    }
    return b;
}

std::unique_ptr<PeImage> make_image(uint32_t initial_dir_size,
                                     bool      seed = true) {
    auto bytes = make_pe_with_reloc(initial_dir_size, seed);
    auto r = PeImage::from_bytes(std::move(bytes), false);
    if (!r.ok()) return nullptr;
    return std::move(*r);
}

}  // namespace

TEST_CASE("add_dir64_relocations: rejects missing .reloc directory",
          "[format][pe_reloc][unit]") {
    // Initial dir size = 0 -> reloc directory is "empty" -> NotSupported.
    auto img = make_image(/*initial_dir_size=*/0, /*seed=*/false);
    REQUIRE(img != nullptr);

    std::vector<uint32_t> targets{ 0x4000 };
    auto r = add_dir64_relocations(*img, targets);
    REQUIRE(!r.ok());
    CHECK(r.error().kind == morphkatz::ErrorKind::NotSupported);
}

TEST_CASE("add_dir64_relocations: rejects targets that span multiple pages",
          "[format][pe_reloc][unit]") {
    auto img = make_image(/*initial_dir_size=*/0x10);
    REQUIRE(img != nullptr);

    // Two RVAs in two different 4 KiB pages.
    std::vector<uint32_t> targets{ 0x4000, 0x5000 };
    auto r = add_dir64_relocations(*img, targets);
    REQUIRE(!r.ok());
    CHECK(r.error().kind == morphkatz::ErrorKind::NotSupported);
    CHECK(r.error().what.find("multiple") != std::string::npos);
}

TEST_CASE("add_dir64_relocations: appends a single page block in .reloc",
          "[format][pe_reloc][unit]") {
    constexpr uint32_t kInitialDirSize = 0x10;       // 16 bytes seed block
    auto img = make_image(kInitialDirSize);
    REQUIRE(img != nullptr);

    // Three targets, all on the 0x4000 page.
    std::vector<uint32_t> targets{ 0x4010, 0x4018, 0x4020 };
    auto r = add_dir64_relocations(*img, targets);
    REQUIRE(r.ok());

    const auto& buf = img->buffer();

    // The new block lives at file_off = .reloc.raw_ptr (0x500) + dir_end_in_section
    //   dir_end_rva     = 0x2000 + 0x10 = 0x2010
    //   in_section      = 0x2010 - 0x2000 = 0x10
    //   file_off        = 0x500 + 0x10  = 0x510
    constexpr size_t kNewBlockOff = 0x510;

    // Block size = 8 (hdr) + 3 entries * 2 = 14 -> aligned to 16 = 0x10.
    constexpr uint32_t kBlockSize = 0x10;

    CHECK(r32(buf, kNewBlockOff + 0) == 0x4000);     // PageRVA (page-aligned)
    CHECK(r32(buf, kNewBlockOff + 4) == kBlockSize); // BlockSize

    // Entry encoding: top nibble = type (10 = DIR64), low 12 = page off.
    constexpr uint32_t kImageRelDir64 = 10;
    auto entry_off = [](uint32_t rva) {
        return static_cast<uint16_t>(((kImageRelDir64 & 0xF) << 12) |
                                     ((rva - 0x4000) & 0xFFF));
    };
    CHECK(r16(buf, kNewBlockOff + 8 + 0) == entry_off(0x4010));
    CHECK(r16(buf, kNewBlockOff + 8 + 2) == entry_off(0x4018));
    CHECK(r16(buf, kNewBlockOff + 8 + 4) == entry_off(0x4020));
    // Padding entry (ABSOLUTE / type=0 / off=0) at +14, 2 bytes wide.
    CHECK(r16(buf, kNewBlockOff + 8 + 6) == 0);

    // Reloc directory size grows by kBlockSize.
    const size_t opt      = kElfanew + 4 + 20;
    const size_t dd_reloc = opt + 112 + 5 * 8;
    CHECK(r32(buf, dd_reloc + 4) == kInitialDirSize + kBlockSize);

    // Section virtual_size catches up to the new directory payload.
    const size_t reloc_hdr = kSectTbl + 1 * 40;
    CHECK(r32(buf, reloc_hdr + 8) >= kInitialDirSize + kBlockSize);
}

TEST_CASE("add_dir64_relocations: rejects when .reloc has insufficient slack",
          "[format][pe_reloc][unit]") {
    // Make the initial dir size eat almost the entire .reloc section so
    // the new block can't fit. .reloc raw_size is 0x300; leave 4 bytes
    // (definitely smaller than 8B header + entries).
    constexpr uint32_t kInitialDirSize = 0x300 - 4;
    auto img = make_image(kInitialDirSize);
    REQUIRE(img != nullptr);

    std::vector<uint32_t> targets{ 0x4010, 0x4018 };
    auto r = add_dir64_relocations(*img, targets);
    REQUIRE(!r.ok());
    CHECK(r.error().kind == morphkatz::ErrorKind::NotSupported);
    CHECK(r.error().what.find("slack") != std::string::npos);
}

TEST_CASE("add_dir64_relocations: empty target list is a no-op",
          "[format][pe_reloc][unit]") {
    auto img = make_image(/*initial_dir_size=*/0x10);
    REQUIRE(img != nullptr);

    const auto before = img->buffer();
    std::vector<uint32_t> targets;
    auto r = add_dir64_relocations(*img, targets);
    REQUIRE(r.ok());
    // Nothing changed.
    CHECK(img->buffer() == before);
}

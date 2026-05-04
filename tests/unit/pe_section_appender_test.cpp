#include "morphkatz/format/pe_section_appender.hpp"

#include "morphkatz/format/pe_image.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <vector>

namespace {

using morphkatz::format::append_section;
using morphkatz::format::AppendedSection;
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
inline uint16_t r16(const std::vector<uint8_t>& b, size_t o) {
    return static_cast<uint16_t>(b[o]) |
           (static_cast<uint16_t>(b[o + 1]) << 8);
}
inline uint32_t r32(const std::vector<uint8_t>& b, size_t o) {
    return static_cast<uint32_t>(b[o]) |
           (static_cast<uint32_t>(b[o + 1]) << 8) |
           (static_cast<uint32_t>(b[o + 2]) << 16) |
           (static_cast<uint32_t>(b[o + 3]) << 24);
}

constexpr size_t kElfanew  = 0x80;
constexpr size_t kSectTbl  = 0x188;
constexpr size_t kFileSize = 0x800;     // includes some slack at the end

// Build a synthetic PE32+ buffer. SizeOfHeaders = first_section_raw_ptr
// is also the "first raw" anchor so the slack-check logic in
// append_section sees [section_table_end, first_raw_ptr) as the
// header padding zone.
std::vector<uint8_t> make_pe(uint32_t first_section_raw_ptr) {
    std::vector<uint8_t> b(kFileSize, 0xCC);

    b[0] = 'M'; b[1] = 'Z';
    w32(b, 0x3c, static_cast<uint32_t>(kElfanew));

    b[kElfanew + 0] = 'P';
    b[kElfanew + 1] = 'E';
    b[kElfanew + 2] = 0;
    b[kElfanew + 3] = 0;

    const size_t coff = kElfanew + 4;
    w16(b, coff +  0, 0x8664);
    w16(b, coff +  2, 3);             // NumberOfSections
    w16(b, coff + 16, 0xF0);          // SizeOfOptionalHeader
    w16(b, coff + 18, 0x22);

    const size_t opt = coff + 20;
    w16(b, opt + 0, 0x20b);           // PE32+
    w32(b, opt + 4,   0x100);         // SizeOfCode
    w32(b, opt + 8,   0x200);         // SizeOfInitializedData
    w32(b, opt + 24,  0x00400000);    // ImageBase low
    w32(b, opt + 32,  0x00001000);    // SectionAlignment
    w32(b, opt + 36,  0x00000200);    // FileAlignment
    w32(b, opt + 56,  0x00004000);    // SizeOfImage (placeholder)
    w32(b, opt + 60,  static_cast<uint32_t>(first_section_raw_ptr));
    w32(b, opt + 0x6c, 16);           // NumberOfRvaAndSizes

    const auto write_section = [&](size_t off, const char* name,
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
    constexpr uint32_t kCode  = 0x60000020u;
    constexpr uint32_t kRdata = 0x40000040u;
    constexpr uint32_t kData  = 0xC0000040u;
    write_section(kSectTbl + 0 * 40, ".text",  0x100, 0x1000, 0x100,
                  first_section_raw_ptr, kCode);
    write_section(kSectTbl + 1 * 40, ".rdata", 0x100, 0x2000, 0x100,
                  first_section_raw_ptr + 0x100, kRdata);
    write_section(kSectTbl + 2 * 40, ".data",  0x100, 0x3000, 0x100,
                  first_section_raw_ptr + 0x200, kData);
    return b;
}

std::unique_ptr<PeImage> make_image(uint32_t first_raw) {
    auto bytes = make_pe(first_raw);
    // is_pe=false routes through the raw-shellcode constructor which
    // doesn't try to LIEF-parse our synthetic bytes; append_section
    // gates on the MZ/PE\0\0 signature only, so it accepts the buffer.
    auto r = PeImage::from_bytes(std::move(bytes), false);
    if (!r.ok()) return nullptr;
    return std::move(*r);
}

}  // namespace

TEST_CASE("append_section: rejects raw shellcode (no MZ)",
          "[format][pe_section_appender][unit]") {
    std::vector<uint8_t> raw(1024, 0xAA);
    auto img_r = PeImage::from_bytes(std::move(raw), false);
    REQUIRE(img_r.ok());
    auto& img = **img_r;

    std::vector<uint8_t> payload(64, 0x42);
    auto r = append_section(img, ".morph", payload, 0x40000040u);
    REQUIRE(!r.ok());
    CHECK(r.error().kind == morphkatz::ErrorKind::NotSupported);
}

TEST_CASE("append_section: rejects when there's no header slack",
          "[format][pe_section_appender][unit]") {
    // first_raw=0x200 => section table runs 0x188..0x200. No room for
    // a fourth 40-byte header.
    auto img = make_image(/*first_raw=*/0x200);
    REQUIRE(img != nullptr);

    std::vector<uint8_t> payload(64, 0x42);
    auto r = append_section(*img, ".morph", payload, 0x40000040u);
    REQUIRE(!r.ok());
    CHECK(r.error().kind == morphkatz::ErrorKind::Invalid);
    CHECK(r.error().what.find("slack") != std::string::npos);
}

TEST_CASE("append_section: succeeds with sufficient slack and updates headers",
          "[format][pe_section_appender][unit]") {
    // first_raw=0x400 => section table runs 0x188..0x200; header slack
    // is [0x200, 0x400). One more 40-byte slot fits comfortably.
    auto img = make_image(/*first_raw=*/0x400);
    REQUIRE(img != nullptr);

    std::vector<uint8_t> payload(0x40, 0x42);
    auto r = append_section(*img, ".morph", payload, 0x40000040u);
    REQUIRE(r.ok());
    const AppendedSection& a = *r;

    // FileAlignment = 0x200 -> raw_size rounds up.
    CHECK(a.raw_size == 0x200);
    CHECK(a.raw_offset == 0x800);            // file size was 0x800
    // Last section ended at VA 0x3100 (0x3000 + 0x100). SectionAlignment
    // = 0x1000 -> next VA is 0x4000.
    CHECK(a.virtual_addr == 0x4000);
    CHECK(a.virtual_size == 0x40);
    CHECK(a.section_index == 3);
    CHECK(a.name == ".morph");

    const auto& buf = img->buffer();
    REQUIRE(buf.size() == 0x800 + 0x200);

    // NumberOfSections bumped from 3 to 4.
    CHECK(r16(buf, kElfanew + 4 + 2) == 4);

    // SizeOfImage updated to align(0x4000+0x40, 0x1000) = 0x5000.
    const size_t opt = kElfanew + 4 + 20;
    CHECK(r32(buf, opt + 56) == 0x5000);

    // SizeOfInitializedData incremented by raw_size (we set CntInitData
    // bit). Was 0x200, becomes 0x400.
    CHECK(r32(buf, opt + 8) == 0x400);

    // The 4th IMAGE_SECTION_HEADER is in the slack zone (offset 0x200).
    const size_t new_hdr = kSectTbl + 3 * 40;
    REQUIRE(new_hdr + 40 <= 0x400);          // sanity: still inside slack
    CHECK(r32(buf, new_hdr +  8) == a.virtual_size);
    CHECK(r32(buf, new_hdr + 12) == a.virtual_addr);
    CHECK(r32(buf, new_hdr + 16) == a.raw_size);
    CHECK(r32(buf, new_hdr + 20) == a.raw_offset);
    CHECK(r32(buf, new_hdr + 36) == a.characteristics);
    // Name field: ".morph" + zero pad
    CHECK(buf[new_hdr + 0] == '.');
    CHECK(buf[new_hdr + 1] == 'm');
    CHECK(buf[new_hdr + 5] == 'h');
    CHECK(buf[new_hdr + 6] == 0);
    CHECK(buf[new_hdr + 7] == 0);

    // Payload bytes copied at the new raw offset.
    REQUIRE(buf.size() > a.raw_offset + payload.size());
    for (size_t i = 0; i < payload.size(); ++i) {
        CHECK(buf[a.raw_offset + i] == 0x42);
    }
    // The padding bytes after the payload up to raw_size are zero.
    for (size_t i = payload.size(); i < a.raw_size; ++i) {
        CHECK(buf[a.raw_offset + i] == 0);
    }
}

TEST_CASE("append_section: aligns FileAlignment when payload is unaligned",
          "[format][pe_section_appender][unit]") {
    auto img = make_image(/*first_raw=*/0x400);
    REQUIRE(img != nullptr);

    std::vector<uint8_t> payload(0x37, 0x99);  // odd size
    auto r = append_section(*img, ".x", payload, 0x40000040u);
    REQUIRE(r.ok());
    CHECK(r->raw_size == 0x200);          // 0x37 -> aligned to 0x200
    CHECK(r->virtual_size == 0x37);
}

TEST_CASE("append_section: marks executable section in SizeOfCode",
          "[format][pe_section_appender][unit]") {
    auto img = make_image(/*first_raw=*/0x400);
    REQUIRE(img != nullptr);

    std::vector<uint8_t> payload(0x40, 0x90);
    auto r = append_section(*img, ".text2", payload,
                            /*chars=*/0x60000020u);  // CODE|EXEC|READ
    REQUIRE(r.ok());

    const auto& buf = img->buffer();
    const size_t opt = kElfanew + 4 + 20;
    // SizeOfCode was 0x100 in fixture; raw_size is 0x200 -> 0x300.
    CHECK(r32(buf, opt + 4) == 0x300);
    // SizeOfInitializedData unchanged (no CntInitData bit set).
    CHECK(r32(buf, opt + 8) == 0x200);
}

TEST_CASE("set_entry_point_rva: patches AddressOfEntryPoint and entry_point_va",
          "[format][pe_image][unit]") {
    auto img = make_image(/*first_raw=*/0x400);
    REQUIRE(img != nullptr);
    // PeImage::from_bytes(..., false) doesn't compute image_base_ from
    // headers; the entry-point VA we get back is image_base_ + new_rva
    // where image_base_ is the raw shellcode base (0x1000). Validate
    // that the AddressOfEntryPoint field in the headers is correct
    // regardless.
    REQUIRE(img->set_entry_point_rva(0x4040).ok());
    const auto& buf = img->buffer();
    const size_t opt = kElfanew + 4 + 20;
    CHECK(r32(buf, opt + 16) == 0x4040);
}

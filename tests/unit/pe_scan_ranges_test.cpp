#include "morphkatz/scan/pe_scan_ranges.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <vector>

namespace {

using morphkatz::scan::compute_pe_scan_ranges;
using morphkatz::scan::ScanRange;
using morphkatz::scan::ScanScope;

// Synthetic PE32+ fixture used across the scoped-bisect tests.
//
// Layout (offsets in hex):
//   0x000 .. 0x040   DOS header (MZ + e_lfanew @ 0x3c -> 0x80)
//   0x040 .. 0x080   DOS stub (filler)
//   0x080 .. 0x084   "PE\0\0"
//   0x084 .. 0x098   COFF header (NumberOfSections=3, OptHdrSize=0xF0)
//   0x098 .. 0x188   Optional header PE32+ (magic 0x20b)
//                      NumberOfRvaAndSizes=16 @ 0x098+0x6c
//                      Data directories @ 0x098+0x70 .. 0x108+0x80=0x188
//                      Import dir (idx 1) -> rva=0x2040, size=0x50
//   0x188 .. 0x200   Section table (3 sections, 40 bytes each)
//   0x200 .. 0x300   .text    (CODE|EXECUTE|READ)
//   0x300 .. 0x500   gap  (filler 0xCC; not in any section)
//   0x500 .. 0x600   .rdata   (INIT_DATA|READ)
//   0x600 .. 0x800   gap
//   0x800 .. 0x900   .data    (INIT_DATA|READ|WRITE)
//
// Import directory rva 0x2040 maps to file offset 0x540 (inside .rdata)
// and runs for 0x50 bytes -> [0x540, 0x590). That punches a hole through
// .rdata's raw range when the `Sections` scope subtracts directories.
struct SyntheticPe {
    std::vector<uint8_t> bytes;
    static constexpr size_t kSize       = 0x900;
    static constexpr size_t kElfanew    = 0x80;
    static constexpr size_t kSectTable  = 0x188;
    static constexpr size_t kTextOff    = 0x200;
    static constexpr size_t kRdataOff   = 0x500;
    static constexpr size_t kDataOff    = 0x800;
    static constexpr uint32_t kImpRva   = 0x2040;
    static constexpr uint32_t kImpSize  = 0x50;
    static constexpr size_t kImpFileLo  = 0x540;   // 0x500 + 0x40
    static constexpr size_t kImpFileHi  = 0x590;   // 0x540 + 0x50
};

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

void write_section(std::vector<uint8_t>& b, size_t off, const char* name,
                   uint32_t virt_size, uint32_t virt_addr,
                   uint32_t raw_size,  uint32_t raw_ptr,
                   uint32_t chars) {
    std::memset(b.data() + off, 0, 40);
    std::memcpy(b.data() + off, name, std::min<size_t>(8, std::strlen(name)));
    w32(b, off +  8, virt_size);
    w32(b, off + 12, virt_addr);
    w32(b, off + 16, raw_size);
    w32(b, off + 20, raw_ptr);
    w32(b, off + 36, chars);
}

SyntheticPe make_pe() {
    SyntheticPe pe;
    pe.bytes.assign(SyntheticPe::kSize, 0xCC);

    // DOS header
    pe.bytes[0] = 'M';
    pe.bytes[1] = 'Z';
    w32(pe.bytes, 0x3c, static_cast<uint32_t>(SyntheticPe::kElfanew));

    // PE\0\0
    pe.bytes[SyntheticPe::kElfanew + 0] = 'P';
    pe.bytes[SyntheticPe::kElfanew + 1] = 'E';
    pe.bytes[SyntheticPe::kElfanew + 2] = 0;
    pe.bytes[SyntheticPe::kElfanew + 3] = 0;

    // COFF
    const size_t coff = SyntheticPe::kElfanew + 4;
    w16(pe.bytes, coff +  0, 0x8664);   // Machine: AMD64
    w16(pe.bytes, coff +  2, 3);        // NumberOfSections
    w32(pe.bytes, coff +  4, 0);        // TimeDateStamp
    w32(pe.bytes, coff +  8, 0);        // PointerToSymbolTable
    w32(pe.bytes, coff + 12, 0);        // NumberOfSymbols
    w16(pe.bytes, coff + 16, 0xF0);     // SizeOfOptionalHeader
    w16(pe.bytes, coff + 18, 0x22);     // Characteristics: EXEC | LARGE_ADDR

    // Optional header
    const size_t opt = coff + 20;
    w16(pe.bytes, opt + 0, 0x20b);      // Magic: PE32+
    w32(pe.bytes, opt + 0x6c, 16);      // NumberOfRvaAndSizes
    // Import directory (idx 1) -> rva, size
    const size_t dir = opt + 0x70;
    w32(pe.bytes, dir + 1 * 8 + 0, SyntheticPe::kImpRva);
    w32(pe.bytes, dir + 1 * 8 + 4, SyntheticPe::kImpSize);
    // All other directories left zero -> ignored by compute_pe_scan_ranges.

    // Section table
    constexpr uint32_t kCode  = 0x60000020u; // CODE | EXECUTE | READ
    constexpr uint32_t kRdata = 0x40000040u; // INIT_DATA | READ
    constexpr uint32_t kData  = 0xC0000040u; // INIT_DATA | READ | WRITE

    write_section(pe.bytes, SyntheticPe::kSectTable + 0  * 40, ".text",
                  0x100, 0x1000, 0x100,
                  static_cast<uint32_t>(SyntheticPe::kTextOff), kCode);
    write_section(pe.bytes, SyntheticPe::kSectTable + 1  * 40, ".rdata",
                  0x100, 0x2000, 0x100,
                  static_cast<uint32_t>(SyntheticPe::kRdataOff), kRdata);
    write_section(pe.bytes, SyntheticPe::kSectTable + 2  * 40, ".data",
                  0x100, 0x3000, 0x100,
                  static_cast<uint32_t>(SyntheticPe::kDataOff), kData);

    return pe;
}

bool contains(const std::vector<ScanRange>& v, size_t off, size_t len) {
    for (const auto& r : v) {
        if (r.file_offset == off && r.length == len) return true;
    }
    return false;
}

size_t total_bytes(const std::vector<ScanRange>& v) {
    size_t n = 0;
    for (const auto& r : v) n += r.length;
    return n;
}

}  // namespace

TEST_CASE("compute_pe_scan_ranges: Sections subtracts data directories",
          "[scan][pe_scan_ranges][unit]") {
    auto pe = make_pe();
    auto r  = compute_pe_scan_ranges(pe.bytes, ScanScope::Sections);
    REQUIRE(r.ok());
    const auto& v = *r;

    // .text: untouched (no directory there)
    CHECK(contains(v, SyntheticPe::kTextOff, 0x100));

    // .rdata is sliced by the import directory hole.
    CHECK(contains(v, SyntheticPe::kRdataOff,
                   SyntheticPe::kImpFileLo - SyntheticPe::kRdataOff));
    CHECK(contains(v, SyntheticPe::kImpFileHi,
                   (SyntheticPe::kRdataOff + 0x100) - SyntheticPe::kImpFileHi));

    // .data: untouched
    CHECK(contains(v, SyntheticPe::kDataOff, 0x100));

    // Total bytes = 3 sections (0x300) minus the imported dir (0x50).
    CHECK(total_bytes(v) == 0x300 - SyntheticPe::kImpSize);
    CHECK(v.size() == 4);
}

TEST_CASE("compute_pe_scan_ranges: SectionsAll keeps directories",
          "[scan][pe_scan_ranges][unit]") {
    auto pe = make_pe();
    auto r  = compute_pe_scan_ranges(pe.bytes, ScanScope::SectionsAll);
    REQUIRE(r.ok());
    const auto& v = *r;
    REQUIRE(v.size() == 3);
    CHECK(contains(v, SyntheticPe::kTextOff,  0x100));
    CHECK(contains(v, SyntheticPe::kRdataOff, 0x100));
    CHECK(contains(v, SyntheticPe::kDataOff,  0x100));
    CHECK(total_bytes(v) == 0x300);
}

TEST_CASE("compute_pe_scan_ranges: CodeOnly returns just .text",
          "[scan][pe_scan_ranges][unit]") {
    auto pe = make_pe();
    auto r  = compute_pe_scan_ranges(pe.bytes, ScanScope::CodeOnly);
    REQUIRE(r.ok());
    REQUIRE(r->size() == 1);
    CHECK((*r)[0].file_offset == SyntheticPe::kTextOff);
    CHECK((*r)[0].length      == 0x100);
}

TEST_CASE("compute_pe_scan_ranges: DataOnly returns .rdata + .data",
          "[scan][pe_scan_ranges][unit]") {
    auto pe = make_pe();
    auto r  = compute_pe_scan_ranges(pe.bytes, ScanScope::DataOnly);
    REQUIRE(r.ok());
    const auto& v = *r;
    // .rdata sliced + .data whole = 3 ranges
    REQUIRE(v.size() == 3);
    CHECK(contains(v, SyntheticPe::kRdataOff,
                   SyntheticPe::kImpFileLo - SyntheticPe::kRdataOff));
    CHECK(contains(v, SyntheticPe::kImpFileHi,
                   (SyntheticPe::kRdataOff + 0x100) - SyntheticPe::kImpFileHi));
    CHECK(contains(v, SyntheticPe::kDataOff, 0x100));
}

TEST_CASE("compute_pe_scan_ranges: Raw returns empty list",
          "[scan][pe_scan_ranges][unit]") {
    auto pe = make_pe();
    auto r  = compute_pe_scan_ranges(pe.bytes, ScanScope::Raw);
    REQUIRE(r.ok());
    CHECK(r->empty());
}

TEST_CASE("compute_pe_scan_ranges: non-PE input returns empty list",
          "[scan][pe_scan_ranges][unit]") {
    std::vector<uint8_t> raw(1024, 0xAA);
    auto r = compute_pe_scan_ranges(raw, ScanScope::Sections);
    REQUIRE(r.ok());
    CHECK(r->empty());

    std::vector<uint8_t> tiny{1, 2, 3};
    auto r2 = compute_pe_scan_ranges(tiny, ScanScope::Sections);
    REQUIRE(r2.ok());
    CHECK(r2->empty());
}

TEST_CASE("compute_pe_scan_ranges: zero-length sections are filtered out",
          "[scan][pe_scan_ranges][unit]") {
    auto pe = make_pe();
    // Zero out .data's raw_size (kSectTable + 2*40 + 16 == raw_size field).
    w32(pe.bytes, SyntheticPe::kSectTable + 2 * 40 + 16, 0);

    auto r = compute_pe_scan_ranges(pe.bytes, ScanScope::SectionsAll);
    REQUIRE(r.ok());
    const auto& v = *r;
    REQUIRE(v.size() == 2);
    CHECK(contains(v, SyntheticPe::kTextOff,  0x100));
    CHECK(contains(v, SyntheticPe::kRdataOff, 0x100));
    for (const auto& rr : v) CHECK(rr.length > 0);
}

TEST_CASE("compute_pe_scan_ranges: adjacent sections coalesce in SectionsAll",
          "[scan][pe_scan_ranges][unit]") {
    auto pe = make_pe();
    // Repoint .rdata to be exactly contiguous with .text in the file
    // (raw_ptr 0x300 instead of 0x500). The Sections scope walker will
    // produce two consecutive ranges that should collapse into one.
    constexpr size_t kRdataField = SyntheticPe::kSectTable + 1 * 40;
    constexpr uint32_t kNewRptr  = static_cast<uint32_t>(SyntheticPe::kTextOff) +
                                   0x100;
    w32(pe.bytes, kRdataField + 20, kNewRptr);

    // Move the import directory out of .rdata for this test (otherwise
    // the subtract would split things again). RVA 0 + size 0 = ignored.
    const size_t opt = SyntheticPe::kElfanew + 4 + 20;
    w32(pe.bytes, opt + 0x70 + 1 * 8 + 0, 0);
    w32(pe.bytes, opt + 0x70 + 1 * 8 + 4, 0);

    auto r = compute_pe_scan_ranges(pe.bytes, ScanScope::SectionsAll);
    REQUIRE(r.ok());
    const auto& v = *r;
    // .text and .rdata coalesce into one [0x200, 0x400); .data still
    // separated.
    REQUIRE(v.size() == 2);
    CHECK(contains(v, SyntheticPe::kTextOff, 0x200));
    CHECK(contains(v, SyntheticPe::kDataOff, 0x100));
}

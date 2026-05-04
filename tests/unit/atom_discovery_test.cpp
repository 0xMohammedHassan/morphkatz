#include "morphkatz/datapass/atom_discovery.hpp"

#include "morphkatz/format/pe_image.hpp"
#include "morphkatz/scan/bisect.hpp"
#include "morphkatz/yara/yara_target.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <vector>

namespace {

using morphkatz::datapass::Atom;
using morphkatz::datapass::AtomDiscoveryConfig;
using morphkatz::datapass::discover_atoms_raw;
using morphkatz::datapass::SkipReason;

// Synthetic PE32+ fixture, very close to the one in
// `pe_scan_ranges_test.cpp` but with a 4th `.data` section (W+R+
// initialized data) so we can place atoms in both .rdata and .data.
//
// Layout (offsets in hex):
//   0x000 .. 0x040   DOS header (e_lfanew @ 0x3c -> 0x80)
//   0x080 .. 0x084   "PE\0\0"
//   0x084 .. 0x098   COFF (NumberOfSections=3, OptHdrSize=0xF0)
//   0x098 .. 0x188   Optional header (PE32+, magic 0x20b)
//   0x188 .. 0x200   Section table (3 entries)
//   0x200 .. 0x300   .text   (CODE|EXECUTE|READ)
//   0x500 .. 0x600   .rdata  (INIT_DATA|READ)
//   0x800 .. 0x900   .data   (INIT_DATA|READ|WRITE)
struct SyntheticPe {
    std::vector<uint8_t> bytes;
    static constexpr size_t kSize     = 0x900;
    static constexpr size_t kElfanew  = 0x80;
    static constexpr size_t kSectTbl  = 0x188;
    static constexpr size_t kTextOff  = 0x200;
    static constexpr size_t kRdataOff = 0x500;
    static constexpr size_t kDataOff  = 0x800;
    static constexpr uint32_t kRdataVa = 0x2000;
    static constexpr uint32_t kDataVa  = 0x3000;
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
                   uint32_t vsz, uint32_t va,
                   uint32_t rsz, uint32_t rptr, uint32_t chars) {
    std::memset(b.data() + off, 0, 40);
    std::memcpy(b.data() + off, name, std::min<size_t>(8, std::strlen(name)));
    w32(b, off +  8, vsz);
    w32(b, off + 12, va);
    w32(b, off + 16, rsz);
    w32(b, off + 20, rptr);
    w32(b, off + 36, chars);
}

SyntheticPe make_pe() {
    SyntheticPe pe;
    pe.bytes.assign(SyntheticPe::kSize, 0xCC);

    pe.bytes[0] = 'M';
    pe.bytes[1] = 'Z';
    w32(pe.bytes, 0x3c, static_cast<uint32_t>(SyntheticPe::kElfanew));

    pe.bytes[SyntheticPe::kElfanew + 0] = 'P';
    pe.bytes[SyntheticPe::kElfanew + 1] = 'E';
    pe.bytes[SyntheticPe::kElfanew + 2] = 0;
    pe.bytes[SyntheticPe::kElfanew + 3] = 0;

    const size_t coff = SyntheticPe::kElfanew + 4;
    w16(pe.bytes, coff +  0, 0x8664);
    w16(pe.bytes, coff +  2, 3);
    w32(pe.bytes, coff +  4, 0);
    w32(pe.bytes, coff +  8, 0);
    w32(pe.bytes, coff + 12, 0);
    w16(pe.bytes, coff + 16, 0xF0);
    w16(pe.bytes, coff + 18, 0x22);

    const size_t opt = coff + 20;
    w16(pe.bytes, opt + 0, 0x20b);
    // ImageBase + SectionAlignment + FileAlignment so LIEF can parse.
    w32(pe.bytes, opt + 24, 0x00400000); // ImageBase low
    w32(pe.bytes, opt + 28, 0x00000000); // ImageBase high
    w32(pe.bytes, opt + 32, 0x00001000); // SectionAlignment
    w32(pe.bytes, opt + 36, 0x00000200); // FileAlignment
    w32(pe.bytes, opt + 0x6c, 16);       // NumberOfRvaAndSizes
    // No directories populated - keeps the test focused on atoms.

    constexpr uint32_t kCode  = 0x60000020u;
    constexpr uint32_t kRdata = 0x40000040u;
    constexpr uint32_t kData  = 0xC0000040u;

    write_section(pe.bytes, SyntheticPe::kSectTbl + 0 * 40, ".text",
                  0x100, 0x1000, 0x100,
                  static_cast<uint32_t>(SyntheticPe::kTextOff), kCode);
    write_section(pe.bytes, SyntheticPe::kSectTbl + 1 * 40, ".rdata",
                  0x100, SyntheticPe::kRdataVa, 0x100,
                  static_cast<uint32_t>(SyntheticPe::kRdataOff), kRdata);
    write_section(pe.bytes, SyntheticPe::kSectTbl + 2 * 40, ".data",
                  0x100, SyntheticPe::kDataVa, 0x100,
                  static_cast<uint32_t>(SyntheticPe::kDataOff), kData);
    return pe;
}

// Test helper that returns the raw byte buffer; we route the test
// through `discover_atoms_raw` so we don't need a LIEF-parseable PE.
std::vector<uint8_t> synth_bytes() { return make_pe().bytes; }

// Lightweight stand-in for a BisectAnchor whose `fragments` covers a
// concrete file-offset window inside `.rdata`.
morphkatz::scan::BisectAnchor make_anchor(uint64_t off, uint32_t len,
                                          const char* section_kind = "data") {
    morphkatz::scan::BisectAnchor a;
    a.status       = morphkatz::scan::BisectResult::Status::Found;
    a.offset       = static_cast<size_t>(off);
    a.length       = len;
    a.section      = ".rdata";
    a.section_kind = section_kind;
    a.bytes.assign(len, 0xAA);
    morphkatz::scan::ScanRange fr;
    fr.file_offset = static_cast<size_t>(off);
    fr.length      = len;
    a.fragments.push_back(fr);
    return a;
}

}  // namespace

TEST_CASE("discover_atoms: bisect anchor in .rdata becomes an atom",
          "[datapass][unit]") {
    auto bytes = synth_bytes();

    std::vector<morphkatz::scan::BisectAnchor> anchors;
    anchors.push_back(make_anchor(0x520, 16));

    AtomDiscoveryConfig cfg;
    auto r = discover_atoms_raw(bytes, /*lief=*/nullptr, /*yara=*/nullptr,
                                anchors, cfg);
    REQUIRE(r.ok());
    REQUIRE(r->atoms.size() == 1);
    CHECK(r->atoms[0].file_offset == 0x520);
    CHECK(r->atoms[0].length      == 16);
    CHECK(r->atoms[0].section     == ".rdata");
    CHECK(r->atoms[0].source      == "bisect");
    CHECK(r->bisect_candidates_total == 1);
}

TEST_CASE("discover_atoms: bisect anchor in .text is rejected (not a data section)",
          "[datapass][unit]") {
    auto bytes = synth_bytes();

    std::vector<morphkatz::scan::BisectAnchor> anchors;
    morphkatz::scan::BisectAnchor a;
    a.status = morphkatz::scan::BisectResult::Status::Found;
    a.offset = 0x220;
    a.length = 16;
    a.section = ".text";
    a.section_kind = "code";
    a.bytes.assign(16, 0xCC);
    morphkatz::scan::ScanRange fr;
    fr.file_offset = 0x220; fr.length = 16;
    a.fragments.push_back(fr);
    anchors.push_back(std::move(a));

    AtomDiscoveryConfig cfg;
    auto r = discover_atoms_raw(bytes, nullptr, nullptr, anchors, cfg);
    REQUIRE(r.ok());
    CHECK(r->atoms.empty());
    REQUIRE(r->skipped.size() == 1);
    CHECK(r->skipped[0].reason == SkipReason::NotInDataSection);
}

TEST_CASE("discover_atoms: rejects atoms below min_length",
          "[datapass][unit]") {
    auto bytes = synth_bytes();

    std::vector<morphkatz::scan::BisectAnchor> anchors;
    anchors.push_back(make_anchor(0x520, 2));

    AtomDiscoveryConfig cfg;
    auto r = discover_atoms_raw(bytes, nullptr, nullptr, anchors, cfg);
    REQUIRE(r.ok());
    CHECK(r->atoms.empty());
    REQUIRE(r->skipped.size() == 1);
    CHECK(r->skipped[0].reason == SkipReason::TooSmall);
}

TEST_CASE("discover_atoms: dedup by substring",
          "[datapass][unit]") {
    auto bytes = synth_bytes();

    std::vector<morphkatz::scan::BisectAnchor> anchors;
    anchors.push_back(make_anchor(0x520, 32));   // wide
    anchors.push_back(make_anchor(0x528, 8));    // contained in the above

    AtomDiscoveryConfig cfg;
    auto r = discover_atoms_raw(bytes, nullptr, nullptr, anchors, cfg);
    REQUIRE(r.ok());
    REQUIRE(r->atoms.size() == 1);
    CHECK(r->atoms[0].file_offset == 0x520);
    CHECK(r->atoms[0].length      == 32);
    REQUIRE(r->skipped.size() == 1);
    CHECK(r->skipped[0].reason == SkipReason::DuplicateOfPrevious);
}

TEST_CASE("discover_atoms: respects include_data flag",
          "[datapass][unit]") {
    auto bytes = synth_bytes();

    std::vector<morphkatz::scan::BisectAnchor> anchors;
    morphkatz::scan::BisectAnchor a;
    a.status = morphkatz::scan::BisectResult::Status::Found;
    a.offset = 0x820;
    a.length = 16;
    a.section = ".data";
    a.section_kind = "data";
    a.bytes.assign(16, 0xBB);
    morphkatz::scan::ScanRange fr;
    fr.file_offset = 0x820; fr.length = 16;
    a.fragments.push_back(fr);
    anchors.push_back(std::move(a));

    AtomDiscoveryConfig cfg;
    cfg.include_data = false;
    auto r = discover_atoms_raw(bytes, nullptr, nullptr, anchors, cfg);
    REQUIRE(r.ok());
    CHECK(r->atoms.empty());
    REQUIRE(r->skipped.size() == 1);
    CHECK(r->skipped[0].reason == SkipReason::NotInDataSection);
}

TEST_CASE("discover_atoms: rejects non-PE input via the raw entry point",
          "[datapass][unit]") {
    // No section table parses out of a flat blob; raw entry should
    // surface a ParseFormat error rather than crashing.
    std::vector<uint8_t> raw(1024, 0xAA);
    std::vector<morphkatz::scan::BisectAnchor> anchors;
    AtomDiscoveryConfig cfg;
    auto rd = discover_atoms_raw(raw, nullptr, nullptr, anchors, cfg);
    REQUIRE(!rd.ok());
    CHECK(rd.error().kind == morphkatz::ErrorKind::ParseFormat);
}

TEST_CASE("discover_atoms: many candidates respect max_atoms cap",
          "[datapass][unit]") {
    auto bytes = synth_bytes();

    // Place 5 disjoint anchors inside .rdata; cap to 2.
    std::vector<morphkatz::scan::BisectAnchor> anchors;
    anchors.push_back(make_anchor(0x500, 8));
    anchors.push_back(make_anchor(0x510, 8));
    anchors.push_back(make_anchor(0x520, 8));
    anchors.push_back(make_anchor(0x530, 8));
    anchors.push_back(make_anchor(0x540, 8));

    AtomDiscoveryConfig cfg;
    cfg.max_atoms = 2;
    auto r = discover_atoms_raw(bytes, nullptr, nullptr, anchors, cfg);
    REQUIRE(r.ok());
    CHECK(r->atoms.size() == 2);
    // Three should land in skipped with budget-exhausted classification.
    CHECK(r->skipped.size() == 3);
}

#include "morphkatz/engine/rng.hpp"
#include "morphkatz/format/pe_image.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <cstring>
#include <vector>

namespace {

// Build a minimal DOS-like buffer with a plausible Rich header block. The
// block lives at offset 0x80 and encodes [DanS, pad, pad, pad, entry, entry,
// Rich, key] with a constant key. scrub_rich_header operates on the raw
// bytes so we don't need a LIEF-parseable PE here.
constexpr uint32_t kKey      = 0xCAFEBABEu;
constexpr uint32_t kEntry1   = 0xAAAAAAAAu;
constexpr uint32_t kEntry2   = 0xBBBBBBBBu;
constexpr size_t   kRichOff  = 0x98;          // position of literal "Rich"
constexpr size_t   kKeyOff   = 0x9C;
constexpr size_t   kDansOff  = 0x80;
constexpr size_t   kEntry1Off = 0x90;
constexpr size_t   kEntry2Off = 0x94;

std::vector<uint8_t> build_fake_rich_blob() {
    std::vector<uint8_t> b(0x200, 0u);
    b[0] = 'M'; b[1] = 'Z';
    const uint32_t dans_enc = 0x536E6144u ^ kKey;
    const uint32_t pad_enc  = 0x00000000u ^ kKey;
    const uint32_t entry1   = kEntry1   ^ kKey;
    const uint32_t entry2   = kEntry2   ^ kKey;
    const uint32_t rich     = 0x68636952u;
    const auto put = [&](size_t off, uint32_t v) {
        std::memcpy(b.data() + off, &v, 4);
    };
    put(kDansOff + 0,  dans_enc);
    put(kDansOff + 4,  pad_enc);
    put(kDansOff + 8,  pad_enc);
    put(kDansOff + 12, pad_enc);
    put(kEntry1Off,    entry1);
    put(kEntry2Off,    entry2);
    put(kRichOff,      rich);
    put(kKeyOff,       kKey);
    return b;
}

uint32_t load_u32(const std::vector<uint8_t>& b, size_t off) {
    uint32_t v = 0;
    std::memcpy(&v, b.data() + off, 4);
    return v;
}

}  // namespace

TEST_CASE("scrub_rich_header zeroes the DanS..Rich block in strip mode",
          "[format][rich]") {
    auto blob = build_fake_rich_blob();
    const auto before_len = blob.size();

    auto img_r = morphkatz::format::PeImage::from_bytes(std::move(blob),
                                                        /*is_pe=*/false);
    REQUIRE(img_r.ok());
    auto& img = **img_r;

    REQUIRE(img.scrub_rich_header("strip", nullptr).ok());

    // After strip, the DanS..Rich region should be zero bytes; the Rich
    // sentinel and its key are part of the range we scrub.
    auto bytes = img.bytes();
    REQUIRE(bytes.size() == before_len);
    const std::vector<uint8_t> copy(bytes.begin(), bytes.end());

    REQUIRE(load_u32(copy, kDansOff)   == 0u);
    REQUIRE(load_u32(copy, kEntry1Off) == 0u);
    REQUIRE(load_u32(copy, kEntry2Off) == 0u);
    REQUIRE(load_u32(copy, kRichOff)   == 0u);
    REQUIRE(load_u32(copy, kKeyOff)    == 0u);

    // MZ sentinel must survive.
    REQUIRE(copy[0] == 'M');
    REQUIRE(copy[1] == 'Z');
}

TEST_CASE("scrub_rich_header randomize mutates the entries and preserves the key",
          "[format][rich]") {
    auto blob = build_fake_rich_blob();
    const auto pristine_entry1 = kEntry1 ^ kKey;

    auto img_r = morphkatz::format::PeImage::from_bytes(std::move(blob),
                                                        /*is_pe=*/false);
    REQUIRE(img_r.ok());
    auto& img = **img_r;

    morphkatz::engine::Rng rng(0xDEADBEEFu);
    REQUIRE(img.scrub_rich_header("randomize", &rng).ok());

    auto bytes = img.bytes();
    const std::vector<uint8_t> out(bytes.begin(), bytes.end());

    // DanS sentinel and the Rich literal must remain intact so downstream
    // tooling recognises the block; only the body between them changes.
    REQUIRE(load_u32(out, kDansOff) == (0x536E6144u ^ kKey));
    REQUIRE(load_u32(out, kRichOff) == 0x68636952u);
    REQUIRE(load_u32(out, kKeyOff)  == kKey);

    // The entry words must have changed (probability of collision with a
    // quality PRNG seeded from a fixed seed is negligible).
    REQUIRE(load_u32(out, kEntry1Off) != pristine_entry1);
}

TEST_CASE("scrub_rich_header randomize without an RNG is an error",
          "[format][rich]") {
    auto blob = build_fake_rich_blob();
    auto img_r = morphkatz::format::PeImage::from_bytes(std::move(blob),
                                                        /*is_pe=*/false);
    REQUIRE(img_r.ok());
    REQUIRE_FALSE((*img_r)->scrub_rich_header("randomize", nullptr).ok());
}

TEST_CASE("scrub_rich_header preserve is a no-op", "[format][rich]") {
    auto blob = build_fake_rich_blob();
    const auto before = blob;
    auto img_r = morphkatz::format::PeImage::from_bytes(std::move(blob),
                                                        /*is_pe=*/false);
    REQUIRE(img_r.ok());
    REQUIRE((*img_r)->scrub_rich_header("preserve", nullptr).ok());
    auto bytes = (*img_r)->bytes();
    REQUIRE(std::equal(before.begin(), before.end(), bytes.begin()));
}

namespace {

// Synthesise a blob with just enough PE header fields populated for the
// pre-LIEF compatibility gate to read. We do NOT need LIEF to successfully
// parse these - the gate runs before LIEF::PE::Parser::parse.
struct PeHeaderParams {
    uint16_t machine   = 0x8664;  // IMAGE_FILE_MACHINE_AMD64
    uint16_t opt_magic = 0x020B;  // PE32+
    uint32_t clr_rva   = 0;
    uint32_t clr_size  = 0;
};

std::vector<uint8_t> build_pe_header_blob(const PeHeaderParams& p) {
    std::vector<uint8_t> b(0x400, 0u);
    b[0] = 'M'; b[1] = 'Z';

    const uint32_t e_lfanew = 0x80;
    std::memcpy(b.data() + 0x3C, &e_lfanew, sizeof(e_lfanew));

    b[e_lfanew + 0] = 'P';
    b[e_lfanew + 1] = 'E';
    b[e_lfanew + 2] = 0;
    b[e_lfanew + 3] = 0;

    std::memcpy(b.data() + e_lfanew + 4, &p.machine, sizeof(p.machine));

    const size_t opt_off = e_lfanew + 24;
    std::memcpy(b.data() + opt_off, &p.opt_magic, sizeof(p.opt_magic));

    const size_t data_dir_off =
        opt_off + (p.opt_magic == 0x020B ? 0x70 : 0x60);
    const size_t clr_entry_off = data_dir_off + 14 * 8;
    std::memcpy(b.data() + clr_entry_off,     &p.clr_rva,  sizeof(p.clr_rva));
    std::memcpy(b.data() + clr_entry_off + 4, &p.clr_size, sizeof(p.clr_size));
    return b;
}

}  // namespace

TEST_CASE("PeImage refuses 32-bit (I386) machine type", "[format][gate]") {
    PeHeaderParams p;
    p.machine   = 0x014C;  // IMAGE_FILE_MACHINE_I386
    p.opt_magic = 0x010B;  // PE32

    auto r = morphkatz::format::PeImage::from_bytes(
        build_pe_header_blob(p), /*is_pe=*/true);

    REQUIRE_FALSE(r.ok());
    REQUIRE(r.error().kind == morphkatz::ErrorKind::NotSupported);
    // Message must mention the unsupported machine and point at the
    // roadmap anchor so operators know where to track future support.
    REQUIRE(r.error().what.find("machine type") != std::string::npos);
    REQUIRE(r.error().what.find("AMD64") != std::string::npos);
    REQUIRE(r.error().what.find("roadmap.md#multi-arch") != std::string::npos);
}

TEST_CASE("PeImage refuses managed (.NET) PE", "[format][gate]") {
    PeHeaderParams p;
    p.machine   = 0x8664;   // AMD64
    p.opt_magic = 0x020B;   // PE32+
    p.clr_rva   = 0x2000;   // any non-zero RVA...
    p.clr_size  = 0x48;     // ...with a non-zero size flags .NET

    auto r = morphkatz::format::PeImage::from_bytes(
        build_pe_header_blob(p), /*is_pe=*/true);

    REQUIRE_FALSE(r.ok());
    REQUIRE(r.error().kind == morphkatz::ErrorKind::NotSupported);
    REQUIRE(r.error().what.find(".NET") != std::string::npos);
    REQUIRE(r.error().what.find("roadmap.md#dotnet") != std::string::npos);
}

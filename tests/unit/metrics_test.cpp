#include "morphkatz/analysis/metrics.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_floating_point.hpp>

#include <array>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

using Catch::Matchers::WithinAbs;

namespace {

// Rotate-left used by the Rich-header checksum. Mirrors the one in
// metrics.cpp so the expected-value arithmetic below stays readable.
uint32_t rotl32(uint32_t v, unsigned n) noexcept {
    n &= 31;
    return (v << n) | (v >> ((32 - n) & 31));
}

}  // namespace

TEST_CASE("shannon_entropy zero on empty input", "[analysis][metrics]") {
    std::vector<uint8_t> empty;
    REQUIRE(morphkatz::analysis::shannon_entropy(empty) == 0.0);
}

TEST_CASE("shannon_entropy zero on constant input", "[analysis][metrics]") {
    std::vector<uint8_t> flat(1024, 0x90);
    REQUIRE_THAT(morphkatz::analysis::shannon_entropy(flat),
                 WithinAbs(0.0, 1e-9));
}

TEST_CASE("shannon_entropy eight on uniform input", "[analysis][metrics]") {
    // Uniform distribution across 256 symbols -> exactly 8 bits/byte.
    std::vector<uint8_t> uniform(256 * 4);
    for (size_t i = 0; i < uniform.size(); ++i) uniform[i] = static_cast<uint8_t>(i & 0xFF);
    REQUIRE_THAT(morphkatz::analysis::shannon_entropy(uniform),
                 WithinAbs(8.0, 1e-9));
}

TEST_CASE("sha256_hex matches known NIST vectors", "[analysis][metrics]") {
    // "abc" -> ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
    std::string abc = "abc";
    std::vector<uint8_t> abc_bytes(abc.begin(), abc.end());
    REQUIRE(morphkatz::analysis::sha256_hex(abc_bytes)
            == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

    // Empty input -> e3b0c442...
    std::vector<uint8_t> empty;
    REQUIRE(morphkatz::analysis::sha256_hex(empty)
            == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

TEST_CASE("byte_diff_count counts identical as zero", "[analysis][metrics]") {
    std::vector<uint8_t> a(256);
    for (size_t i = 0; i < a.size(); ++i) a[i] = static_cast<uint8_t>(i);
    REQUIRE(morphkatz::analysis::byte_diff_count(a, a) == 0);
}

TEST_CASE("byte_diff_count mismatched length counts tail as diff",
          "[analysis][metrics]") {
    std::vector<uint8_t> a(100, 0xAA);
    std::vector<uint8_t> b(120, 0xAA);
    REQUIRE(morphkatz::analysis::byte_diff_count(a, b) == 20);
}

TEST_CASE("byte_diff_count counts exactly the changed positions",
          "[analysis][metrics]") {
    std::vector<uint8_t> a(16, 0x00);
    std::vector<uint8_t> b(16, 0x00);
    b[3] = 0x01; b[7] = 0x01; b[15] = 0x01;
    REQUIRE(morphkatz::analysis::byte_diff_count(a, b) == 3);
}

namespace {

// Build the smallest blob with a well-formed Rich header:
// - MZ at [0,2)
// - e_lfanew at [0x3C,0x40) = 0x100
// - DanS^key at [0x80,0x84)
// - three padding words of 0^key at [0x84, 0x90)
// - one entry: comp^key at [0x90,0x94), count^key at [0x94,0x98)
// - "Rich" at [0x98,0x9C)
// - key at [0x9C,0xA0)
std::vector<uint8_t> build_rich_blob(uint32_t key, uint32_t comp, uint32_t count) {
    std::vector<uint8_t> b(0x200, 0u);
    b[0] = 'M'; b[1] = 'Z';
    const uint32_t e_lfanew = 0x100;
    std::memcpy(b.data() + 0x3C, &e_lfanew, sizeof(e_lfanew));

    const uint32_t dans_enc = 0x536E6144u ^ key;
    const uint32_t pad_enc  = 0x00000000u ^ key;
    const uint32_t comp_enc = comp        ^ key;
    const uint32_t cnt_enc  = count       ^ key;
    const uint32_t rich_lit = 0x68636952u;  // "Rich"

    const auto put = [&](size_t off, uint32_t v) {
        std::memcpy(b.data() + off, &v, sizeof(v));
    };
    put(0x80, dans_enc);
    put(0x84, pad_enc);
    put(0x88, pad_enc);
    put(0x8C, pad_enc);
    put(0x90, comp_enc);
    put(0x94, cnt_enc);
    put(0x98, rich_lit);
    put(0x9C, key);
    return b;
}

}  // namespace

TEST_CASE("rich_hash returns 0 on non-PE input", "[analysis][metrics]") {
    std::vector<uint8_t> zeros(0x200, 0u);
    REQUIRE(morphkatz::analysis::rich_hash(zeros) == 0);
}

TEST_CASE("rich_hash returns 0 when Rich sentinel is absent",
          "[analysis][metrics]") {
    std::vector<uint8_t> mz(0x200, 0u);
    mz[0] = 'M'; mz[1] = 'Z';
    const uint32_t e_lfanew = 0x100;
    std::memcpy(mz.data() + 0x3C, &e_lfanew, sizeof(e_lfanew));
    REQUIRE(morphkatz::analysis::rich_hash(mz) == 0);
}

TEST_CASE("rich_hash matches the pefile-compatible formula",
          "[analysis][metrics]") {
    const uint32_t key   = 0xDEADBEEFu;
    const uint32_t comp  = 0x12345678u;
    const uint32_t count = 0x00000005u;
    const auto blob = build_rich_blob(key, comp, count);

    // Reference computation mirroring pefile's RichHeader.get_hash:
    //   checksum = dans_off;
    //   for i in [0, dans_off), skipping [0x3C..0x40):
    //       checksum += rol(blob[i], i & 31);
    //   for each entry (comp, count):
    //       checksum += rol(comp, count & 31);
    const size_t dans_off = 0x80;
    uint32_t expected = static_cast<uint32_t>(dans_off);
    for (size_t i = 0; i < dans_off; ++i) {
        if (i >= 0x3C && i < 0x40) continue;
        expected = expected + rotl32(blob[i], static_cast<unsigned>(i & 31));
    }
    expected = expected + rotl32(comp, count & 31);

    REQUIRE(morphkatz::analysis::rich_hash(blob) == expected);
}

TEST_CASE("rich_hash shifts when a DOS-stub byte changes",
          "[analysis][metrics]") {
    auto a = build_rich_blob(0xCAFEBABEu, 0x01020304u, 0x00000007u);
    auto b = a;
    b[0x20] = 0xFF;  // flip one byte in the DOS stub
    REQUIRE(morphkatz::analysis::rich_hash(a) != morphkatz::analysis::rich_hash(b));
}

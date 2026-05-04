#include "morphkatz/engine/patcher.hpp"
#include "morphkatz/engine/pad_policy.hpp"
#include "morphkatz/engine/rng.hpp"
#include "morphkatz/format/pe_image.hpp"
#include "morphkatz/report/diff_report.hpp"

#include <catch2/catch_test_macros.hpp>

#include <vector>

TEST_CASE("Patcher applies a raw-byte rule via Aho-Corasick scan", "[engine][patcher]") {
    std::vector<uint8_t> blob{
        0xAA, 0xBB, 0x33, 0xC0, 0xEB, 0x08, 0xCC, 0xDD  // contains 33 C0 EB 08
    };
    auto img = morphkatz::format::PeImage::from_bytes(std::move(blob), /*is_pe=*/false);
    REQUIRE(img.ok());

    morphkatz::engine::Patcher p;
    const std::vector<uint8_t> from{0x33, 0xC0, 0xEB, 0x08};
    const std::vector<uint8_t> to  {0x29, 0xC0, 0xEB, 0x08};
    p.queue_raw({from.data(), from.size()}, {to.data(), to.size()}, "x64.donut.zero_eax_variant_1");
    auto applied = p.apply(**img);
    REQUIRE(applied.size() == 1);
    REQUIRE(applied[0].rule_id == "x64.donut.zero_eax_variant_1");
    REQUIRE(applied[0].old_bytes == from);
    REQUIRE(applied[0].new_bytes == to);

    // Verify the image body was actually rewritten in-place.
    auto out = (*img)->bytes();
    REQUIRE(out[2] == 0x29);
    REQUIRE(out[3] == 0xC0);
}

TEST_CASE("Patcher leaves non-matching bytes untouched", "[engine][patcher]") {
    std::vector<uint8_t> blob{0x01, 0x02, 0x03, 0x04};
    auto img = morphkatz::format::PeImage::from_bytes(std::move(blob), false);
    REQUIRE(img.ok());
    morphkatz::engine::Patcher p;
    const std::vector<uint8_t> from{0xDE, 0xAD};
    const std::vector<uint8_t> to  {0xBE, 0xEF};
    p.queue_raw({from.data(), from.size()}, {to.data(), to.size()}, "noop");
    auto applied = p.apply(**img);
    REQUIRE(applied.empty());
    const auto& bytes = (*img)->bytes();
    REQUIRE(bytes[0] == 0x01);
    REQUIRE(bytes[1] == 0x02);
}

TEST_CASE("Patcher::rollback restores original bytes", "[engine][patcher][rollback]") {
    std::vector<uint8_t> blob{0x33, 0xC0, 0xEB, 0x08, 0xCC, 0xCC};
    auto img = morphkatz::format::PeImage::from_bytes(std::move(blob), false);
    REQUIRE(img.ok());

    morphkatz::engine::Patcher p;
    const std::vector<uint8_t> from{0x33, 0xC0, 0xEB, 0x08};
    const std::vector<uint8_t> to  {0x29, 0xC0, 0xEB, 0x08};
    p.queue_raw({from.data(), from.size()}, {to.data(), to.size()}, "demo");
    auto applied = p.apply(**img);
    REQUIRE(applied.size() == 1);
    REQUIRE((*img)->bytes()[0] == 0x29);

    const auto restored = morphkatz::engine::Patcher::rollback(
        **img, std::span<const morphkatz::engine::AppliedPatch>(applied.data(), applied.size()));
    REQUIRE(restored == 1);
    REQUIRE((*img)->bytes()[0] == 0x33);
    REQUIRE((*img)->bytes()[1] == 0xC0);
}

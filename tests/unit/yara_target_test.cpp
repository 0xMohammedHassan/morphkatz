#include "morphkatz/yara/yara_target.hpp"

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <filesystem>
#include <vector>

using morphkatz::yara_target::PriorityMap;

namespace {

// Tiny helper: build a PriorityMap without touching libyara so the test
// can run on every CI configuration, even without MORPHKATZ_WITH_YARA.
// Uses the atoms-only constructor so the test translation unit never has
// to see `PriorityMap::Compiled` (which is PIMPL-hidden in yara_target.cpp).
std::unique_ptr<PriorityMap> make_map(std::vector<PriorityMap::Atom> atoms) {
    return std::make_unique<PriorityMap>(std::move(atoms), /*rule_count=*/1);
}

}  // namespace

TEST_CASE("PriorityMap::boost_for returns 0 when atom set is empty", "[yara][priority]") {
    auto pm = make_map({});
    const std::array<uint8_t, 3> oldb{0x90, 0x90, 0x90};
    const std::array<uint8_t, 3> newb{0x66, 0x90, 0x90};
    REQUIRE(pm->boost_for(0, {oldb.data(), oldb.size()},
                             {newb.data(), newb.size()}) == 0.0);
}

TEST_CASE("PriorityMap::boost_for fires when atom is present in old but missing in new", "[yara][priority]") {
    std::vector<PriorityMap::Atom> atoms;
    PriorityMap::Atom a;
    a.bytes    = {0xDE, 0xAD, 0xBE, 0xEF};
    a.weight   = 2.5;
    a.rule_name = "demo";
    atoms.push_back(a);
    auto pm = make_map(std::move(atoms));

    const std::array<uint8_t, 6> oldb{0x11, 0xDE, 0xAD, 0xBE, 0xEF, 0x22};
    const std::array<uint8_t, 6> newb{0x11, 0x00, 0x00, 0x00, 0x00, 0x22};
    REQUIRE(pm->boost_for(0x1000,
                          {oldb.data(), oldb.size()},
                          {newb.data(), newb.size()}) == 2.5);
}

TEST_CASE("PriorityMap::boost_for returns 0 when atom is preserved across the rewrite", "[yara][priority]") {
    std::vector<PriorityMap::Atom> atoms;
    PriorityMap::Atom a;
    a.bytes  = {0xCA, 0xFE};
    a.weight = 1.0;
    atoms.push_back(a);
    auto pm = make_map(std::move(atoms));

    // old and new both contain 0xCA 0xFE — atom was not broken.
    const std::array<uint8_t, 4> oldb{0xCA, 0xFE, 0x00, 0x00};
    const std::array<uint8_t, 4> newb{0x00, 0xCA, 0xFE, 0x00};
    REQUIRE(pm->boost_for(0, {oldb.data(), oldb.size()},
                             {newb.data(), newb.size()}) == 0.0);
}

#if MORPHKATZ_WITH_YARA
TEST_CASE("yara_target::load picks up the bundled Mimikatz hint pack",
          "[yara][priority][rules]") {
    const std::filesystem::path pack =
        std::filesystem::path(MORPHKATZ_RULES_DIR) / "yara" / "x64" /
        "mimikatz.yar";
    REQUIRE(std::filesystem::is_regular_file(pack));

    auto pm = morphkatz::yara_target::load(pack);
    REQUIRE(pm.ok());
    // 2 rules: MorphKatz_Mimikatz_Strings, MorphKatz_Mimikatz_CodeAtoms.
    CHECK((*pm)->rule_count() == 2);
    // 6 hex code atoms + plenty of string atoms; tighten the lower
    // bound but stay generous to avoid bitrot when we add atoms.
    CHECK((*pm)->atom_count() >= 6);

    // Sanity: scanning a buffer that contains one of the code atoms
    // returns a positive boost on that atom.
    const std::array<uint8_t, 8> oldb{0x90, 0x48, 0x85, 0xC9, 0x90, 0, 0, 0};
    const std::array<uint8_t, 8> newb{0x90, 0x48, 0x09, 0xC9, 0x90, 0, 0, 0};
    CHECK((*pm)->boost_for(0,
        {oldb.data(), oldb.size()},
        {newb.data(), newb.size()}) > 0.0);
}
#endif

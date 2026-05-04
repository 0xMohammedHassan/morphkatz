#include "morphkatz/rules/rule_loader.hpp"

#include <catch2/catch_test_macros.hpp>

#include <filesystem>

TEST_CASE("rule loader parses bundled equivalence packs", "[rules][loader]") {
    std::filesystem::path rules_dir = MORPHKATZ_RULES_DIR;
    rules_dir /= "x64";
    rules_dir /= "equivalence";
    REQUIRE(std::filesystem::is_directory(rules_dir));

    auto zero = morphkatz::rules::load_file(rules_dir / "zero_register.yaml");
    REQUIRE(zero.ok());
    REQUIRE(zero->size() >= 2);
    for (const auto& r : *zero) {
        REQUIRE(!r.id.empty());
        REQUIRE(r.match_mnemonic != 0);
        REQUIRE(r.compiled_predicate);
    }
}

TEST_CASE("rule loader parses targeted raw-byte packs", "[rules][loader][targeted]") {
    std::filesystem::path rules_dir = MORPHKATZ_RULES_DIR;
    rules_dir /= "x64";
    rules_dir /= "targeted";
    auto donut = morphkatz::rules::load_file(rules_dir / "donut.yaml");
    REQUIRE(donut.ok());
    REQUIRE(!donut->empty());
    for (const auto& r : *donut) {
        REQUIRE(r.raw_from.has_value());
        REQUIRE(r.raw_to.has_value());
        REQUIRE(r.raw_from->size() == r.raw_to->size());
        REQUIRE(!r.raw_from->empty());
    }
}

TEST_CASE("load_all aggregates every yaml under the rules directory", "[rules][loader]") {
    morphkatz::rules::LoaderOptions opts;
    opts.default_rules_dir = MORPHKATZ_RULES_DIR;
    auto pack = morphkatz::rules::load_all(opts);
    REQUIRE(pack.ok());
    REQUIRE((*pack)->rule_count() >= 5);
    REQUIRE((*pack)->pack_count() >= 3);
}

TEST_CASE("add_sub_neg pack carries imm-negate transform and flag-diff mask",
          "[rules][loader][add-sub-neg]") {
    std::filesystem::path rules_dir = MORPHKATZ_RULES_DIR;
    auto rs = morphkatz::rules::load_file(
        rules_dir / "x64" / "equivalence" / "add_sub_neg.yaml");
    REQUIRE(rs.ok());
    REQUIRE(rs->size() == 2);
    for (const auto& r : *rs) {
        REQUIRE(r.flags_effect ==
                morphkatz::rules::FlagsEquivalence::EquivalentIfDead);
        // Author-declared value differences: CF | OF | AF.
        const uint32_t want = morphkatz::ir::F_CF |
                              morphkatz::ir::F_OF |
                              morphkatz::ir::F_AF;
        CHECK(r.flags_value_diff_mask == want);

        // Operand 1 must carry the negate transform; without it the
        // rewrite is the v0.1 regression that broke mimikatz at runtime.
        REQUIRE(r.rewrite_operands.size() == 2);
        CHECK(r.rewrite_operands[1].source ==
              morphkatz::rules::Rule::RewriteOperand::Source::CopyFrom);
        CHECK(r.rewrite_operands[1].imm_transform ==
              morphkatz::rules::Rule::RewriteOperand::ImmTransform::Negate);
    }
}

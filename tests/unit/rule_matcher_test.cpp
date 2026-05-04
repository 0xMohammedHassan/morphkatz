#include "morphkatz/disasm/decoder.hpp"
#include "morphkatz/engine/encoder.hpp"
#include "morphkatz/rules/rule_loader.hpp"
#include "morphkatz/rules/rule_matcher.hpp"

#include <Zydis/Zydis.h>
#include <catch2/catch_test_macros.hpp>

#include <array>
#include <cstring>

namespace {

morphkatz::ir::Instruction decode(std::initializer_list<uint8_t> bytes) {
    morphkatz::ir::Instruction ins{};
    const std::vector<uint8_t> buf(bytes);
    auto r = morphkatz::disasm::decode_one(
        std::span<const uint8_t>(buf.data(), buf.size()),
        0x1000, 0, ins);
    REQUIRE(r.ok());
    return ins;
}

}

TEST_CASE("xor rax, rax matches the zero_register pack", "[rules][matcher]") {
    morphkatz::rules::LoaderOptions opts;
    opts.default_rules_dir = MORPHKATZ_RULES_DIR;
    auto pack = morphkatz::rules::load_all(opts);
    REQUIRE(pack.ok());

    morphkatz::rules::RuleMatcher matcher(**pack, nullptr);

    // 48 31 C0  ->  xor rax, rax
    auto ins = decode({0x48, 0x31, 0xC0});
    const auto cs = matcher.evaluate_one(ins);
    REQUIRE(!cs.empty());

    bool saw_xor_to_sub = false;
    for (const auto& c : cs) {
        if (c.rule && c.rule->id == "x64.zero.xor_to_sub") saw_xor_to_sub = true;
    }
    REQUIRE(saw_xor_to_sub);
}

TEST_CASE("register_blacklist rejects RSP cases", "[rules][matcher]") {
    morphkatz::rules::LoaderOptions opts;
    opts.default_rules_dir = MORPHKATZ_RULES_DIR;
    auto pack = morphkatz::rules::load_all(opts);
    REQUIRE(pack.ok());
    morphkatz::rules::RuleMatcher matcher(**pack, nullptr);

    // 48 31 E4  ->  xor rsp, rsp    (must be refused; would trash the stack)
    auto ins = decode({0x48, 0x31, 0xE4});
    const auto cs = matcher.evaluate_one(ins);
    for (const auto& c : cs) {
        REQUIRE(c.rule->id != "x64.zero.xor_to_sub");
        REQUIRE(c.rule->id != "x64.zero.sub_to_xor");
    }
}

TEST_CASE("cmp reg, 0 lights up the test_self rule", "[rules][matcher]") {
    morphkatz::rules::LoaderOptions opts;
    opts.default_rules_dir = MORPHKATZ_RULES_DIR;
    auto pack = morphkatz::rules::load_all(opts);
    REQUIRE(pack.ok());
    morphkatz::rules::RuleMatcher matcher(**pack, nullptr);

    // 48 83 F8 00  ->  cmp rax, 0
    auto ins = decode({0x48, 0x83, 0xF8, 0x00});
    const auto cs = matcher.evaluate_one(ins);
    bool hit = false;
    for (const auto& c : cs) if (c.rule->id == "x64.cmp.reg0_to_test_self") hit = true;
    REQUIRE(hit);
}

TEST_CASE("sub rsp, 0x50 rewrites to add rsp, -0x50 (imm negated)",
          "[rules][matcher][encoder][regression]") {
    // v0.1 regression: this rule used to copy the immediate verbatim,
    // turning every `sub rsp, X` function-prologue into `add rsp, X`
    // and crashing mimikatz with STATUS_ACCESS_VIOLATION before main().
    morphkatz::rules::LoaderOptions opts;
    opts.default_rules_dir = MORPHKATZ_RULES_DIR;
    auto pack = morphkatz::rules::load_all(opts);
    REQUIRE(pack.ok());

    // Find x64.sub_neg_to_add_pos in the loaded pack.
    const morphkatz::rules::Rule* rule = nullptr;
    for (const auto& r : (*pack)->rules()) {
        if (r.id == "x64.sub_neg_to_add_pos") { rule = &r; break; }
    }
    REQUIRE(rule != nullptr);

    // 48 83 EC 50  ->  sub rsp, 0x50
    auto ins = decode({0x48, 0x83, 0xEC, 0x50});
    auto enc = morphkatz::engine::encode_rewrite(ins, *rule);
    REQUIRE(enc.ok());

    // Expected: add rsp, -0x50  ==  48 83 C4 B0  (sign-extended imm8).
    REQUIRE(enc->size() == 4);
    CHECK((*enc)[0] == 0x48);
    CHECK((*enc)[1] == 0x83);
    CHECK((*enc)[2] == 0xC4);   // ModR/M for `add rsp, imm`
    CHECK((*enc)[3] == 0xB0);   // -0x50 sign-extended
}

TEST_CASE("add rcx, 5 rewrites to sub rcx, -5 (imm negated)",
          "[rules][matcher][encoder][regression]") {
    morphkatz::rules::LoaderOptions opts;
    opts.default_rules_dir = MORPHKATZ_RULES_DIR;
    auto pack = morphkatz::rules::load_all(opts);
    REQUIRE(pack.ok());

    const morphkatz::rules::Rule* rule = nullptr;
    for (const auto& r : (*pack)->rules()) {
        if (r.id == "x64.add_neg_to_sub_pos") { rule = &r; break; }
    }
    REQUIRE(rule != nullptr);

    // 48 83 C1 05  ->  add rcx, 5
    auto ins = decode({0x48, 0x83, 0xC1, 0x05});
    auto enc = morphkatz::engine::encode_rewrite(ins, *rule);
    REQUIRE(enc.ok());

    // Expected: sub rcx, -5  ==  48 83 E9 FB
    REQUIRE(enc->size() == 4);
    CHECK((*enc)[0] == 0x48);
    CHECK((*enc)[1] == 0x83);
    CHECK((*enc)[2] == 0xE9);   // ModR/M for `sub rcx, imm`
    CHECK((*enc)[3] == 0xFB);   // -5 sign-extended
}

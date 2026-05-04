#include "morphkatz/cli/args.hpp"
#include "morphkatz/engine/orchestrator.hpp"
#include "morphkatz/engine/patcher.hpp"
#include "morphkatz/engine/pad_policy.hpp"
#include "morphkatz/engine/rng.hpp"
#include "morphkatz/format/pe_image.hpp"
#include "morphkatz/rules/rule_loader.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iterator>

// Integration tests that verify every targeted byte-pair YAML rule under
// rules/x64/targeted/ (donut, cobaltstrike, adaptix, mimikatz) loads
// correctly and applies the expected from->to substitution to synthetic
// shellcode through the rule matcher.

namespace {

struct PairCase {
    const char* rule_pack;            // rule file relative to default_rules_dir
    const char* rule_id;
    std::initializer_list<uint8_t> from;
    std::initializer_list<uint8_t> to;
};

const PairCase kCases[] = {
    {"x64/targeted/donut.yaml",        "x64.donut.zero_eax_variant_1",
        {0x33, 0xC0, 0xEB, 0x08},
        {0x29, 0xC0, 0xEB, 0x08}},
    {"x64/targeted/donut.yaml",        "x64.donut.zero_edx_after_je",
        {0x74, 0x14, 0x33, 0xD2},
        {0x74, 0x14, 0x29, 0xD2}},
    {"x64/targeted/cobaltstrike.yaml", "x64.cs.mov_rdx_rax_pushpop",
        {0x48, 0x89, 0xC2, 0x83, 0xE2, 0x03},
        {0x50, 0x5A, 0x90, 0x83, 0xE2, 0x03}},
    {"x64/targeted/adaptix.yaml",      "x64.adaptix.movzx_to_movsx",
        {0x0F, 0xB6, 0x55, 0x12, 0x88, 0x10},
        {0x0F, 0xBE, 0x55, 0x12, 0x88, 0x10}},
    {"x64/targeted/mimikatz.yaml",     "x64.mk.movdqu_to_vmovdqu",
        {0xF3, 0x0F, 0x6F, 0x6C, 0x24, 0x30},
        {0xC5, 0xFA, 0x6F, 0x6C, 0x24, 0x30}},
    {"x64/targeted/mimikatz.yaml",     "x64.mk.mov_rcx_rdx_alt",
        {0x48, 0x8B, 0xCA, 0xF3},
        {0x48, 0x89, 0xD1, 0xF3}},
};

}  // namespace

TEST_CASE("Every ported raw-byte rule loads and appears in the matcher table",
          "[integration][parity]") {
    morphkatz::rules::LoaderOptions opts;
    opts.default_rules_dir = MORPHKATZ_RULES_DIR;
    auto pack = morphkatz::rules::load_all(opts);
    REQUIRE(pack.ok());

    for (const auto& tc : kCases) {
        bool found = false;
        for (const auto& r : (*pack)->rules()) {
            if (r.id == tc.rule_id) { found = true; break; }
        }
        INFO("missing rule id: " << tc.rule_id);
        REQUIRE(found);
    }
}

TEST_CASE("Each ported rule correctly patches a synthetic blob containing its signature",
          "[integration][parity]") {
    for (const auto& tc : kCases) {
        std::vector<uint8_t> blob{0xAA, 0xAA};
        blob.insert(blob.end(), tc.from.begin(), tc.from.end());
        blob.insert(blob.end(), {0xBB, 0xBB});

        auto img = morphkatz::format::PeImage::from_bytes(std::move(blob), false);
        REQUIRE(img.ok());

        morphkatz::engine::Patcher p;
        std::vector<uint8_t> from(tc.from);
        std::vector<uint8_t> to  (tc.to);
        p.queue_raw({from.data(), from.size()}, {to.data(), to.size()}, tc.rule_id);
        auto applied = p.apply(**img);
        REQUIRE(applied.size() == 1);
        REQUIRE(applied[0].rule_id == tc.rule_id);
    }
}

namespace {

std::filesystem::path make_tmp_dir() {
    auto dir = std::filesystem::temp_directory_path() / "morphkatz-parity-test";
    std::filesystem::create_directories(dir);
    return dir;
}

std::vector<uint8_t> read_all(const std::filesystem::path& p) {
    std::ifstream f(p, std::ios::binary);
    return {std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>()};
}

}  // namespace

TEST_CASE(
    "Orchestrator pipeline applies raw-byte rules via queue_raw (not the matcher)",
    "[integration][parity][e2e]") {
    // The orchestrator must route rules with raw_from/raw_to through
    // Patcher::queue_raw. If it reverts to per-instruction dispatch the
    // raw pattern gets spliced into arbitrary instruction slots, which
    // was the v1.0 code-review CRITICAL #1. We drive the full pipeline
    // and assert the expected pattern — and only the expected pattern —
    // is rewritten.
    const auto dir = make_tmp_dir();
    int i = 0;
    for (const auto& tc : kCases) {
        ++i;
        std::vector<uint8_t> blob;
        // 0x20 byte prefix + pattern + 0x20 byte suffix.
        blob.resize(0x20, 0xAA);
        blob.insert(blob.end(), tc.from.begin(), tc.from.end());
        blob.resize(blob.size() + 0x20, 0xBB);
        blob.push_back(0xC3);  // RET, gives us a decodable terminator

        const auto in  = dir / ("parity-in-"  + std::to_string(i) + ".bin");
        const auto out = dir / ("parity-out-" + std::to_string(i) + ".bin");
        {
            std::ofstream f(in, std::ios::binary | std::ios::trunc);
            f.write(reinterpret_cast<const char*>(blob.data()),
                    static_cast<std::streamsize>(blob.size()));
        }

        morphkatz::cli::Options opts;
        opts.input             = in;
        opts.output            = out;
        opts.profile           = morphkatz::cli::Profile::Aggressive;
        opts.verify            = morphkatz::cli::Verify::None;
        opts.seed              = 0xC0FFEE;
        opts.fix_checksum      = false;
        opts.strip_signature   = false;
        opts.rich_header_mode  = "preserve";
        opts.backup            = false;
        opts.default_rules_dir = MORPHKATZ_RULES_DIR;

        morphkatz::engine::Orchestrator orch(opts);
        INFO("rule: " << tc.rule_id);
        REQUIRE(orch.run().ok());

        const auto patched = read_all(out);
        REQUIRE(patched.size() == blob.size());

        // Expected `to` bytes at the pattern offset.
        const std::vector<uint8_t> to(tc.to);
        REQUIRE(std::equal(to.begin(), to.end(), patched.begin() + 0x20));

        // Prefix and suffix guard regions must be untouched (barring the
        // terminator 0xC3). This is what fails when the matcher misroutes
        // raw rules through per-instruction dispatch.
        for (size_t k = 0; k < 0x20; ++k) REQUIRE(patched[k] == 0xAA);
        for (size_t k = 0x20 + to.size(); k < blob.size() - 1; ++k) {
            REQUIRE(patched[k] == 0xBB);
        }
    }
}

#include "morphkatz/cli/args.hpp"
#include "morphkatz/engine/batch.hpp"

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <unordered_set>
#include <vector>

namespace {

std::filesystem::path write_temp(std::string_view tag,
                                 const std::vector<uint8_t>& bytes) {
    auto dir = std::filesystem::temp_directory_path() / "morphkatz-batch-test";
    std::filesystem::create_directories(dir);
    auto path = dir / (std::string{tag} + ".bin");
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    f.write(reinterpret_cast<const char*>(bytes.data()),
            static_cast<std::streamsize>(bytes.size()));
    return path;
}

std::string read_text(const std::filesystem::path& p) {
    std::ifstream f(p);
    std::stringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

}  // namespace

TEST_CASE("run_variants emits N outputs with derived seeds and summary JSON",
          "[engine][batch]") {
    // Same fixture as orchestrator_test: three xor-zero idioms + ret.
    // Three separate rewritable atoms give the polymorph engine enough
    // surface to produce visibly distinct outputs across variants.
    const std::vector<uint8_t> blob{
        0x48, 0x31, 0xC0,
        0x48, 0x31, 0xC9,
        0x48, 0x31, 0xD2,
        0x90,
        0xC3,
    };
    const auto input_path  = write_temp("batch-in", blob);
    const auto base_output = input_path.parent_path() / "batch-out.bin";
    const auto base_report = input_path.parent_path() / "batch-report.json";

    // Purge any outputs from previous runs so we detect regressions.
    for (int i = 0; i < 4; ++i) {
        std::error_code ec;
        std::filesystem::remove(
            input_path.parent_path() /
            ("batch-out_v" + std::to_string(i) + ".bin"), ec);
        std::filesystem::remove(
            input_path.parent_path() /
            ("batch-report_v" + std::to_string(i) + ".json"), ec);
    }
    std::error_code ec;
    std::filesystem::remove(
        std::filesystem::path{base_report.string() + ".summary.json"}, ec);

    morphkatz::cli::Options opts;
    opts.input             = input_path;
    opts.output            = base_output;
    opts.report_path       = base_report;
    opts.profile           = morphkatz::cli::Profile::Normal;
    opts.verify            = morphkatz::cli::Verify::Redisasm;
    opts.seed              = 0xABCDEFULL;
    opts.variants          = 3;
    opts.backup            = false;
    opts.default_rules_dir = MORPHKATZ_RULES_DIR;

    auto r = morphkatz::engine::run_variants(opts);
    REQUIRE(r.ok());

    // Per-variant outputs must exist and be distinct from the input.
    std::unordered_set<std::string> output_hashes;
    for (int i = 0; i < 3; ++i) {
        const auto out_path = input_path.parent_path() /
                              ("batch-out_v" + std::to_string(i) + ".bin");
        REQUIRE(std::filesystem::exists(out_path));

        std::ifstream f(out_path, std::ios::binary);
        std::vector<uint8_t> body{
            std::istreambuf_iterator<char>(f),
            std::istreambuf_iterator<char>()
        };
        REQUIRE(body.size() == blob.size());
        REQUIRE(body != blob);              // something actually mutated
        REQUIRE(body.back() == 0xC3);        // ret preserved
        output_hashes.insert(std::string(body.begin(), body.end()));
    }

    // The whole point of --variants is diversity: at least 2/3 variants
    // must differ. (Not all 3 — for a 3-atom fixture the polymorph
    // engine occasionally collides on the same rewrite choices.)
    REQUIRE(output_hashes.size() >= 2);

    // Summary JSON is mandatory when --report is set.
    const auto summary_path = std::filesystem::path{
        base_report.string() + ".summary.json"};
    REQUIRE(std::filesystem::exists(summary_path));

    const auto body = read_text(summary_path);
    const auto j = nlohmann::json::parse(body);

    REQUIRE(j.at("tool")  == "morphkatz");
    REQUIRE(j.at("count") == 3);
    REQUIRE(j.at("variants").is_array());
    REQUIRE(j.at("variants").size() == 3);

    // Each variant entry carries its derived seed and metrics.
    std::unordered_set<uint64_t> seeds;
    std::unordered_set<std::string> sha_after;
    for (const auto& v : j.at("variants")) {
        REQUIRE(v.contains("seed"));
        REQUIRE(v.contains("output"));
        REQUIRE(v.contains("metrics"));
        seeds.insert(v.at("seed").get<uint64_t>());
        sha_after.insert(v.at("metrics").at("sha256_after").get<std::string>());
    }
    REQUIRE(seeds.size() == 3);                  // distinct derived seeds
    REQUIRE(j.at("distinct_sha256_count").get<size_t>() == sha_after.size());

    REQUIRE(j.contains("summary_stats"));
    REQUIRE(j.at("summary_stats").contains("min_bytes_changed_pct"));
    REQUIRE(j.at("summary_stats").contains("mean_bytes_changed_pct"));
}

TEST_CASE("run_variants with N=1 still round-trips cleanly",
          "[engine][batch]") {
    const std::vector<uint8_t> blob{0x48, 0x31, 0xC0, 0xC3};
    const auto input_path  = write_temp("batch-one", blob);
    const auto base_output = input_path.parent_path() / "batch-one-out.bin";

    morphkatz::cli::Options opts;
    opts.input             = input_path;
    opts.output            = base_output;
    opts.profile           = morphkatz::cli::Profile::Normal;
    opts.verify            = morphkatz::cli::Verify::None;
    opts.seed              = 1;
    opts.variants          = 1;
    opts.backup            = false;
    opts.default_rules_dir = MORPHKATZ_RULES_DIR;

    auto r = morphkatz::engine::run_variants(opts);
    REQUIRE(r.ok());

    const auto expected = input_path.parent_path() / "batch-one-out_v0.bin";
    REQUIRE(std::filesystem::exists(expected));
}

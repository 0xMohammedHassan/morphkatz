#include "morphkatz/analysis/binary_diff.hpp"
#include "morphkatz/cli/args.hpp"
#include "morphkatz/engine/compare.hpp"

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

namespace {

std::filesystem::path temp_write(std::string_view tag,
                                 const std::vector<uint8_t>& bytes) {
    auto dir = std::filesystem::temp_directory_path() / "morphkatz-diff-test";
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

TEST_CASE("profile_bytes populates size, sha, entropy, histogram",
          "[analysis][binary_diff]") {
    const std::vector<uint8_t> buf{0x00, 0xFF, 0xFF, 0x41};
    const auto p = morphkatz::analysis::profile_bytes(buf);
    REQUIRE(p.size == 4);
    REQUIRE(p.histogram[0x00] == 1);
    REQUIRE(p.histogram[0xFF] == 2);
    REQUIRE(p.histogram[0x41] == 1);
    REQUIRE(p.entropy > 0.0);      // non-uniform, > 0
    REQUIRE(p.entropy <= 8.0);
    REQUIRE(p.sha256.size() == 64);
}

TEST_CASE("diff_bytes on identical inputs", "[analysis][binary_diff]") {
    const std::vector<uint8_t> a(256, 0x42);
    const auto d = morphkatz::analysis::diff_bytes(a, a);

    REQUIRE(d.aligned_bytes_diff == 0);
    REQUIRE(d.aligned_bytes_same == 256);
    REQUIRE(d.aligned_hamming_pct == 0.0);
    REQUIRE(d.histogram_cosine == 1.0);
    REQUIRE(d.alphabet_jaccard == 1.0);
}

TEST_CASE("diff_bytes on totally disjoint alphabets", "[analysis][binary_diff]") {
    const std::vector<uint8_t> a(32, 0x11);
    const std::vector<uint8_t> b(32, 0x22);
    const auto d = morphkatz::analysis::diff_bytes(a, b);

    REQUIRE(d.aligned_bytes_diff == 32);
    REQUIRE(d.aligned_hamming_pct == 100.0);
    REQUIRE(d.histogram_cosine == 0.0);   // no shared bin mass
    REQUIRE(d.alphabet_jaccard == 0.0);   // no shared byte values
}

TEST_CASE("diff_bytes handles length mismatch via aligned prefix",
          "[analysis][binary_diff]") {
    const std::vector<uint8_t> a{0x01, 0x02, 0x03, 0x04};
    const std::vector<uint8_t> b{0x01, 0xFF, 0x03};   // b shorter, middle byte diff
    const auto d = morphkatz::analysis::diff_bytes(a, b);

    REQUIRE(d.aligned_bytes_diff == 1);
    REQUIRE(d.aligned_bytes_same == 2);
    REQUIRE(d.a.size == 4);
    REQUIRE(d.b.size == 3);
}

TEST_CASE("run_compare writes a valid JSON report with pairs",
          "[engine][compare]") {
    // Three files: two identical, one very different. Expected outcome:
    // distinct_sha256_count == 2, pair (0,1) is a zero-hamming entry.
    std::vector<uint8_t> a(64, 0xAB);
    std::vector<uint8_t> b = a;                // identical to a
    std::vector<uint8_t> c(64, 0);
    for (size_t i = 0; i < c.size(); ++i) c[i] = static_cast<uint8_t>(i);

    const auto pa = temp_write("cmp-a", a);
    const auto pb = temp_write("cmp-b", b);
    const auto pc = temp_write("cmp-c", c);
    const auto report = pa.parent_path() / "cmp-report.json";
    std::error_code ec;
    std::filesystem::remove(report, ec);

    morphkatz::cli::CompareOptions copts;
    copts.inputs      = {pa, pb, pc};
    copts.report_path = report;

    const auto r = morphkatz::engine::run_compare(copts);
    REQUIRE(r.ok());
    REQUIRE(std::filesystem::exists(report));

    const auto j = nlohmann::json::parse(read_text(report));
    REQUIRE(j.at("mode") == "compare");
    REQUIRE(j.at("distinct_sha256_count").get<size_t>() == 2);
    REQUIRE(j.at("inputs").size() == 3);
    REQUIRE(j.at("pairs").size() == 3);   // C(3,2) = 3 pairs

    // The (a,b) pair must be zero-hamming; (a,c) and (b,c) both 100%.
    size_t zero_pairs = 0;
    size_t full_pairs = 0;
    for (const auto& pair : j.at("pairs")) {
        const double ham = pair.at("aligned_hamming_pct").get<double>();
        if (ham == 0.0)      ++zero_pairs;
        else if (ham == 100.0) ++full_pairs;
    }
    REQUIRE(zero_pairs == 1);
    REQUIRE(full_pairs == 2);
}

TEST_CASE("run_compare writes HTML when extension is .html",
          "[engine][compare]") {
    const std::vector<uint8_t> a{1, 2, 3, 4};
    const std::vector<uint8_t> b{1, 5, 3, 4};
    const auto pa = temp_write("html-a", a);
    const auto pb = temp_write("html-b", b);
    const auto report = pa.parent_path() / "cmp-report.html";
    std::error_code ec;
    std::filesystem::remove(report, ec);

    morphkatz::cli::CompareOptions copts;
    copts.inputs      = {pa, pb};
    copts.report_path = report;

    const auto r = morphkatz::engine::run_compare(copts);
    REQUIRE(r.ok());
    REQUIRE(std::filesystem::exists(report));

    const auto body = read_text(report);
    REQUIRE(body.find("<!doctype html>") != std::string::npos);
    REQUIRE(body.find("MorphKatz compare") != std::string::npos);
    REQUIRE(body.find("hamming") != std::string::npos);
}

TEST_CASE("run_compare rejects a single input", "[engine][compare]") {
    const auto pa = temp_write("lonely", {0x90});
    morphkatz::cli::CompareOptions copts;
    copts.inputs = {pa};
    const auto r = morphkatz::engine::run_compare(copts);
    REQUIRE_FALSE(r.ok());
    REQUIRE(r.error().kind == morphkatz::ErrorKind::Invalid);
}

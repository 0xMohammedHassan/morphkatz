#include "morphkatz/cli/args.hpp"
#include "morphkatz/engine/orchestrator.hpp"
#include "morphkatz/format/pe_image.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <vector>

namespace {

std::filesystem::path write_temp(std::string_view tag,
                                 std::span<const uint8_t> bytes) {
    auto dir  = std::filesystem::temp_directory_path() / "morphkatz-orch-test";
    std::filesystem::create_directories(dir);
    auto path = dir / (std::string{tag} + ".bin");
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    f.write(reinterpret_cast<const char*>(bytes.data()),
            static_cast<std::streamsize>(bytes.size()));
    return path;
}

std::vector<uint8_t> read_file(const std::filesystem::path& p) {
    std::ifstream f(p, std::ios::binary);
    return {std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>()};
}

}  // namespace

TEST_CASE("Orchestrator runs end-to-end over raw shellcode",
          "[orchestrator][e2e]") {
    // Synthetic shellcode fixture:
    //   xor rax, rax   ;  48 31 C0  — matched by x64.zero.xor_to_sub
    //   xor rcx, rcx   ;  48 31 C9
    //   xor rdx, rdx   ;  48 31 D2
    //   nop            ;  90
    //   ret            ;  C3
    const std::vector<uint8_t> blob{
        0x48, 0x31, 0xC0,
        0x48, 0x31, 0xC9,
        0x48, 0x31, 0xD2,
        0x90,
        0xC3,
    };
    const auto input_path = write_temp("in", blob);
    const auto output_path = input_path.parent_path() / "out.bin";
    const auto report_path = input_path.parent_path() / "report.json";

    morphkatz::cli::Options opts;
    opts.input             = input_path;
    opts.output            = output_path;
    opts.profile           = morphkatz::cli::Profile::Normal;
    opts.verify            = morphkatz::cli::Verify::Redisasm;
    opts.seed              = 0x1234;
    opts.fix_checksum      = false;
    opts.strip_signature   = false;
    opts.rich_header_mode  = "preserve";
    opts.backup            = false;
    opts.default_rules_dir = MORPHKATZ_RULES_DIR;
    opts.report_path       = report_path;

    morphkatz::engine::Orchestrator orch(opts);
    auto r = orch.run();
    REQUIRE(r.ok());

    REQUIRE(std::filesystem::exists(output_path));
    const auto before = blob;
    const auto after  = read_file(output_path);
    REQUIRE(after.size() == before.size());
    // At least one byte changed — rules should rewrite the xor zeroing idioms.
    REQUIRE(before != after);
    // Last byte (ret) must be preserved so control flow is intact.
    REQUIRE(after.back() == 0xC3);

    // JSON report must exist and mention at least one rewrite.
    REQUIRE(std::filesystem::exists(report_path));
    const auto report_bytes = read_file(report_path);
    REQUIRE(!report_bytes.empty());
    const std::string report(report_bytes.begin(), report_bytes.end());
    REQUIRE(report.find("\"patches\"") != std::string::npos);
    REQUIRE(report.find("x64.") != std::string::npos);
}

TEST_CASE("Orchestrator respects --dry-run and writes no output",
          "[orchestrator][dry-run]") {
    const std::vector<uint8_t> blob{0x48, 0x31, 0xC0, 0xC3};
    const auto input_path  = write_temp("dry-in", blob);
    const auto output_path = input_path.parent_path() / "dry-out.bin";
    std::filesystem::remove(output_path);

    morphkatz::cli::Options opts;
    opts.input             = input_path;
    opts.output            = output_path;
    opts.profile           = morphkatz::cli::Profile::Normal;
    opts.verify            = morphkatz::cli::Verify::None;
    opts.seed              = 7;
    opts.dry_run           = true;
    opts.backup            = false;
    opts.default_rules_dir = MORPHKATZ_RULES_DIR;

    morphkatz::engine::Orchestrator orch(opts);
    auto r = orch.run();
    REQUIRE(r.ok());
    REQUIRE_FALSE(std::filesystem::exists(output_path));
}

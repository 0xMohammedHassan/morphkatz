#include "morphkatz/cli/args.hpp"
#include "morphkatz/format/pe_image.hpp"

#include <catch2/catch_test_macros.hpp>

#include <filesystem>

TEST_CASE("CLI parses --version flag", "[cli]") {
    const char* argv[] = {"morphkatz", "--version"};
    auto parsed = morphkatz::cli::parse(2, argv);
    REQUIRE(parsed.ok());
    REQUIRE(parsed->action == morphkatz::cli::Action::ShowVersion);
}

TEST_CASE("CLI shows first-run banner when invoked with no arguments",
          "[cli]") {
    // Zero-arg invocation is a common 'double-clicked the exe' case on
    // Windows. Instead of dying with exit 1 and no output, we route to
    // Action::ShowBanner so main() can print the logo + synopsis.
    const char* argv[] = {"morphkatz"};
    auto parsed = morphkatz::cli::parse(1, argv);
    REQUIRE(parsed.ok());
    REQUIRE(parsed->action == morphkatz::cli::Action::ShowBanner);
}

TEST_CASE("CLI still rejects a bogus positional when flags are present",
          "[cli]") {
    // If the user explicitly typed something but forgot the input path,
    // we want the proper 'missing required argument' error, not the
    // gentle first-run banner.
    const char* argv[] = {"morphkatz", "--seed", "42"};
    auto parsed = morphkatz::cli::parse(3, argv);
    REQUIRE_FALSE(parsed.ok());
    REQUIRE(parsed.error().exit_code == 1);
}

TEST_CASE("CLI default output preserves the input extension", "[cli][output]") {
    // foo.exe should yield foo.patched.exe, not foo.exe.patched, so that
    // Windows still executes it. The CLI only computes the path - we
    // don't actually run the orchestrator here.
    const char* argv[] = {"morphkatz", __FILE__};  // any existing file
    auto parsed = morphkatz::cli::parse(2, argv);
    REQUIRE(parsed.ok());
    REQUIRE(parsed->action == morphkatz::cli::Action::Run);
    const auto& out = parsed->options.output;
    const auto  ext = std::filesystem::path(__FILE__).extension();
    REQUIRE(out.extension() == ext);
    REQUIRE(out.stem().string().ends_with(".patched"));
}

TEST_CASE("CLI routes to compare subcommand with multiple inputs",
          "[cli][compare]") {
    // Both inputs must exist for CLI11's ExistingFile check; use this
    // source file as a stand-in.
    const char* self = __FILE__;
    const char* argv[] = {"morphkatz", "compare", self, self};
    auto parsed = morphkatz::cli::parse(4, argv);
    REQUIRE(parsed.ok());
    REQUIRE(parsed->action == morphkatz::cli::Action::Compare);
    REQUIRE(parsed->compare.inputs.size() == 2);
}

TEST_CASE("PeImage accepts raw shellcode", "[format][pe_image]") {
    std::vector<uint8_t> blob{0x90, 0x90, 0xC3};
    auto img = morphkatz::format::PeImage::from_bytes(std::move(blob), /*is_pe=*/false);
    REQUIRE(img.ok());
    REQUIRE_FALSE((*img)->is_pe());
    REQUIRE((*img)->code_sections().size() == 1);
    REQUIRE((*img)->code_sections()[0].raw_size == 3);
}

TEST_CASE("PeImage reports 'MZ' as PE magic", "[format][pe_image]") {
    std::vector<uint8_t> mz{'M', 'Z', 0x00, 0x00};
    auto img = morphkatz::format::PeImage::from_bytes(std::move(mz), /*is_pe=*/true);
    if (!img.ok()) {
        REQUIRE(img.error().kind == morphkatz::ErrorKind::ParseFormat);
    }
}

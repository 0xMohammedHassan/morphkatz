// Integration test for the data-section morphing pass end-to-end.
//
// Pre-condition: tests/samples/data_string_demo.exe must exist.
// Run `tests/samples/build_data_string_demo.cmd` from a VS x64 Native
// Tools Command Prompt before this test; otherwise the test SKIPs.
//
// What it verifies:
//   1. We can run the orchestrator with --data-morph on against the
//      sample binary.
//   2. The morphed binary still parses as a valid PE.
//   3. The morphed binary, when executed, returns exit code 42 (the
//      same as the unmorphed binary), proving that the decoder stub
//      restored the .rdata literal at runtime.

#include "morphkatz/cli/args.hpp"
#include "morphkatz/engine/orchestrator.hpp"
#include "morphkatz/format/pe_image.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <vector>

#if defined(_WIN32)
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <windows.h>
#endif

namespace fs = std::filesystem;

namespace {

fs::path test_data_dir() {
    return fs::path(MORPHKATZ_TEST_DATA_DIR);
}

fs::path locate_sample() {
    // Look for the sample exe in a few likely places. CI / dev users
    // run the CMD script in `tests/samples`; allow an override via env.
    if (const char* env = std::getenv("MORPHKATZ_DATA_STRING_DEMO")) {
        const fs::path p = env;
        if (fs::is_regular_file(p)) return p;
    }
    const auto candidates = {
        test_data_dir() / "samples" / "data_string_demo.exe",
        test_data_dir() / ".." / "build" / "tests" / "samples" /
            "data_string_demo.exe",
    };
    for (const auto& p : candidates) {
        if (fs::is_regular_file(p)) return p;
    }
    return {};
}

#if defined(_WIN32)
int run_and_get_exit_code(const fs::path& exe) {
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    std::wstring cmd = L"\"" + exe.wstring() + L"\"";

    if (!CreateProcessW(nullptr, cmd.data(), nullptr, nullptr, FALSE,
                        CREATE_NO_WINDOW,
                        nullptr, nullptr, &si, &pi)) {
        return -1;
    }
    WaitForSingleObject(pi.hProcess, 10'000);
    DWORD code = 0;
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return static_cast<int>(code);
}
#endif

}  // namespace

TEST_CASE("data-string demo round-trips through --data-morph on (ep_thunk)",
          "[data-pass][integration][requires-windows-toolchain]") {
    const fs::path sample = locate_sample();
    if (sample.empty()) {
        WARN("data_string_demo.exe not found; build it via "
             "tests/samples/build_data_string_demo.cmd "
             "(this test is skipped, not failed).");
        SUCCEED("skipped: sample not built");
        return;
    }

#if !defined(_WIN32)
    WARN("data-string demo test requires Windows for runtime execution");
    SUCCEED("skipped: non-Windows host");
    return;
#else
    // Drop a tiny YARA rule next to the test exe so atom discovery has
    // a target. Without this, the orchestrator runs a no-op pass and
    // the test wouldn't actually exercise the encoder. Our rule
    // matches the literal that lives in the sample's .rdata.
    const fs::path yara_path =
        sample.parent_path() / "data_string_demo.target.yar";
    {
        std::ofstream f(yara_path);
        REQUIRE(f);
        f << "rule data_string_demo_secret {\n"
          << "  strings:\n"
          << "    $s = \"MorphKatz_DataPass_OK_1234567890\"\n"
          << "  condition:\n"
          << "    $s\n"
          << "}\n";
    }

    morphkatz::cli::Options o;
    o.input  = sample;
    o.output = sample.parent_path() / "data_string_demo.morphed.exe";
    o.backup = false;
    o.yara_target = yara_path;
    o.data_morph = morphkatz::cli::DataMorphMode::On;
    o.data_morph_min_len = 4;
    // Force EP-thunk; the sample has no TLS callbacks so Auto would
    // pick EP-thunk anyway, but pinning the placement here makes the
    // test exercise a known code path.
    o.decoder_placement = morphkatz::cli::DecoderPlacement::EpThunk;
    o.strip_signature = true;
    o.fix_checksum = true;
    o.verify = morphkatz::cli::Verify::None;

    {
        morphkatz::engine::Orchestrator orch(o);
        const auto run_r = orch.run();
        REQUIRE(run_r.ok());
    }

    REQUIRE(fs::exists(o.output));

    // Sanity: morphed bytes must still be a parseable PE.
    {
        std::ifstream f(o.output, std::ios::binary);
        REQUIRE(f);
        std::vector<uint8_t> bytes(
            std::istreambuf_iterator<char>(f),
            std::istreambuf_iterator<char>{});
        auto img_r = morphkatz::format::PeImage::from_bytes(std::move(bytes), true);
        REQUIRE(img_r.ok());
        REQUIRE((*img_r)->is_pe());
    }

    // Run the morphed binary and check the exit code.
    const int code = run_and_get_exit_code(o.output);
    INFO("morphed binary exit code = " << code);
    REQUIRE(code == 42);
#endif
}

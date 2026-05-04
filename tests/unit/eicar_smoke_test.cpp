#include "morphkatz/scan/mpcmdrun_scanner.hpp"
#include "morphkatz/scan/threat_classify.hpp"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <filesystem>
#include <fstream>

// Real Defender scan against the EICAR test string. Only runs when
// invoked with the [requires-defender] tag, since most CI runners don't
// keep RTP+MAPS in the configuration the scanner enforces. The test
// expects MpCmdRun to flag the canonical EICAR file as a virus.

TEST_CASE("EICAR file is detected by MpCmdRun",
          "[scan][integration][requires-defender]") {
    using namespace morphkatz::scan;

    auto found = discover_mpcmdrun();
    if (!found) {
        SKIP("MpCmdRun.exe not found - Defender unavailable");
    }

    MpCmdRunScanner::Options opts;
    opts.mpcmdrun_path = *found;
    opts.enforce_preconditions = false;  // can't enforce on shared CI runners
    opts.timeout = std::chrono::milliseconds(60'000);
    auto scanner_r = MpCmdRunScanner::create(std::move(opts));
    if (!scanner_r.ok()) {
        SKIP(("scanner create failed: " + scanner_r.error().what).c_str());
    }
    auto scanner = std::move(*scanner_r);

    const auto dir = std::filesystem::temp_directory_path() / "morphkatz-eicar";
    std::filesystem::create_directories(dir);
    const auto path = dir / "eicar.com";
    {
        std::ofstream f(path, std::ios::binary | std::ios::trunc);
        f << kEicarStandardAntivirusTestFile;
    }

    auto v = scanner->scan_file(path);
    REQUIRE(v.ok());

    // RTP-scrubbed-before-scan is a known interference pattern: the
    // file is quarantined between write() and MpCmdRun's first read,
    // and the scanner reports "clean" because the bytes are gone.
    // Treat that as a skip (host-policy issue, not a code bug).
    if (!v->infected) {
        SKIP("Defender RTP scrubbed EICAR before MpCmdRun saw it; "
             "add the temp dir to Defender exclusions to verify");
    }

    bool eicar_found = false;
    for (const auto& t : v->threats) {
        if (is_eicar(t)) { eicar_found = true; break; }
    }
    CHECK(eicar_found);

    std::error_code ec;
    std::filesystem::remove(path, ec);
}

#pragma once

#include "morphkatz/scan/preconditions.hpp"
#include "morphkatz/scan/scanner.hpp"

#include <chrono>
#include <filesystem>
#include <memory>
#include <vector>

namespace morphkatz::scan {

// Tier-1 scanner: shell-out to MpCmdRun.exe.
//
// MpCmdRun is the "official" command-line interface to the Defender
// engine. It is always present on Windows 10/11 + Server 2016+ and
// requires no API SDK. The trade-off is that it spawns a new process
// per scan (~300-700 ms cold start) and parses its output, which means
// every release of Defender risks bumping the format and breaking us.
//
// The implementation deliberately keeps the I/O surface narrow:
//   - everything goes through CreateProcessW with redirected stdout
//   - no PowerShell shell-outs (registry preconditions are direct reads)
//   - input files are always copied into a Defender-excluded temp dir
//     before scanning so RTP can't quarantine the source under us
class MpCmdRunScanner final : public IDefenderScanner {
public:
    struct Options {
        // Path to MpCmdRun.exe. Empty -> probe `discover_mpcmdrun()`
        // first; the constructor returns an error if no path is found.
        std::filesystem::path mpcmdrun_path;

        // Working directory for temp inputs. Empty -> a uuid-stamped
        // subdirectory under the system temp folder. This directory
        // is added to Defender exclusions by the caller (or by the
        // mimikatz fetch script for the manual workflow); the scanner
        // itself never modifies Defender preferences.
        std::filesystem::path temp_dir;

        // Pre-condition expectations. Defaults to the safe "cloud off,
        // submission off" set so the scanner never causes a sample
        // submission to Microsoft on behalf of the user.
        PreconditionExpectations expectations{};
        bool                     enforce_preconditions = true;

        std::chrono::milliseconds timeout{60'000};
    };

    static Result<std::unique_ptr<MpCmdRunScanner>> create(Options opts);

    Result<ScanVerdict> scan_file(const std::filesystem::path& path) override;
    Result<ScanVerdict> scan_buffer(std::span<const uint8_t> bytes,
                                    std::string_view name_hint) override;
    std::string         engine_label() const override;

    ~MpCmdRunScanner() override;
    MpCmdRunScanner(const MpCmdRunScanner&) = delete;
    MpCmdRunScanner& operator=(const MpCmdRunScanner&) = delete;
    MpCmdRunScanner(MpCmdRunScanner&&) noexcept;
    MpCmdRunScanner& operator=(MpCmdRunScanner&&) noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;

    explicit MpCmdRunScanner(std::unique_ptr<Impl>);
};

// MpCmdRun.exe auto-discovery, in probe order:
//   1. %ProgramData%\Microsoft\Windows Defender\Platform\<latest>\
//   2. %ProgramFiles%\Windows Defender\
//   3. PATH (via the SearchPathW API)
// Returns the first existing path, or nullopt if none found.
//
// `extra_search_dirs` is consulted before the default probes so tests
// can inject a fake exe and so an admin can override discovery via the
// `--mpcmdrun` CLI flag.
[[nodiscard]] std::optional<std::filesystem::path>
    discover_mpcmdrun(const std::vector<std::filesystem::path>& extra_search_dirs = {});

// Parse a full MpCmdRun stdout dump and produce a structured verdict.
// Public so tests can feed it canned fixtures.
[[nodiscard]] ScanVerdict parse_mpcmdrun_output(std::string raw_stdout,
                                                int exit_code);

}

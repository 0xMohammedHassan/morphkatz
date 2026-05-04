#pragma once

#include "morphkatz/common/error.hpp"

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace morphkatz::scan {

// One detected threat as reported by the underlying AV engine.
//
// `name` is the canonical Microsoft threat name (e.g.
// "Trojan:Win32/Mimikatz.A") which is what every Defender / EDR report
// keys on. `severity` is engine-assigned and only "Severe" is treated
// as a hard malicious verdict for downstream weighting; the rest of
// the severity ladder is preserved verbatim for forensic display.
//
// `is_ml` is set when the threat name carries the !ml suffix that
// Defender uses to mark machine-learning-derived detections. These
// cannot be bisected meaningfully (the model evaluates global features,
// not byte patterns) and the scanner refuses to recurse into them.
struct Threat {
    std::string name;
    std::string severity;
    bool        is_ml  = false;
    bool        is_pua = false;

    [[nodiscard]] bool operator==(const Threat& o) const noexcept {
        return name == o.name;
    }
};

// Result of a single scan invocation. `infected == false` on a clean
// scan; `threats` is empty in that case. `raw_stdout` is preserved so
// downstream tooling can debug parser regressions when MS changes the
// MpCmdRun output format (which it does, occasionally).
struct ScanVerdict {
    bool                       infected = false;
    std::vector<Threat>        threats;
    std::string                engine_version;       // mpengine version, may be empty
    std::string                vdm_version;          // signature DB version, may be empty
    std::chrono::milliseconds  elapsed{0};
    int                        raw_exit_code = 0;
    std::string                raw_stdout;
};

// Abstract scanner interface.
//
// Concrete implementations: `MpCmdRunScanner` (Tier-1, always-available
// shell-out), `AmsiScanner` (Tier-2, in-process - reserved for v0.2).
// `bisect_single` and `DefenderTarget` operate exclusively through this
// interface so the bisection algorithm and orchestrator integration are
// fully engine-agnostic.
class IDefenderScanner {
public:
    virtual ~IDefenderScanner() = default;

    // Scan an existing on-disk file. Implementations may copy the file
    // into a Defender-excluded temp directory if the source path lives
    // somewhere RTP would otherwise quarantine the bytes mid-scan.
    [[nodiscard]] virtual Result<ScanVerdict>
        scan_file(const std::filesystem::path& path) = 0;

    // Scan an in-memory buffer. The implementation is responsible for
    // materialising the buffer to disk (most engines only scan paths)
    // and cleaning up the temp file regardless of the scan outcome.
    // `name_hint` is used to construct the temp filename so threat
    // logs are attributable.
    [[nodiscard]] virtual Result<ScanVerdict>
        scan_buffer(std::span<const uint8_t> bytes,
                    std::string_view         name_hint) = 0;

    // Short, human-readable identity tag for the engine - included in
    // generated reports so a reader can tell which scanner produced
    // which row. Examples: "MpCmdRun-Tier1", "AMSI-Tier2".
    [[nodiscard]] virtual std::string engine_label() const = 0;
};

// Helper: parse a single MpCmdRun "Threat : ..." line and produce a
// `Threat` populated with name/severity/is_ml/is_pua. Returns nullopt
// for unrecognisable lines so callers can quietly skip them. Defined
// in src/scan/scanner.cpp; tested in tests/unit/mpcmdrun_parse_test.cpp.
[[nodiscard]] std::optional<Threat>
    parse_mpcmdrun_threat_line(std::string_view line);

// Helper: scrub control characters and trailing whitespace from a
// scanner stdout string before logging it. MpCmdRun writes CR/LF and
// occasional NUL bytes which trip up downstream UI.
[[nodiscard]] std::string sanitize_scanner_output(std::string_view raw);

}

#pragma once

#include "morphkatz/common/error.hpp"

#include <optional>
#include <string>
#include <vector>

namespace morphkatz::scan {

// Snapshot of the Defender preferences MorphKatz cares about when
// scanning. Each field is read straight out of the registry; absence
// is encoded as nullopt rather than a default so the validator can
// distinguish "user explicitly set this to N" from "we couldn't read
// the key".
//
// Sources (HKLM):
//   Spynet\SpynetReporting              - cloud-delivered protection
//   Spynet\SubmitSamplesConsent         - automatic sample submission
//   Real-Time Protection\DisableRealtimeMonitoring
struct DefenderState {
    std::optional<unsigned> spynet_reporting;          // 0 = disabled
    std::optional<unsigned> submit_samples_consent;    // 2 = never send
    std::optional<unsigned> disable_realtime_monitoring; // 1 = RTP off
    std::optional<unsigned> tamper_protection;         // advisory only

    // True if the registry hive responded at all. False means we are
    // either not on a Defender-capable host (Server core, container,
    // Defender uninstalled) or running without sufficient privileges.
    bool defender_present = false;
};

// What the caller insists on. Each `require_*_off` becomes a hard gate;
// when a gate fails the validator returns a multi-line error message
// that names the failing key AND the exact PowerShell incantation to
// fix it (so the user doesn't have to go googling).
struct PreconditionExpectations {
    bool require_cloud_off       = true;   // SpynetReporting must be 0
    bool require_submission_off  = true;   // SubmitSamplesConsent must be 2
    bool require_rtp_off         = false;  // DisableRealtimeMonitoring must be 1
    bool tolerate_unreadable     = false;  // accept missing keys as "off"
};

[[nodiscard]] DefenderState query_state();

// Validates the queried state against the expectations. On failure,
// returns an `ErrorKind::Aborted` with a remediation block in `what`.
// On success, returns `Result<void>::ok` with no diagnostic noise.
[[nodiscard]] Result<void> validate(const DefenderState& s,
                                    const PreconditionExpectations& e);

// Render the state as a multi-line diagnostic string. Used by the scan
// subcommand's verbose output and the report's `defender.preconditions`
// block. Stable, machine-stable order so reports diff cleanly.
[[nodiscard]] std::string state_to_string(const DefenderState& s);

}

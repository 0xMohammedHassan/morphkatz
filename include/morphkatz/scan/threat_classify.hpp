#pragma once

#include "morphkatz/scan/scanner.hpp"

#include <string>
#include <string_view>

namespace morphkatz::scan {

// Classification of a Threat name into useful taxonomic axes.
//
// `family` is the second segment of the colon-separated name with any
// trailing variant suffix stripped. Examples:
//   "Trojan:Win32/Mimikatz.A"    -> family "Mimikatz"
//   "HackTool:Win32/Mimikatz!8"  -> family "Mimikatz"
//   "Trojan:Script/Wacatac.B!ml" -> family "Wacatac"
//   "Virus:DOS/EICAR_Test_File"  -> family "EICAR_Test_File"
//
// The family lets the orchestrator group multi-detection cases (mimikatz
// often triggers Trojan + HackTool simultaneously) and is what the
// `defender:broken` array in the diff report keys on.
struct ThreatClass {
    bool        is_ml   = false;
    bool        is_pua  = false;
    bool        is_test = false;          // EICAR
    std::string family;
    std::string platform;                 // "Win32" / "Win64" / "Script" / "DOS"
    std::string category;                 // "Trojan" / "HackTool" / "Backdoor"
};

[[nodiscard]] ThreatClass classify(const Threat&);

// Convenience: true iff the Threat carries the !ml suffix. Bisection
// callers use this as a fast-fail check before walking the file.
[[nodiscard]] bool is_ml_detection(const Threat&) noexcept;

// Convenience: true iff the threat is the canonical EICAR antivirus
// test string. Used by tests so they don't need real malware.
[[nodiscard]] bool is_eicar(const Threat&) noexcept;

// EICAR test string - exposed publicly so tests and the `morphkatz
// scan --self-test` mode can write it to disk without duplicating
// the byte sequence.
inline constexpr std::string_view kEicarStandardAntivirusTestFile =
    "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

}

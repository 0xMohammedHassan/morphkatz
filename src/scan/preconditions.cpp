#include "morphkatz/scan/preconditions.hpp"

#include <sstream>
#include <utility>

#if defined(_WIN32)
    #ifndef WIN32_LEAN_AND_MEAN
    #define WIN32_LEAN_AND_MEAN
    #endif
    #ifndef NOMINMAX
    #define NOMINMAX
    #endif
    #include <windows.h>
#endif

namespace morphkatz::scan {

namespace {

#if defined(_WIN32)

// Read a DWORD value from HKLM\<subkey>\<name>. Returns nullopt if the
// key/value can't be opened or isn't a REG_DWORD. We try the 64-bit
// view first because Defender lives under the native hive on x64
// systems even when our process is 32-bit.
std::optional<unsigned> read_hklm_dword(const wchar_t* subkey,
                                        const wchar_t* name) noexcept {
    HKEY hkey = nullptr;
    auto status = ::RegOpenKeyExW(HKEY_LOCAL_MACHINE, subkey, 0,
                                  KEY_READ | KEY_WOW64_64KEY, &hkey);
    if (status != ERROR_SUCCESS) return std::nullopt;

    DWORD type = 0;
    DWORD value = 0;
    DWORD size = sizeof(value);
    status = ::RegQueryValueExW(hkey, name, nullptr, &type,
                                reinterpret_cast<LPBYTE>(&value), &size);
    ::RegCloseKey(hkey);

    if (status != ERROR_SUCCESS || type != REG_DWORD) return std::nullopt;
    return static_cast<unsigned>(value);
}

bool defender_root_present() noexcept {
    HKEY hkey = nullptr;
    if (::RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                        L"SOFTWARE\\Microsoft\\Windows Defender",
                        0, KEY_READ | KEY_WOW64_64KEY, &hkey) != ERROR_SUCCESS) {
        return false;
    }
    ::RegCloseKey(hkey);
    return true;
}

#endif  // _WIN32

const char* describe_dword(const std::optional<unsigned>& v) {
    if (!v) return "<unreadable>";
    switch (*v) {
        case 0: return "0";
        case 1: return "1";
        case 2: return "2";
        default: return "?";
    }
}

void append_remediation(std::ostringstream& os) {
    os << "\n  Fix in an elevated PowerShell:\n"
          "    Set-MpPreference -MAPSReporting Disabled\n"
          "    Set-MpPreference -SubmitSamplesConsent NeverSend\n"
          "  (Both settings are reverted on next Group Policy refresh\n"
          "  unless you are running a managed device, in which case run\n"
          "  morphkatz scan ... --no-strict-preconditions and review\n"
          "  the warning block in the generated report.)\n";
}

}  // namespace

DefenderState query_state() {
    DefenderState s{};
#if defined(_WIN32)
    s.defender_present = defender_root_present();
    if (!s.defender_present) return s;

    s.spynet_reporting = read_hklm_dword(
        L"SOFTWARE\\Microsoft\\Windows Defender\\Spynet",
        L"SpynetReporting");
    s.submit_samples_consent = read_hklm_dword(
        L"SOFTWARE\\Microsoft\\Windows Defender\\Spynet",
        L"SubmitSamplesConsent");
    s.disable_realtime_monitoring = read_hklm_dword(
        L"SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection",
        L"DisableRealtimeMonitoring");
    s.tamper_protection = read_hklm_dword(
        L"SOFTWARE\\Microsoft\\Windows Defender\\Features",
        L"TamperProtection");
#else
    s.defender_present = false;
#endif
    return s;
}

Result<void> validate(const DefenderState& s,
                      const PreconditionExpectations& e) {
    if (!s.defender_present) {
        // A missing Defender hive on a non-Defender host is an
        // expected condition; the scan layer will pick a different
        // engine (or refuse outright) but pre-conditions can't speak
        // to it usefully. Pass.
        return {};
    }

    std::vector<std::string> failures;
    auto missing_or_not = [&](const std::optional<unsigned>& v,
                              unsigned want, const char* key) {
        if (!v) {
            return e.tolerate_unreadable
                ? std::string{}
                : std::string("  - ") + key + " is unreadable";
        }
        if (*v != want) {
            std::ostringstream o;
            o << "  - " << key << " = " << *v << ", want " << want;
            return o.str();
        }
        return std::string{};
    };

    if (e.require_cloud_off) {
        auto m = missing_or_not(s.spynet_reporting, 0u, "SpynetReporting");
        if (!m.empty()) failures.push_back(std::move(m));
    }
    // SubmitSamplesConsent only matters when cloud reporting (MAPS) is
    // actually on. With SpynetReporting == 0 the engine doesn't talk to
    // the cloud at all, so there is nothing to submit regardless of the
    // raw registry value (which `Get-MpPreference` papers over by
    // returning the effective '2 = NeverSend' default). Skip the gate
    // in that case so we don't false-fail on a fully-disabled MAPS.
    const bool cloud_off = s.spynet_reporting && *s.spynet_reporting == 0u;
    if (e.require_submission_off && !cloud_off) {
        auto m = missing_or_not(s.submit_samples_consent, 2u,
                                "SubmitSamplesConsent");
        if (!m.empty()) failures.push_back(std::move(m));
    }
    if (e.require_rtp_off) {
        auto m = missing_or_not(s.disable_realtime_monitoring, 1u,
                                "DisableRealtimeMonitoring");
        if (!m.empty()) failures.push_back(std::move(m));
    }

    if (failures.empty()) return {};

    std::ostringstream os;
    os << "Defender pre-condition gate failed:\n";
    for (const auto& f : failures) os << f << '\n';
    append_remediation(os);
    return Error::make(ErrorKind::Aborted, os.str(), "preconditions");
}

std::string state_to_string(const DefenderState& s) {
    std::ostringstream os;
    os << "defender_present=" << (s.defender_present ? "yes" : "no") << '\n'
       << "  SpynetReporting          = " << describe_dword(s.spynet_reporting) << '\n'
       << "  SubmitSamplesConsent     = " << describe_dword(s.submit_samples_consent) << '\n'
       << "  DisableRealtimeMonitoring= " << describe_dword(s.disable_realtime_monitoring) << '\n'
       << "  TamperProtection         = " << describe_dword(s.tamper_protection);
    return os.str();
}

}

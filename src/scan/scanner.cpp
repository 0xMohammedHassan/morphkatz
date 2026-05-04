#include "morphkatz/scan/scanner.hpp"

#include <algorithm>
#include <cctype>

namespace morphkatz::scan {

namespace {

// Trim ASCII whitespace from both ends of a string_view.
std::string_view ltrim(std::string_view s) noexcept {
    size_t i = 0;
    while (i < s.size() && std::isspace(static_cast<unsigned char>(s[i]))) ++i;
    return s.substr(i);
}
std::string_view rtrim(std::string_view s) noexcept {
    size_t n = s.size();
    while (n > 0 && std::isspace(static_cast<unsigned char>(s[n - 1]))) --n;
    return s.substr(0, n);
}
std::string_view trim(std::string_view s) noexcept {
    return ltrim(rtrim(s));
}

bool ends_with_ci(std::string_view haystack, std::string_view suffix) noexcept {
    if (suffix.size() > haystack.size()) return false;
    const size_t off = haystack.size() - suffix.size();
    for (size_t i = 0; i < suffix.size(); ++i) {
        const auto a = static_cast<unsigned char>(haystack[off + i]);
        const auto b = static_cast<unsigned char>(suffix[i]);
        if (std::tolower(a) != std::tolower(b)) return false;
    }
    return true;
}

bool starts_with_ci(std::string_view haystack, std::string_view prefix) noexcept {
    if (prefix.size() > haystack.size()) return false;
    for (size_t i = 0; i < prefix.size(); ++i) {
        const auto a = static_cast<unsigned char>(haystack[i]);
        const auto b = static_cast<unsigned char>(prefix[i]);
        if (std::tolower(a) != std::tolower(b)) return false;
    }
    return true;
}

}  // namespace

std::optional<Threat> parse_mpcmdrun_threat_line(std::string_view line) {
    // MpCmdRun emits two relevant line shapes:
    //   "Threat                  : Trojan:Win32/Mimikatz"
    //   "Severity                : Severe"
    // The colon-aligned columns make `Threat\s*:\s*<name>` a robust
    // anchor. Everything before the first colon is the key.
    const auto trimmed = trim(line);
    const auto colon = trimmed.find(':');
    if (colon == std::string_view::npos) return std::nullopt;

    const auto key = trim(trimmed.substr(0, colon));
    if (!starts_with_ci(key, "threat")) return std::nullopt;

    const auto value = trim(trimmed.substr(colon + 1));
    if (value.empty()) return std::nullopt;

    Threat t;
    t.name   = std::string(value);
    t.is_ml  = ends_with_ci(t.name, "!ml");
    t.is_pua = starts_with_ci(t.name, "PUA:") ||
               starts_with_ci(t.name, "Application:");
    // Severity is only available on a separate line; the parent parser
    // must populate it once it sees the matching "Severity : ..." entry.
    return t;
}

std::string sanitize_scanner_output(std::string_view raw) {
    std::string out;
    out.reserve(raw.size());
    for (char c : raw) {
        const auto u = static_cast<unsigned char>(c);
        // Keep printable ASCII, plus newline / tab / carriage-return so
        // multi-line output survives. Drop NUL and other control bytes
        // that trip up logging sinks.
        if (c == '\n' || c == '\t' || c == '\r' ||
            (u >= 0x20 && u < 0x7f) || u >= 0x80) {
            out.push_back(c);
        }
    }
    // Trim trailing whitespace so the report doesn't get a wall of
    // empty lines from MpCmdRun's verbose footer.
    while (!out.empty() && std::isspace(static_cast<unsigned char>(out.back()))) {
        out.pop_back();
    }
    return out;
}

}

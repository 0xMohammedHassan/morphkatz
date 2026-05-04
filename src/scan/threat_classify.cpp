#include "morphkatz/scan/threat_classify.hpp"

#include <algorithm>
#include <cctype>

namespace morphkatz::scan {

namespace {

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

// Strip the trailing variant suffix that Defender appends to family
// names: ".A", ".B!ml", "!8" etc. Walks backwards over [.!A-Z0-9] until
// it hits an alphabetic letter that isn't part of a known suffix.
std::string strip_variant(std::string_view family) {
    // Drop !ml / !rfn / !8 etc.
    auto bang = family.find('!');
    if (bang != std::string_view::npos) family = family.substr(0, bang);
    // Drop trailing ".X" / ".AB" alpha-only variants.
    auto dot = family.rfind('.');
    if (dot != std::string_view::npos) {
        const auto tail = family.substr(dot + 1);
        bool alpha_only = !tail.empty() &&
            std::all_of(tail.begin(), tail.end(), [](char c) {
                return std::isalpha(static_cast<unsigned char>(c)) != 0;
            });
        if (alpha_only) family = family.substr(0, dot);
    }
    return std::string(family);
}

}  // namespace

ThreatClass classify(const Threat& t) {
    ThreatClass out;
    out.is_ml   = is_ml_detection(t);
    out.is_pua  = t.is_pua ||
                  starts_with_ci(t.name, "PUA:") ||
                  starts_with_ci(t.name, "Application:");
    out.is_test = is_eicar(t);

    // Canonical Microsoft format:  Category:Platform/Family.Variant!flag
    // Anything not matching that shape leaves the structured fields
    // empty but still gets the boolean flags above.
    const auto colon = t.name.find(':');
    const auto slash = t.name.find('/');
    if (colon == std::string::npos || slash == std::string::npos ||
        slash <= colon + 1) {
        // Malformed - leave structured fields empty, family is the
        // whole name so reports still have something to display.
        out.family = t.name;
        return out;
    }
    out.category = t.name.substr(0, colon);
    out.platform = t.name.substr(colon + 1, slash - colon - 1);
    out.family   = strip_variant(t.name.substr(slash + 1));
    return out;
}

bool is_ml_detection(const Threat& t) noexcept {
    return t.is_ml || ends_with_ci(t.name, "!ml");
}

bool is_eicar(const Threat& t) noexcept {
    // Microsoft has used a couple of EICAR labels over the years:
    //   "Virus:DOS/EICAR_Test_File"
    //   "Virus:DOS/Eicar_Test_File"
    //   "DOS/EICAR_Test_File"
    // Match on the family substring case-insensitively.
    static constexpr std::string_view needle = "EICAR_Test_File";
    if (t.name.size() < needle.size()) return false;
    for (size_t i = 0; i + needle.size() <= t.name.size(); ++i) {
        if (ends_with_ci(t.name.substr(i, needle.size()), needle)) {
            return true;
        }
    }
    return false;
}

}

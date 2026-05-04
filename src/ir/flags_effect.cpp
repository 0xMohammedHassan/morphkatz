#include "morphkatz/ir/flags_effect.hpp"

#include <cstring>

namespace morphkatz::ir {

bool FlagsEffect::equivalent_to(const FlagsEffect& other) const noexcept {
    return tested    == other.tested
        && modified  == other.modified
        && set_to_0  == other.set_to_0
        && set_to_1  == other.set_to_1
        && undefined == other.undefined;
}

uint32_t FlagsEffect::differences(const FlagsEffect& other) const noexcept {
    return (tested    ^ other.tested)
         | (modified  ^ other.modified)
         | (set_to_0  ^ other.set_to_0)
         | (set_to_1  ^ other.set_to_1)
         | (undefined ^ other.undefined);
}

std::string_view flag_name(Flag f) noexcept {
    switch (f) {
        case F_CF: return "CF"; case F_PF: return "PF"; case F_AF: return "AF";
        case F_ZF: return "ZF"; case F_SF: return "SF"; case F_TF: return "TF";
        case F_IF: return "IF"; case F_DF: return "DF"; case F_OF: return "OF";
        default:   return "";
    }
}

std::string flags_to_string(uint32_t mask) {
    constexpr Flag kAll[] = { F_CF, F_PF, F_AF, F_ZF, F_SF, F_TF, F_IF, F_DF, F_OF };
    std::string out;
    for (auto f : kAll) {
        if (mask & f) {
            if (!out.empty()) out.push_back('|');
            out.append(flag_name(f));
        }
    }
    return out.empty() ? std::string("-") : out;
}

}

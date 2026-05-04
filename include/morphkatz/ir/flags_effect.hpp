#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <string_view>

namespace morphkatz::ir {

// Bit positions for the EFLAGS we care about. Keeps us decoupled from the
// ZydisCPUFlag numeric layout.
enum Flag : uint32_t {
    F_CF   = 1u << 0,
    F_PF   = 1u << 1,
    F_AF   = 1u << 2,
    F_ZF   = 1u << 3,
    F_SF   = 1u << 4,
    F_TF   = 1u << 5,
    F_IF   = 1u << 6,
    F_DF   = 1u << 7,
    F_OF   = 1u << 8,
    F_ALL_ARITH = F_CF | F_PF | F_AF | F_ZF | F_SF | F_OF
};

struct FlagsEffect {
    uint32_t tested    = 0;   // flags read by the instruction
    uint32_t modified  = 0;   // flags whose value depends on operands
    uint32_t set_to_0  = 0;   // unconditionally cleared
    uint32_t set_to_1  = 0;   // unconditionally set
    uint32_t undefined = 0;   // left in arch-undefined state

    // Strict equality across all fields. Two rewrites with identical
    // effect-vectors are unconditionally interchangeable.
    [[nodiscard]] bool equivalent_to(const FlagsEffect& other) const noexcept;

    // Weaker equivalence gated on live-out flags: the rewrite is safe iff no
    // disagreeing flag is read downstream. Returns the set of flags that would
    // have to be dead for the swap to be valid.
    [[nodiscard]] uint32_t differences(const FlagsEffect& other) const noexcept;
};

[[nodiscard]] std::string flags_to_string(uint32_t mask);
[[nodiscard]] std::string_view flag_name(Flag f) noexcept;

}

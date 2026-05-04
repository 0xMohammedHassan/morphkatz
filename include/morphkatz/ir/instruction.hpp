#pragma once

#include "morphkatz/ir/flags_effect.hpp"

#include <array>
#include <cstdint>

namespace morphkatz::ir {

// Mirror of ZYDIS_MAX_OPERAND_COUNT. Kept numeric so this header does not
// have to pull in Zydis.h. The Zydis enum values fit comfortably in uint32_t
// and are exchanged only through the .cpp files that do include Zydis.
inline constexpr unsigned kMaxOperands   = 10;
inline constexpr unsigned kMaxInsnBytes  = 15;

using MnemonicId = uint32_t;
using RegisterId = uint32_t;
using CategoryId = uint32_t;

struct Operand {
    enum class Kind : uint8_t { None, Register, Immediate, Memory, Relative };

    Kind             kind       = Kind::None;
    uint16_t         size_bits  = 0;
    bool             read       = false;
    bool             written    = false;

    RegisterId       reg        = 0;    // for Register / Memory base/index
    int64_t          imm        = 0;    // for Immediate / Relative displacement

    struct Mem {
        RegisterId base     = 0;
        RegisterId index    = 0;
        uint8_t    scale    = 0;
        int64_t    disp     = 0;
        uint16_t   segment  = 0;
    } mem{};
};

struct Instruction {
    uint64_t            va        = 0;
    uint64_t            file_off  = 0;
    std::array<uint8_t, kMaxInsnBytes> bytes{};
    uint8_t             length    = 0;
    MnemonicId          mnemonic  = 0;
    CategoryId          category  = 0;
    std::array<Operand, kMaxOperands> ops{};
    uint8_t             op_count  = 0;
    FlagsEffect         flags{};

    [[nodiscard]] bool valid() const noexcept { return length != 0; }

    // Helpers used everywhere in the rule engine.
    [[nodiscard]] bool    op_is_register(unsigned i) const noexcept;
    [[nodiscard]] bool    op_is_immediate(unsigned i) const noexcept;
    [[nodiscard]] bool    op_is_memory(unsigned i) const noexcept;
    [[nodiscard]] bool    op_is_relative(unsigned i) const noexcept;
    [[nodiscard]] bool    same_register(unsigned i, unsigned j) const noexcept;
};

}

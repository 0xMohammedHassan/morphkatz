#pragma once

#include "morphkatz/ir/instruction.hpp"

#include <array>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace morphkatz::rules {

enum class FlagsEquivalence : uint8_t {
    Equivalent,             // flag effects byte-identical, always swap-safe
    EquivalentIfDead,       // safe only when differences() bits are dead downstream
    NotVerified             // rule author opted out of checking (rare, flagged)
};

enum class RegisterClass : uint8_t {
    Any, Gpr, Gpr8, Gpr16, Gpr32, Gpr64, Xmm, Ymm, Zmm
};

enum class OperandKindMatch : uint8_t {
    Any, Register, Immediate, Memory, Relative
};

struct OperandConstraint {
    unsigned          op_index       = 0;
    OperandKindMatch  kind           = OperandKindMatch::Any;
    RegisterClass     reg_class      = RegisterClass::Any;
    std::optional<int64_t> imm_equals;
    uint16_t          size_bits      = 0;       // 0 = any
};

struct SameRegister {
    unsigned op_a = 0;
    unsigned op_b = 0;
};

struct Rule {
    // Identifiers.
    std::string       id;
    std::string       source_file;
    std::string       description;

    // Match predicate.
    ir::MnemonicId    match_mnemonic   = 0;
    std::string       match_mnemonic_name;   // kept for diagnostics, also allows runtime lookup
    int               match_operand_count = -1;
    std::vector<OperandConstraint> constraints;
    std::vector<SameRegister>      same_register;
    std::vector<ir::RegisterId>    register_blacklist;

    // Optional raw-byte match (for targeted/ rules): exact byte pattern to
    // splice in place of an old byte string. Used by Python-parity rules.
    std::optional<std::vector<uint8_t>> raw_from;
    std::optional<std::vector<uint8_t>> raw_to;

    // Rewrite payload.
    ir::MnemonicId    rewrite_mnemonic = 0;
    std::string       rewrite_mnemonic_name;
    struct RewriteOperand {
        enum class Source : uint8_t { CopyFrom, Immediate, Register };
        // Optional transform applied to a `CopyFrom` immediate operand.
        // Used by SUB/ADD swap rules to encode `sub a,X` as `add a,-X`
        // without losing the original value when the rewrite mnemonic
        // changes sign convention. Has no effect on Source::Immediate
        // (the YAML already specifies the literal).
        enum class ImmTransform : uint8_t { None, Negate };
        Source          source         = Source::CopyFrom;
        ImmTransform    imm_transform  = ImmTransform::None;
        unsigned        copy_from_op   = 0;
        int64_t         imm_value      = 0;
        uint16_t        imm_size_bits  = 0;
        ir::RegisterId  reg            = 0;
        uint16_t        size_bits      = 0;
    };
    std::vector<RewriteOperand> rewrite_operands;

    // Semantics & selection.
    FlagsEquivalence  flags_effect     = FlagsEquivalence::Equivalent;
    // Flags whose *value* differs between source and rewrite even when
    // both touch the same set of flags. Used by SUB <-> ADD swaps where
    // numeric result is identical but CF/OF/AF carry different values
    // (sub computes borrow, add computes carry). Only applied when
    // `flags_effect == EquivalentIfDead`. The matcher gates the rule
    // on `(flags_value_diff_mask & live_out) == 0`.
    uint32_t          flags_value_diff_mask = 0;
    int32_t           size_delta       = 0;      // known, fixed; -1 = variable
    double            weight           = 1.0;

    // Pre-compiled match predicate (populated by RuleLoader for speed).
    std::function<bool(const ir::Instruction&)> compiled_predicate;
};

}

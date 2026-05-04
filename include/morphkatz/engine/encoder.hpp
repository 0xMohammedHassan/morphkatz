#pragma once

#include "morphkatz/common/error.hpp"
#include "morphkatz/ir/instruction.hpp"
#include "morphkatz/rules/rule.hpp"

#include <span>
#include <vector>

namespace morphkatz::engine {

// Assemble the rewrite described by `rule` applied to `source`, using Zydis's
// encoder. Returns the encoded byte sequence (no padding applied).
Result<std::vector<uint8_t>> encode_rewrite(const ir::Instruction& source,
                                            const rules::Rule& rule);

// Assemble an arbitrary mnemonic+operands tuple. Convenience wrapper used by
// tests and bench.
Result<std::vector<uint8_t>> encode_insn(ir::MnemonicId mnemonic,
                                         std::span<const ir::Operand> operands);

}

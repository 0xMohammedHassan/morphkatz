#include "morphkatz/ir/instruction.hpp"

namespace morphkatz::ir {

bool Instruction::op_is_register(unsigned i) const noexcept {
    return i < op_count && ops[i].kind == Operand::Kind::Register;
}
bool Instruction::op_is_immediate(unsigned i) const noexcept {
    return i < op_count && ops[i].kind == Operand::Kind::Immediate;
}
bool Instruction::op_is_memory(unsigned i) const noexcept {
    return i < op_count && ops[i].kind == Operand::Kind::Memory;
}
bool Instruction::op_is_relative(unsigned i) const noexcept {
    return i < op_count && ops[i].kind == Operand::Kind::Relative;
}
bool Instruction::same_register(unsigned i, unsigned j) const noexcept {
    if (!op_is_register(i) || !op_is_register(j)) return false;
    return ops[i].reg == ops[j].reg;
}

}

#pragma once

#include "morphkatz/common/error.hpp"
#include "morphkatz/format/pe_image.hpp"
#include "morphkatz/ir/instruction.hpp"

#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

namespace morphkatz::disasm {

struct BasicBlock {
    uint64_t                  start_va  = 0;
    uint64_t                  end_va    = 0;   // exclusive
    uint64_t                  start_off = 0;
    std::vector<ir::Instruction> instructions;
    std::vector<uint64_t>     successors;      // VAs

    [[nodiscard]] std::string id() const;
};

class Cfg {
public:
    Cfg() = default;
    explicit Cfg(std::vector<BasicBlock> bbs) : blocks_(std::move(bbs)) {}

    [[nodiscard]] const std::vector<BasicBlock>& blocks() const noexcept { return blocks_; }
    [[nodiscard]] std::vector<BasicBlock>&       blocks()       noexcept { return blocks_; }

    [[nodiscard]] size_t instruction_count() const noexcept;

private:
    std::vector<BasicBlock> blocks_;
};

// Build a CFG via recursive descent. Seeds: entry point, exports, TLS
// callbacks, exception-table entries (PE only).
Result<std::unique_ptr<Cfg>> build_cfg(const format::PeImage& img);

// Fallback: linear sweep over executable sections. Returns one block per
// section; used when no seeds are available (e.g. raw shellcode with no
// entry metadata).
std::vector<BasicBlock> linear_sweep_blocks(const format::PeImage& img);

}

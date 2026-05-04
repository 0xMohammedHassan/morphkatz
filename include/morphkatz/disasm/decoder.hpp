#pragma once

#include "morphkatz/common/error.hpp"
#include "morphkatz/ir/instruction.hpp"

#include <functional>
#include <span>

namespace morphkatz::disasm {

// Thin singleton wrapper over a thread-local ZydisDecoder configured for x64.
class Decoder {
public:
    Decoder();
    ~Decoder();
    Decoder(const Decoder&) = delete;
    Decoder& operator=(const Decoder&) = delete;

    // Decode a single instruction starting at `code`. On success, fills `out`
    // and returns Ok; the caller advances by out.length bytes.
    Result<void> decode_one(std::span<const uint8_t> code,
                            uint64_t runtime_va,
                            uint64_t file_off,
                            ir::Instruction& out) const;

    // Linear sweep: walk `code` from start to end and invoke `visitor` for
    // every successfully decoded instruction. Bytes that fail to decode are
    // skipped one at a time (matching the Python reference's implicit
    // behaviour) but counted in `skipped`.
    struct LinearStats {
        size_t decoded = 0;
        size_t skipped = 0;
    };

    LinearStats linear_sweep(std::span<const uint8_t> code,
                             uint64_t runtime_va_base,
                             uint64_t file_off_base,
                             const std::function<void(const ir::Instruction&)>& visitor) const;

private:
    void* handle_ = nullptr;   // opaque ZydisDecoder*
};

// Convenience: decode one instruction without constructing a Decoder every time
// (uses a function-local thread_local decoder).
Result<void> decode_one(std::span<const uint8_t> code,
                        uint64_t runtime_va,
                        uint64_t file_off,
                        ir::Instruction& out);

}

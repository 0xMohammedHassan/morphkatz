#pragma once

#include "morphkatz/common/error.hpp"

#include <cstdint>
#include <span>
#include <vector>

namespace morphkatz::engine {

class Rng;

// PadPolicy generates padding byte sequences that make a rewrite fit back
// into the original instruction slot. Size delta can be positive (need pad)
// or negative (need truncation/rejection); both directions are handled
// explicitly so the engine never silent-drops a negative delta.
//
// Padding bytes rotate across the 8 multi-byte NOP encodings recommended by
// the Intel SDM Vol.2A § NOP and Intel Optimization Reference Manual §3.5.1.9.
class PadPolicy {
public:
    explicit PadPolicy(Rng& rng);

    // Pad (or truncate) `body` to fit in the original slot.
    //   delta  > 0: append `delta` NOP bytes drawn from the rotated pool.
    //   delta  = 0: body returned unchanged.
    //   delta  < 0: body is longer than slot; returns Error (NotSupported)
    //               unless the extra tail fits within the next-instruction
    //               boundary as per caller policy.
    [[nodiscard]] Result<std::vector<uint8_t>> pad(std::span<const uint8_t> body,
                                                   int delta);

    // Emit exactly `bytes` NOP bytes, rotated from the pool; used by
    // orchestrators that want to fill a gap independent of a specific rewrite.
    [[nodiscard]] std::vector<uint8_t> emit_nops(size_t bytes);

    // Expose the pool for tests / benchmarks.
    [[nodiscard]] static std::span<const std::span<const uint8_t>> nop_pool() noexcept;

private:
    Rng& rng_;
};

}

#include "morphkatz/engine/pad_policy.hpp"

#include "morphkatz/engine/rng.hpp"

#include <array>
#include <cstring>

namespace morphkatz::engine {

namespace {

// Intel SDM Vol 2A "NOP" table + Intel Optimization Reference Manual
// § 3.5.1.9 (Using NOPs). Lengths 1..9 covered; longer pads chain these.
constexpr std::array<uint8_t, 1> kNop1{ 0x90 };
constexpr std::array<uint8_t, 2> kNop2{ 0x66, 0x90 };
constexpr std::array<uint8_t, 3> kNop3{ 0x0F, 0x1F, 0x00 };
constexpr std::array<uint8_t, 4> kNop4{ 0x0F, 0x1F, 0x40, 0x00 };
constexpr std::array<uint8_t, 5> kNop5{ 0x0F, 0x1F, 0x44, 0x00, 0x00 };
constexpr std::array<uint8_t, 6> kNop6{ 0x66, 0x0F, 0x1F, 0x44, 0x00, 0x00 };
constexpr std::array<uint8_t, 7> kNop7{ 0x0F, 0x1F, 0x80, 0x00, 0x00, 0x00, 0x00 };
constexpr std::array<uint8_t, 8> kNop8{ 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00 };
constexpr std::array<uint8_t, 9> kNop9{ 0x66, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00 };

const std::span<const uint8_t> kPool[] = {
    {kNop1.data(), kNop1.size()}, {kNop2.data(), kNop2.size()},
    {kNop3.data(), kNop3.size()}, {kNop4.data(), kNop4.size()},
    {kNop5.data(), kNop5.size()}, {kNop6.data(), kNop6.size()},
    {kNop7.data(), kNop7.size()}, {kNop8.data(), kNop8.size()},
    {kNop9.data(), kNop9.size()},
};

// Given `n` bytes of padding needed, pick a cover set of NOP encodings that
// sum to exactly n. We greedily pick the longest NOP that still fits, but
// rotate the starting index with `rng` so we don't always emit 0F1F804...
std::vector<uint8_t> compose_padding(Rng& rng, size_t n) {
    std::vector<uint8_t> out;
    out.reserve(n);
    while (n > 0) {
        const size_t max_len = (n >= sizeof(kPool) / sizeof(kPool[0]))
                                 ? sizeof(kPool) / sizeof(kPool[0])
                                 : n;
        // Uniform pick in [1, max_len]. Uniform sampling gives a flat
        // distribution over NOP lengths which is harder to fingerprint than
        // "always emit the longest-fitting NOP"; long-NOP bias is kept as
        // a v1.1 knob (tracked in docs/benchmarks.md).
        const size_t pick = static_cast<size_t>(rng.range(max_len - 1)) + 1;
        const auto&  seq  = kPool[pick - 1];
        out.insert(out.end(), seq.begin(), seq.end());
        n -= pick;
    }
    return out;
}

}  // namespace

PadPolicy::PadPolicy(Rng& rng) : rng_(rng) {}

Result<std::vector<uint8_t>> PadPolicy::pad(std::span<const uint8_t> body, int delta) {
    std::vector<uint8_t> out(body.begin(), body.end());
    if (delta == 0) {
        return out;
    }
    if (delta > 0) {
        auto nops = compose_padding(rng_, static_cast<size_t>(delta));
        out.insert(out.end(), nops.begin(), nops.end());
        return out;
    }
    // delta < 0: replacement longer than slot. We refuse — let the caller
    // decide whether to widen the block or reject the rewrite. (Earlier
    // prototypes silent-dropped the negative-delta path; doing so risks
    // truncating real instruction bytes, so the engine now returns an
    // explicit error instead.)
    return Error::make(ErrorKind::NotSupported,
        "rewrite longer than original slot; pad_policy refusing to truncate");
}

std::vector<uint8_t> PadPolicy::emit_nops(size_t bytes) {
    return compose_padding(rng_, bytes);
}

std::span<const std::span<const uint8_t>> PadPolicy::nop_pool() noexcept {
    return {kPool, sizeof(kPool) / sizeof(kPool[0])};
}

}

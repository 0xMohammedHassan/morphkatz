#pragma once

#include <cstdint>
#include <optional>
#include <span>

namespace morphkatz::engine {

// xoshiro256** — fast, high quality, 256-bit state PRNG. The MorphKatz rule
// engine only uses this class; no std::rand, no unseeded mersenne twister
// anywhere. Reproducibility is a hard guarantee when --seed is provided.
class Rng {
public:
    // Deterministic: seed from u64 (splitmix64-expand to 256 bits).
    // Nondeterministic: seed from BCryptGenRandom on Windows (or /dev/urandom
    // equivalent in tests).
    explicit Rng(std::optional<uint64_t> seed);
    Rng(const Rng&) = delete;
    Rng& operator=(const Rng&) = delete;

    [[nodiscard]] uint64_t next_u64() noexcept;
    [[nodiscard]] uint64_t range(uint64_t inclusive_max) noexcept;
    [[nodiscard]] double   next_unit() noexcept;            // [0,1)
    [[nodiscard]] bool     chance(double p) noexcept;
    [[nodiscard]] uint64_t seed() const noexcept { return seed_echo_; }

    // Weighted reservoir sampling. Returns the index of the winner, or -1 if
    // the input weights are all zero/empty.
    [[nodiscard]] int64_t weighted_pick(std::span<const double> weights) noexcept;

private:
    uint64_t s_[4]{};
    uint64_t seed_echo_ = 0;     // what we echo back for --report reproducibility
};

}

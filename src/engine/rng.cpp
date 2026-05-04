#include "morphkatz/engine/rng.hpp"

#include <cmath>
#include <cstring>

#if defined(_WIN32)
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <windows.h>
#  include <bcrypt.h>
#  pragma comment(lib, "bcrypt")
#endif

namespace morphkatz::engine {

namespace {

uint64_t splitmix64(uint64_t& state) noexcept {
    uint64_t z = (state += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

uint64_t crypto_random_u64() {
#if defined(_WIN32)
    uint64_t v = 0;
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_RNG_ALGORITHM, nullptr, 0) == 0) {
        BCryptGenRandom(hAlg, reinterpret_cast<PUCHAR>(&v), sizeof(v), 0);
        BCryptCloseAlgorithmProvider(hAlg, 0);
    }
    return v ? v : 0xDEADBEEFCAFEBABEULL;
#else
    return 0xDEADBEEFCAFEBABEULL;
#endif
}

constexpr uint64_t rotl(uint64_t x, int k) noexcept {
    return (x << k) | (x >> (64 - k));
}

}  // namespace

Rng::Rng(std::optional<uint64_t> seed) {
    uint64_t init = seed ? *seed : crypto_random_u64();
    seed_echo_ = init;
    uint64_t sm = init;
    s_[0] = splitmix64(sm);
    s_[1] = splitmix64(sm);
    s_[2] = splitmix64(sm);
    s_[3] = splitmix64(sm);
}

uint64_t Rng::next_u64() noexcept {
    const uint64_t result = rotl(s_[1] * 5, 7) * 9;
    const uint64_t t      = s_[1] << 17;
    s_[2] ^= s_[0];
    s_[3] ^= s_[1];
    s_[1] ^= s_[2];
    s_[0] ^= s_[3];
    s_[2] ^= t;
    s_[3]  = rotl(s_[3], 45);
    return result;
}

uint64_t Rng::range(uint64_t inclusive_max) noexcept {
    if (inclusive_max == 0) return 0;
    const uint64_t span      = inclusive_max + 1;
    const uint64_t threshold = (~span + 1) % span;   // (2^64 - span) mod span
    uint64_t r;
    do { r = next_u64(); } while (r < threshold);
    return r % span;
}

double Rng::next_unit() noexcept {
    // 53-bit mantissa, standard trick for unbiased [0,1) draws.
    return static_cast<double>(next_u64() >> 11) * (1.0 / 9007199254740992.0);
}

bool Rng::chance(double p) noexcept {
    if (p <= 0.0) return false;
    if (p >= 1.0) return true;
    return next_unit() < p;
}

int64_t Rng::weighted_pick(std::span<const double> weights) noexcept {
    // Weighted reservoir (Efraimidis-Spirakis): each weight gives a key
    // u^(1/w); the max wins. We run it in log space to avoid the pow for
    // tiny weights.
    int64_t winner = -1;
    double  best_key = -1e300;
    for (size_t i = 0; i < weights.size(); ++i) {
        const double w = weights[i];
        if (w <= 0.0) continue;
        const double u = next_unit();
        // Guard against u==0; log(0) is -inf — rare but possible.
        const double key = (u == 0.0) ? -1e300
                                      : std::log(u) / w;
        if (key > best_key) {
            best_key = key;
            winner   = static_cast<int64_t>(i);
        }
    }
    return winner;
}

}

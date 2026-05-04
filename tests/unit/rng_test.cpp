#include "morphkatz/engine/rng.hpp"

#include <catch2/catch_test_macros.hpp>

#include <array>

using morphkatz::engine::Rng;

TEST_CASE("RNG is deterministic given the same seed", "[engine][rng]") {
    Rng a(uint64_t{0xDEAD'BEEFULL});
    Rng b(uint64_t{0xDEAD'BEEFULL});
    for (int i = 0; i < 256; ++i) {
        REQUIRE(a.next_u64() == b.next_u64());
    }
}

TEST_CASE("RNG with different seeds produces different streams", "[engine][rng]") {
    Rng a(uint64_t{1});
    Rng b(uint64_t{2});
    REQUIRE(a.next_u64() != b.next_u64());
}

TEST_CASE("RNG range stays within the requested bound", "[engine][rng]") {
    Rng r(uint64_t{0});
    for (int i = 0; i < 10'000; ++i) {
        const auto v = r.range(99);
        REQUIRE(v <= 99);
    }
}

TEST_CASE("RNG weighted_pick honours weights", "[engine][rng]") {
    Rng r(uint64_t{42});
    const std::array<double, 3> w{0.0, 1.0, 0.0};
    // With only index 1 having positive weight, it must win every time.
    for (int i = 0; i < 256; ++i) {
        REQUIRE(r.weighted_pick(w) == 1);
    }
}

TEST_CASE("RNG weighted_pick returns -1 on all-zero weights", "[engine][rng]") {
    Rng r(uint64_t{0});
    const std::array<double, 3> w{0.0, 0.0, 0.0};
    REQUIRE(r.weighted_pick(w) == -1);
}

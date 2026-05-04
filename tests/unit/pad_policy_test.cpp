#include "morphkatz/engine/pad_policy.hpp"
#include "morphkatz/engine/rng.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <array>

using morphkatz::engine::PadPolicy;
using morphkatz::engine::Rng;

TEST_CASE("PadPolicy returns body unchanged when delta = 0", "[engine][pad]") {
    Rng rng(uint64_t{0});
    PadPolicy pp(rng);
    const std::array<uint8_t, 3> body{0x90, 0x90, 0x90};
    auto r = pp.pad({body.data(), body.size()}, 0);
    REQUIRE(r.ok());
    REQUIRE(r->size() == 3);
}

TEST_CASE("PadPolicy appends exactly delta NOP bytes for delta > 0", "[engine][pad]") {
    Rng rng(uint64_t{7});
    PadPolicy pp(rng);
    const std::array<uint8_t, 2> body{0xB0, 0x01};
    for (int delta : {1, 2, 3, 4, 5, 6, 7, 8, 9, 17, 32}) {
        auto r = pp.pad({body.data(), body.size()}, delta);
        REQUIRE(r.ok());
        REQUIRE(r->size() == body.size() + static_cast<size_t>(delta));
    }
}

TEST_CASE("PadPolicy rejects negative delta (bug-fix #314-320)", "[engine][pad]") {
    Rng rng(uint64_t{0});
    PadPolicy pp(rng);
    const std::array<uint8_t, 3> body{0x90, 0x90, 0x90};
    auto r = pp.pad({body.data(), body.size()}, -1);
    REQUIRE_FALSE(r.ok());
    REQUIRE(r.error().kind == morphkatz::ErrorKind::NotSupported);
}

TEST_CASE("PadPolicy uses multi-byte NOP forms, never repeating 0x90", "[engine][pad]") {
    // The Python reference wrote 0x90 * n or 0x87 0xFF * n/2, both signature-prone.
    // Our policy must produce non-trivial sequences.
    Rng rng(uint64_t{12345});
    PadPolicy pp(rng);
    auto seq = pp.emit_nops(32);
    REQUIRE(seq.size() == 32);
    // Reject the degenerate "all 0x90" pattern.
    const bool all_90 = std::all_of(seq.begin(), seq.end(), [](uint8_t b) { return b == 0x90; });
    REQUIRE_FALSE(all_90);
}

TEST_CASE("PadPolicy is reproducible with the same seed", "[engine][pad]") {
    Rng a(uint64_t{99}); PadPolicy pa(a);
    Rng b(uint64_t{99}); PadPolicy pb(b);
    REQUIRE(pa.emit_nops(24) == pb.emit_nops(24));
}

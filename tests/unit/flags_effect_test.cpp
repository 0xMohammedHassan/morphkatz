#include "morphkatz/ir/flags_effect.hpp"

#include <catch2/catch_test_macros.hpp>

using morphkatz::ir::FlagsEffect;
using morphkatz::ir::Flag;

TEST_CASE("FlagsEffect strict equivalence requires all fields identical", "[ir][flags]") {
    FlagsEffect a, b;
    a.modified = Flag::F_CF | Flag::F_ZF;
    b.modified = Flag::F_CF | Flag::F_ZF;
    REQUIRE(a.equivalent_to(b));

    b.undefined = Flag::F_AF;
    REQUIRE_FALSE(a.equivalent_to(b));
}

TEST_CASE("FlagsEffect differences mask highlights distinct bits", "[ir][flags]") {
    FlagsEffect xor_rr;   // xor r,r : CF=0, OF=0, ZF=1, PF=1, SF=0, AF=undef
    xor_rr.set_to_0  = Flag::F_CF | Flag::F_OF | Flag::F_SF;
    xor_rr.set_to_1  = Flag::F_ZF | Flag::F_PF;
    xor_rr.undefined = Flag::F_AF;

    FlagsEffect sub_rr = xor_rr;    // same shape
    REQUIRE(xor_rr.differences(sub_rr) == 0);

    FlagsEffect and_r0;
    and_r0.set_to_0  = Flag::F_CF | Flag::F_OF;
    and_r0.modified  = Flag::F_ZF | Flag::F_PF | Flag::F_SF;
    and_r0.undefined = Flag::F_AF;

    const auto diff = xor_rr.differences(and_r0);
    REQUIRE(diff != 0);
}

TEST_CASE("flags_to_string renders multi-flag masks", "[ir][flags]") {
    const auto s = morphkatz::ir::flags_to_string(Flag::F_CF | Flag::F_ZF | Flag::F_OF);
    REQUIRE(s.find("CF") != std::string::npos);
    REQUIRE(s.find("ZF") != std::string::npos);
    REQUIRE(s.find("OF") != std::string::npos);
}

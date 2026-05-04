#include "morphkatz/scan/threat_classify.hpp"

#include <catch2/catch_test_macros.hpp>

using morphkatz::scan::Threat;
using morphkatz::scan::classify;
using morphkatz::scan::is_eicar;
using morphkatz::scan::is_ml_detection;

TEST_CASE("classify recognises classic Trojan family names", "[scan][unit]") {
    Threat t;
    t.name = "Trojan:Win32/Mimikatz.A";
    auto c = classify(t);
    CHECK(c.category == "Trojan");
    CHECK(c.platform == "Win32");
    CHECK(c.family   == "Mimikatz");
    CHECK_FALSE(c.is_ml);
    CHECK_FALSE(c.is_pua);
    CHECK_FALSE(c.is_test);
}

TEST_CASE("classify strips !ml and !N variant suffixes", "[scan][unit]") {
    Threat t1{"Trojan:Script/Wacatac.B!ml", {}, false, false};
    auto c1 = classify(t1);
    CHECK(c1.family == "Wacatac");
    CHECK(c1.is_ml);

    Threat t2{"HackTool:Win32/Mimikatz!8", {}, false, false};
    auto c2 = classify(t2);
    CHECK(c2.family == "Mimikatz");
    CHECK_FALSE(c2.is_ml);
}

TEST_CASE("classify flags PUA / test files", "[scan][unit]") {
    Threat pua{"PUA:Win32/Presenoker", {}, false, true};
    auto p = classify(pua);
    CHECK(p.is_pua);

    Threat eicar{"Virus:DOS/EICAR_Test_File", {}, false, false};
    auto e = classify(eicar);
    CHECK(e.is_test);
    CHECK(is_eicar(eicar));
    CHECK(e.platform == "DOS");
}

TEST_CASE("is_ml_detection is case-insensitive", "[scan][unit]") {
    Threat t{"Trojan:Win32/Foo!ML", {}, false, false};
    CHECK(is_ml_detection(t));
}

TEST_CASE("classify tolerates malformed names", "[scan][unit]") {
    Threat t{"weird-format", {}, false, false};
    auto c = classify(t);
    CHECK(c.family == "weird-format");
    CHECK(c.category.empty());
    CHECK(c.platform.empty());
}

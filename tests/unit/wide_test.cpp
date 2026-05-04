#include "morphkatz/common/wide.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>

TEST_CASE("UTF-8 <-> UTF-16 roundtrip for ASCII", "[common][wide]") {
    const std::string ascii = "Hello, MorphKatz.";
    REQUIRE(morphkatz::to_utf8(morphkatz::to_wide(ascii)) == ascii);
}

TEST_CASE("UTF-8 <-> UTF-16 roundtrip for non-BMP characters", "[common][wide]") {
    // "\xF0\x9F\x91\xBB" is the UTF-8 encoding of U+1F47B (GHOST), surrogate
    // pair in UTF-16. C++20 made `u8"..."` a `const char8_t[]`, which no
    // longer implicitly concatenates with `std::string`; express the
    // UTF-8 bytes as a plain literal instead.
    const std::string ghost = "ghost \xF0\x9F\x91\xBB";
    const auto wide = morphkatz::to_wide(ghost);
    REQUIRE(wide.size() >= 7);
    REQUIRE(morphkatz::to_utf8(wide) == ghost);
}

TEST_CASE("path_from_utf8 round-trips", "[common][wide]") {
    const std::string p = "C:/temp/morphkatz/sample.exe";
    auto path = morphkatz::path_from_utf8(p);
    REQUIRE(morphkatz::path_to_utf8(path).find("sample.exe") != std::string::npos);
}

#include "morphkatz/common/version.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string_view>

TEST_CASE("build metadata is non-empty", "[smoke]") {
    REQUIRE(!morphkatz::kVersion.empty());
    REQUIRE(!morphkatz::kCodename.empty());
    REQUIRE(!morphkatz::kBuildDate.empty());
}

TEST_CASE("version string has MAJOR.MINOR.PATCH shape", "[smoke]") {
    const std::string_view v = morphkatz::kVersion;
    const auto dots = static_cast<size_t>(std::count(v.begin(), v.end(), '.'));
    REQUIRE(dots == 2);
}

#include "morphkatz/common/error.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>

using morphkatz::Error;
using morphkatz::ErrorKind;
using morphkatz::Result;

static Result<int> divide(int a, int b) {
    if (b == 0) {
        return Error::make(ErrorKind::Invalid, "division by zero", "divide()");
    }
    return a / b;
}

TEST_CASE("Result<T> returns value on success", "[common][error]") {
    auto r = divide(10, 2);
    REQUIRE(r.ok());
    REQUIRE(*r == 5);
}

TEST_CASE("Result<T> carries typed error on failure", "[common][error]") {
    auto r = divide(10, 0);
    REQUIRE_FALSE(r.ok());
    REQUIRE(r.error().kind == ErrorKind::Invalid);
    REQUIRE(r.error().what.find("division") != std::string::npos);
    REQUIRE(morphkatz::kind_name(r.error().kind) == "Invalid");
}

TEST_CASE("Result<void> models success/failure", "[common][error]") {
    Result<void> ok;
    REQUIRE(ok.ok());

    Result<void> err = Error::make(ErrorKind::Io, "disk full");
    REQUIRE_FALSE(err.ok());
    REQUIRE(err.error().kind == ErrorKind::Io);
}

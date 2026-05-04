#pragma once

#include <string>
#include <string_view>
#include <utility>
#include <variant>

namespace morphkatz {

// Coarse error taxonomy. One variant per failure class so callers can branch
// on kind without string matching.
enum class ErrorKind : unsigned {
    Ok = 0,
    Io,
    ParseFormat,      // PE/ELF parse failure
    Decode,           // Zydis decode failure
    Encode,           // Zydis encode failure
    RuleLoad,         // YAML parse/schema failure
    RuleMatch,        // rule preconditions not satisfied (informational)
    Verify,           // re-disasm or Unicorn disagreement
    Invalid,          // internal invariant violated
    NotSupported,
    Aborted
};

struct Error {
    ErrorKind   kind  = ErrorKind::Invalid;
    std::string what;
    std::string where;   // optional: file path, offset, rule id

    [[nodiscard]] bool ok() const noexcept { return kind == ErrorKind::Ok; }

    static Error ok_() noexcept { return Error{ ErrorKind::Ok, {}, {} }; }
    static Error make(ErrorKind k, std::string msg, std::string loc = {}) {
        return Error{ k, std::move(msg), std::move(loc) };
    }
};

// Lightweight expected<T,Error>. We use std::expected on MSVC 19.40+ when
// available, but ship our own to avoid forcing /std:c++latest on every caller.
template <typename T>
class Result {
public:
    // NOLINTNEXTLINE(google-explicit-constructor) — intentionally implicit.
    Result(T value) : data_(std::move(value)) {}
    // NOLINTNEXTLINE(google-explicit-constructor)
    Result(Error err) : data_(std::move(err)) {}

    [[nodiscard]] bool  ok()    const noexcept { return data_.index() == 0; }
    [[nodiscard]] explicit operator bool() const noexcept { return ok(); }

    [[nodiscard]] T&        value()       { return std::get<0>(data_); }
    [[nodiscard]] const T&  value() const { return std::get<0>(data_); }
    [[nodiscard]] const Error& error() const { return std::get<1>(data_); }

    T& operator*() { return value(); }
    const T& operator*() const { return value(); }
    T* operator->() { return &value(); }
    const T* operator->() const { return &value(); }

private:
    std::variant<T, Error> data_;
};

// Void specialisation for functions that either succeed or fail.
template <>
class Result<void> {
public:
    Result() : err_{ErrorKind::Ok, {}, {}} {}
    // NOLINTNEXTLINE(google-explicit-constructor)
    Result(Error err) : err_(std::move(err)) {}

    [[nodiscard]] bool ok() const noexcept { return err_.ok(); }
    [[nodiscard]] explicit operator bool() const noexcept { return ok(); }
    [[nodiscard]] const Error& error() const { return err_; }

private:
    Error err_;
};

inline std::string_view kind_name(ErrorKind k) noexcept {
    switch (k) {
        case ErrorKind::Ok:           return "Ok";
        case ErrorKind::Io:           return "Io";
        case ErrorKind::ParseFormat:  return "ParseFormat";
        case ErrorKind::Decode:       return "Decode";
        case ErrorKind::Encode:       return "Encode";
        case ErrorKind::RuleLoad:     return "RuleLoad";
        case ErrorKind::RuleMatch:    return "RuleMatch";
        case ErrorKind::Verify:       return "Verify";
        case ErrorKind::Invalid:      return "Invalid";
        case ErrorKind::NotSupported: return "NotSupported";
        case ErrorKind::Aborted:      return "Aborted";
    }
    return "Unknown";
}

}

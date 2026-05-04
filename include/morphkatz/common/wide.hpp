#pragma once

#include <filesystem>
#include <string>
#include <string_view>

namespace morphkatz {

// UTF-8 <-> UTF-16 boundary helpers. Internally the engine speaks UTF-8;
// Windows filesystem / CLI layer uses wide strings.
[[nodiscard]] std::wstring to_wide(std::string_view utf8);
[[nodiscard]] std::string  to_utf8(std::wstring_view utf16);

[[nodiscard]] std::filesystem::path path_from_utf8(std::string_view utf8);
[[nodiscard]] std::string           path_to_utf8(const std::filesystem::path& p);

}

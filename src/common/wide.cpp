#include "morphkatz/common/wide.hpp"

#include <cstring>

#if defined(_WIN32)
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <windows.h>
#endif

namespace morphkatz {

std::wstring to_wide(std::string_view utf8) {
#if defined(_WIN32)
    if (utf8.empty()) return {};
    const int src_len = static_cast<int>(utf8.size());
    const int needed  = ::MultiByteToWideChar(CP_UTF8, 0, utf8.data(), src_len, nullptr, 0);
    std::wstring out(static_cast<size_t>(needed), L'\0');
    ::MultiByteToWideChar(CP_UTF8, 0, utf8.data(), src_len, out.data(), needed);
    return out;
#else
    return std::wstring(utf8.begin(), utf8.end());
#endif
}

std::string to_utf8(std::wstring_view utf16) {
#if defined(_WIN32)
    if (utf16.empty()) return {};
    const int src_len = static_cast<int>(utf16.size());
    const int needed  = ::WideCharToMultiByte(CP_UTF8, 0, utf16.data(), src_len,
                                              nullptr, 0, nullptr, nullptr);
    std::string out(static_cast<size_t>(needed), '\0');
    ::WideCharToMultiByte(CP_UTF8, 0, utf16.data(), src_len,
                          out.data(), needed, nullptr, nullptr);
    return out;
#else
    return std::string(utf16.begin(), utf16.end());
#endif
}

std::filesystem::path path_from_utf8(std::string_view utf8) {
#if defined(_WIN32)
    return std::filesystem::path(to_wide(utf8));
#else
    return std::filesystem::path(std::string(utf8));
#endif
}

std::string path_to_utf8(const std::filesystem::path& p) {
#if defined(_WIN32)
    return to_utf8(p.wstring());
#else
    return p.string();
#endif
}

}

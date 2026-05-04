#pragma once

#include <filesystem>
#include <memory>
#include <string_view>

#include <spdlog/logger.h>

namespace morphkatz::logging {

struct Options {
    int  verbosity = 0;    // 0 = info, 1 = debug, >=2 = trace
    bool quiet     = false;
    std::filesystem::path log_file;
};

// Install the global spdlog sink. Call once from main().
void init(const Options& opts);

// Convenience accessors.
spdlog::logger&  get();
std::shared_ptr<spdlog::logger> get_ptr();

}  // namespace morphkatz::logging

// Thin wrappers so translation units don't need to pull in spdlog everywhere.
#include <spdlog/spdlog.h>
#define MK_TRACE(...)   SPDLOG_LOGGER_TRACE   (::morphkatz::logging::get_ptr(), __VA_ARGS__)
#define MK_DEBUG(...)   SPDLOG_LOGGER_DEBUG   (::morphkatz::logging::get_ptr(), __VA_ARGS__)
#define MK_INFO(...)    SPDLOG_LOGGER_INFO    (::morphkatz::logging::get_ptr(), __VA_ARGS__)
#define MK_WARN(...)    SPDLOG_LOGGER_WARN    (::morphkatz::logging::get_ptr(), __VA_ARGS__)
#define MK_ERROR(...)   SPDLOG_LOGGER_ERROR   (::morphkatz::logging::get_ptr(), __VA_ARGS__)
#define MK_CRIT(...)    SPDLOG_LOGGER_CRITICAL(::morphkatz::logging::get_ptr(), __VA_ARGS__)

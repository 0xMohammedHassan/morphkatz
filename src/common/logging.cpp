#include "morphkatz/common/logging.hpp"

#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/sinks/dist_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>

#include <mutex>

namespace morphkatz::logging {

namespace {
std::shared_ptr<spdlog::logger>& logger_slot() {
    static std::shared_ptr<spdlog::logger> slot;
    return slot;
}
std::once_flag& init_once() {
    static std::once_flag f;
    return f;
}
}  // namespace

void init(const Options& opts) {
    std::call_once(init_once(), [&]() {
        auto dist = std::make_shared<spdlog::sinks::dist_sink_mt>();
        if (!opts.quiet) {
            dist->add_sink(std::make_shared<spdlog::sinks::stderr_color_sink_mt>());
        }
        if (!opts.log_file.empty()) {
            dist->add_sink(std::make_shared<spdlog::sinks::basic_file_sink_mt>(
                opts.log_file.string(), /*truncate=*/true));
        }

        auto lg = std::make_shared<spdlog::logger>("morphkatz", dist);
        switch (opts.verbosity) {
            case 0:  lg->set_level(spdlog::level::info);  break;
            case 1:  lg->set_level(spdlog::level::debug); break;
            default: lg->set_level(spdlog::level::trace); break;
        }
        lg->set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%^%l%$] %v");
        lg->flush_on(spdlog::level::warn);

        spdlog::register_logger(lg);
        spdlog::set_default_logger(lg);
        logger_slot() = lg;
    });
}

spdlog::logger& get() {
    auto& slot = logger_slot();
    if (!slot) {
        Options defaults{};
        init(defaults);
    }
    return *logger_slot();
}

std::shared_ptr<spdlog::logger> get_ptr() {
    (void)get();
    return logger_slot();
}

}

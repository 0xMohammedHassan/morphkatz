#include "morphkatz/cli/args.hpp"
#include "morphkatz/cli/banner.hpp"
#include "morphkatz/common/logging.hpp"
#include "morphkatz/common/version.hpp"
#include "morphkatz/engine/batch.hpp"
#include "morphkatz/engine/compare.hpp"
#include "morphkatz/engine/orchestrator.hpp"
#include "morphkatz/scan/scan_subcommand.hpp"

#include <cstdio>
#include <exception>

int wmain(int argc, wchar_t** argv);  // Windows entry point

int wmain(int argc, wchar_t** argv) {
    try {
        auto parsed = morphkatz::cli::parse(argc, argv);
        if (!parsed) {
            // Print the parse-error message instead of dying silently.
            // CLI11's own errors (unknown flag, type mismatch) are already
            // printed by app.exit() before we get here; our hand-rolled
            // ParseErrors are the ones we still need to surface.
            const auto& err = parsed.error();
            if (!err.what.empty()) {
                std::fprintf(stderr, "[morphkatz] %s\n", err.what.c_str());
            }
            return err.exit_code;
        }
        auto& opts = parsed->options;

        if (parsed->action == morphkatz::cli::Action::ShowVersion) {
            std::fputs(morphkatz::cli::kBanner.data(), stdout);
            std::printf("morphkatz %s (%s)\n"
                        "build: %s\n"
                        "tools: Zydis + LIEF + Unicorn + YARA (vcpkg)\n",
                        morphkatz::kVersion.data(),
                        morphkatz::kCodename.data(),
                        morphkatz::kBuildDate.data());
            return 0;
        }
        if (parsed->action == morphkatz::cli::Action::ShowHelp) {
            std::fputs(parsed->help_text.c_str(), stdout);
            return 0;
        }
        if (parsed->action == morphkatz::cli::Action::ShowBanner) {
            std::fputs(morphkatz::cli::kBanner.data(),       stdout);
            std::fputs(morphkatz::cli::kFirstRunHint.data(), stdout);
            return 0;
        }

        if (parsed->action == morphkatz::cli::Action::Compare) {
            morphkatz::logging::init({
                .verbosity = parsed->compare.verbosity,
                .quiet     = parsed->compare.quiet,
                .log_file  = parsed->compare.log_file
            });
            const auto rc = morphkatz::engine::run_compare(parsed->compare);
            if (!rc.ok()) {
                const auto& err = rc.error();
                std::fprintf(stderr, "[morphkatz] %.*s: %s",
                             static_cast<int>(morphkatz::kind_name(err.kind).size()),
                             morphkatz::kind_name(err.kind).data(),
                             err.what.c_str());
                if (!err.where.empty()) {
                    std::fprintf(stderr, " (%s)", err.where.c_str());
                }
                std::fputc('\n', stderr);
                return 1;
            }
            return 0;
        }

        if (parsed->action == morphkatz::cli::Action::Scan) {
            morphkatz::logging::init({
                .verbosity = parsed->scan.verbosity,
                .quiet     = parsed->scan.quiet,
                .log_file  = parsed->scan.log_file
            });
            const auto rc = morphkatz::scan::run_scan(parsed->scan);
            if (!rc.ok()) {
                const auto& err = rc.error();
                std::fprintf(stderr, "[morphkatz] %.*s: %s",
                             static_cast<int>(morphkatz::kind_name(err.kind).size()),
                             morphkatz::kind_name(err.kind).data(),
                             err.what.c_str());
                if (!err.where.empty()) {
                    std::fprintf(stderr, " (%s)", err.where.c_str());
                }
                std::fputc('\n', stderr);
                return 1;
            }
            return 0;
        }

        morphkatz::logging::init({
            .verbosity = opts.verbosity,
            .quiet     = opts.quiet,
            .log_file  = opts.log_file
        });

        const auto rc = (opts.variants > 1)
            ? morphkatz::engine::run_variants(opts)
            : [&]() {
                morphkatz::engine::Orchestrator orch(opts);
                return orch.run();
              }();
        if (!rc.ok()) {
            const auto& err = rc.error();
            std::fprintf(stderr, "[morphkatz] %.*s: %s",
                         static_cast<int>(morphkatz::kind_name(err.kind).size()),
                         morphkatz::kind_name(err.kind).data(),
                         err.what.c_str());
            if (!err.where.empty()) {
                std::fprintf(stderr, " (%s)", err.where.c_str());
            }
            std::fputc('\n', stderr);
            return 1;
        }
        return 0;
    } catch (const std::exception& e) {
        std::fprintf(stderr, "[morphkatz] unhandled exception: %s\n", e.what());
        return 2;
    } catch (...) {
        std::fputs("[morphkatz] unhandled non-std exception\n", stderr);
        return 2;
    }
}

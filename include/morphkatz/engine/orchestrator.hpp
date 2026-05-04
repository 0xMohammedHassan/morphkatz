#pragma once

#include "morphkatz/cli/args.hpp"
#include "morphkatz/common/error.hpp"
#include "morphkatz/report/diff_report.hpp"

#include <memory>

namespace morphkatz::engine {

class Orchestrator {
public:
    explicit Orchestrator(cli::Options opts);
    ~Orchestrator();

    // End-to-end: load -> CFG -> rewrite -> verify -> save -> report.
    Result<void> run();

    // Whole-binary before/after metrics captured during the last run().
    // Valid only after a successful run(); empty (populated=false) before.
    [[nodiscard]] const report::Metrics& metrics() const noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}

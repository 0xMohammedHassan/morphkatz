#pragma once

#include "morphkatz/cli/args.hpp"
#include "morphkatz/common/error.hpp"

namespace morphkatz::scan {

// Dispatcher for `morphkatz scan ...`. Constructs the configured
// scanner, optionally bisects, and writes a JSON or HTML report.
// Mirrors the shape of `morphkatz::engine::run_compare`.
[[nodiscard]] Result<void> run_scan(const cli::ScanOptions& opts);

}

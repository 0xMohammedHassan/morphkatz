#pragma once

#include "morphkatz/cli/args.hpp"
#include "morphkatz/common/error.hpp"

namespace morphkatz::engine {

// Pairwise compare 2..N input files and (optionally) write a JSON or
// HTML report. Dispatcher for the `morphkatz compare` subcommand.
Result<void> run_compare(const cli::CompareOptions& opts);

}

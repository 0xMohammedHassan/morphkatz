#pragma once

#include "morphkatz/cli/args.hpp"
#include "morphkatz/common/error.hpp"

namespace morphkatz::engine {

// Run N deterministic morphs of the same input binary.
//
// Per-variant seed is derived from `opts.seed` (or a fallback constant) via
// splitmix64, guaranteeing distinct streams even for adjacent master seeds.
// Outputs are suffixed with "_v<idx>" (e.g. payload.exe -> payload_v0.exe,
// payload_v1.exe, ...). When --report is set, each variant gets its own
// report file and a rollup summary is written to <report>.summary.json.
//
// Returns the first per-variant error encountered; on success the batch is
// complete and the summary has been written.
Result<void> run_variants(cli::Options opts);

}

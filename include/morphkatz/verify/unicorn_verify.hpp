#pragma once

#include "morphkatz/common/error.hpp"
#include "morphkatz/engine/patcher.hpp"

#include <vector>

namespace morphkatz::format { class PeImage; }

namespace morphkatz::verify {

struct UnicornOptions {
    int  timeout_ms = 5000;
    bool log_first_disagreement = true;
};

// For each patched basic block, emulate original vs patched with identical
// register/memory seed and compare live-out GPRs + flags. Disagreements are
// reported; the orchestrator decides whether to roll back or continue based
// on --profile.
//
// Requires MORPHKATZ_WITH_UNICORN. Otherwise returns NotSupported.
Result<void> unicorn_verify(const format::PeImage& image,
                            const std::vector<engine::AppliedPatch>& applied,
                            const UnicornOptions& opts);

}

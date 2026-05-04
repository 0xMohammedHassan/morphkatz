#pragma once

#include "morphkatz/common/error.hpp"
#include "morphkatz/engine/patcher.hpp"

#include <vector>

namespace morphkatz::format { class PeImage; }

namespace morphkatz::verify {

// Re-disassemble every patched region. Any byte that fails to decode,
// or any instruction whose length crosses the end of the patched region,
// triggers a rollback. Always run when --verify != none.
Result<void> redisasm_check(const format::PeImage& image,
                            const std::vector<engine::AppliedPatch>& applied);

}

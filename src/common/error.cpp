#include "morphkatz/common/error.hpp"

// The Error/Result types are header-only (templates + inline functions).
// This translation unit exists to anchor the build-system list and host
// any future out-of-line helpers.

namespace morphkatz {

// Silence "no public symbols in translation unit" on some toolchains.
[[maybe_unused]] static const char* const kErrorModuleTag = "morphkatz.error";

}

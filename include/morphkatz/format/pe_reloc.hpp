#pragma once

#include "morphkatz/common/error.hpp"

#include <cstdint>
#include <span>
#include <vector>

namespace morphkatz::format {

class PeImage;

// Add IMAGE_REL_BASED_DIR64 relocation entries for the given list of
// target RVAs. The entries are appended to the existing .reloc section
// in place: we write a new IMAGE_BASE_RELOCATION page block (header +
// per-entry uint16_t list) into the slack between the section's
// virtual_size and raw_size, and grow IMAGE_DIRECTORY_ENTRY_BASERELOC
// to include the new bytes.
//
// Errors:
//   NotSupported - .reloc section absent or has no slack big enough
//                  to hold one more page block (caller should fall
//                  back to EP-thunk decoder placement).
//   ParseFormat  - directory or section header malformed.
//
// Implementation note: v1 supports a single page (4 KiB) of new
// targets per call. Mimikatz needs <= 8 entries (the new TLS callback
// array slots), so a single page block is more than sufficient.
[[nodiscard]] Result<void>
add_dir64_relocations(PeImage&                    image,
                      std::span<const uint32_t>   target_rvas);

}

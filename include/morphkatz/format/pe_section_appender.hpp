#pragma once

#include "morphkatz/common/error.hpp"

#include <cstdint>
#include <span>
#include <string>

namespace morphkatz::format {

class PeImage;

// Standard PE section characteristics. Re-stamped here so callers don't
// need to drag in <windows.h>; matches the values from <winnt.h>.
namespace SectionChars {
constexpr uint32_t kCntCode             = 0x00000020u;
constexpr uint32_t kCntInitData         = 0x00000040u;
constexpr uint32_t kCntUninitData       = 0x00000080u;
constexpr uint32_t kMemDiscardable      = 0x02000000u;
constexpr uint32_t kMemNotCached        = 0x04000000u;
constexpr uint32_t kMemNotPaged         = 0x08000000u;
constexpr uint32_t kMemShared           = 0x10000000u;
constexpr uint32_t kMemExecute          = 0x20000000u;
constexpr uint32_t kMemRead             = 0x40000000u;
constexpr uint32_t kMemWrite            = 0x80000000u;
}  // namespace SectionChars

// Information about the section that was just appended. Returned to
// the caller so they can patch references that target the new section
// (e.g. AddressOfEntryPoint into a stub at `virtual_addr + offset`).
struct AppendedSection {
    std::string name;            // truncated to 8 chars, NUL-padded
    uint16_t    section_index = 0;
    uint32_t    raw_offset    = 0;     // file offset of the appended raw data
    uint32_t    raw_size      = 0;     // FileAlignment-rounded size on disk
    uint32_t    virtual_addr  = 0;     // RVA of the section in memory
    uint32_t    virtual_size  = 0;     // unaligned content size
    uint32_t    characteristics = 0;
};

// Append a new section to a PE image. The image's underlying buffer
// (`PeImage::buffer()`) grows by `align(raw.size(), FileAlignment)`
// bytes. The PE headers are mutated in place: a new
// IMAGE_SECTION_HEADER is written into the slack between the section
// table and the first section's raw data, NumberOfSections is bumped,
// SizeOfImage is recomputed, and SizeOfInitializedData / SizeOfCode
// are updated based on `characteristics`.
//
// Errors:
//   ParseFormat  - DOS/PE header malformed
//   NotSupported - raw shellcode (no section table to grow)
//   Invalid      - section table has no slack for one more entry
//                  (caller should bail and tell the user to re-run
//                  without --data-morph; we don't shift section raw
//                  offsets in v1)
[[nodiscard]] Result<AppendedSection>
append_section(PeImage&                 image,
               std::string              name,             // <= 8 ASCII chars
               std::span<const uint8_t> raw,
               uint32_t                 characteristics);

}

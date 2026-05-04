#pragma once

#include "morphkatz/common/error.hpp"

#include <cstdint>
#include <vector>

namespace morphkatz::format {

class PeImage;

// Result of TLS callback inspection. Populated by inspect_tls(). When
// `has_directory` is false, the PE has no IMAGE_DIRECTORY_ENTRY_TLS;
// callers should fall back to EP-thunk placement. When true,
// `existing_callbacks` lists the VAs (image-based) that the loader
// will call before our pass injected anything.
struct TlsState {
    bool                  has_directory      = false;
    uint32_t              tls_struct_rva     = 0;     // RVA of IMAGE_TLS_DIRECTORY64
    uint64_t              address_of_callbacks_va = 0; // current value
    uint32_t              callback_array_rva = 0;     // null on PE32-only path
    std::vector<uint64_t> existing_callbacks;
};

[[nodiscard]] Result<TlsState>
inspect_tls(const PeImage& image);

// Plan the on-disk layout of a new TLS callback array: prepended with
// `our_callback_va`, followed by all existing callbacks, terminated
// with 0. The caller is responsible for placing `bytes` somewhere in
// the appended `.morph` section and reporting back the resulting RVA;
// this helper does NOT mutate the image directly (it's pure planning
// so we can fold the bytes into the existing append_section call).
struct TlsArrayLayout {
    std::vector<uint8_t>  bytes;          // length = (N+2)*8 with terminator
    uint32_t              entry_count = 0; // including our prepended one
};
[[nodiscard]] TlsArrayLayout
plan_tls_callback_array(const TlsState& state, uint64_t our_callback_va);

// Patch the IMAGE_TLS_DIRECTORY64.AddressOfCallBacks field to the new
// VA. The existing relocation entry covering that 8-byte slot still
// applies (loader rebases by adding the load-base delta), so no new
// relocation is needed for the slot itself. Returns NotSupported on
// non-PE images or when the TLS directory is empty.
[[nodiscard]] Result<void>
patch_address_of_callbacks(PeImage& image, uint64_t new_va);

}

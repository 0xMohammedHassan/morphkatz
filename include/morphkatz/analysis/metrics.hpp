#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>

namespace morphkatz::analysis {

// Shannon entropy in bits per byte for the input buffer. Range [0, 8].
// An empty buffer returns 0.
[[nodiscard]] double shannon_entropy(std::span<const uint8_t> data) noexcept;

// SHA-256 of the buffer rendered as 64 lower-case hex characters.
// Thin wrapper over OpenSSL's EVP API.
[[nodiscard]] std::string sha256_hex(std::span<const uint8_t> data);

// Count the number of positions where `before[i] != after[i]`. When the two
// buffers differ in length the extra tail on the longer side is counted as
// changed (matches the intuitive "bytes that are different" interpretation).
[[nodiscard]] size_t byte_diff_count(std::span<const uint8_t> before,
                                     std::span<const uint8_t> after) noexcept;

// Rich header checksum (a.k.a. "RichHash"). Computed on the raw MZ..Rich
// prefix using Microsoft's undocumented per-nibble rotate-add scheme, the
// same algorithm pefile's `RichHeader.checksum` uses. Returns 0 if the
// Rich block is absent or malformed.
[[nodiscard]] uint32_t rich_hash(std::span<const uint8_t> data) noexcept;

}

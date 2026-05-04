#pragma once

#include "morphkatz/common/error.hpp"

#include <cstdint>
#include <filesystem>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace LIEF::PE { class Binary; }
namespace morphkatz::engine { class Rng; }

namespace morphkatz::format {

// Flat view of one executable code region. The patcher sees this; it does
// not need to know about LIEF specifics.
struct CodeSection {
    std::string          name;          // e.g. ".text"
    uint64_t             image_base  = 0;
    uint64_t             virtual_addr= 0;  // RVA added to image_base when disassembling
    uint64_t             virtual_size= 0;
    uint64_t             raw_offset  = 0;  // file offset of the section body
    uint64_t             raw_size    = 0;
    uint32_t             characteristics = 0;
};

// Owning wrapper around an in-memory binary. Supports PE (via LIEF) and raw
// shellcode (the whole file treated as one executable section).
class PeImage {
public:
    PeImage();
    ~PeImage();
    PeImage(const PeImage&)            = delete;
    PeImage& operator=(const PeImage&) = delete;
    PeImage(PeImage&&) noexcept;
    PeImage& operator=(PeImage&&) noexcept;

    static Result<std::unique_ptr<PeImage>> load(const std::filesystem::path& path);
    static Result<std::unique_ptr<PeImage>> from_bytes(std::vector<uint8_t> data, bool is_pe);

    [[nodiscard]] bool is_pe() const noexcept { return is_pe_; }
    [[nodiscard]] uint64_t image_base() const noexcept { return image_base_; }
    [[nodiscard]] uint64_t entry_point_va() const noexcept { return entry_point_va_; }

    // Writable access to the raw file bytes (for patching).
    [[nodiscard]] std::span<uint8_t>       bytes()       noexcept { return {data_.data(), data_.size()}; }
    [[nodiscard]] std::span<const uint8_t> bytes() const noexcept { return {data_.data(), data_.size()}; }

    // Mutable access to the underlying byte buffer. Used by passes
    // that grow the file (e.g. the data-section morphing pass which
    // appends a new section). The cached LIEF view is NOT updated
    // when bytes are appended past `bytes().size()`; downstream
    // consumers must rely on the on-disk image (saved via `save()`)
    // and direct PE-header walks for any post-grow queries.
    [[nodiscard]] std::vector<uint8_t>& buffer() noexcept { return data_; }

    // Patch IMAGE_OPTIONAL_HEADER::AddressOfEntryPoint to the given
    // image-relative virtual address (RVA). Updates the cached
    // entry_point_va_ as well. Returns NotSupported on raw shellcode.
    Result<void> set_entry_point_rva(uint32_t new_rva);

    [[nodiscard]] const std::vector<CodeSection>& code_sections() const noexcept { return code_sections_; }
    [[nodiscard]] std::vector<uint64_t>            code_entry_seeds() const;   // VA seeds for CFG

    // Translate between file offset and virtual address using the section map.
    [[nodiscard]] uint64_t va_to_file(uint64_t va) const noexcept;
    [[nodiscard]] uint64_t file_to_va(uint64_t off) const noexcept;

    Result<void> save(const std::filesystem::path& path) const;

    // PE-only helpers. Noop on raw shellcode.
    Result<void> fix_checksum();
    Result<void> strip_authenticode();
    Result<void> set_timestamp(int64_t unix_ts);
    // Zero or randomize the Rich header (undocumented Microsoft build-ID
    // metadata between the DOS stub and the PE header). `mode` is one of
    // "preserve" (default, no-op), "strip" (zero the block), "randomize"
    // (replace entries with random IDs keyed by the engine RNG).
    Result<void> scrub_rich_header(std::string_view mode, morphkatz::engine::Rng* rng);

    // Access the underlying LIEF binary for advanced callers (e.g. relocation walk).
    [[nodiscard]] LIEF::PE::Binary* lief() const noexcept { return lief_.get(); }

private:
    bool                               is_pe_         = false;
    uint64_t                           image_base_    = 0;
    uint64_t                           entry_point_va_= 0;
    std::vector<uint8_t>               data_;
    std::vector<CodeSection>           code_sections_;
    std::unique_ptr<LIEF::PE::Binary>  lief_;   // null for raw shellcode
};

}

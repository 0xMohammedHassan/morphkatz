#include "morphkatz/format/pe_image.hpp"

#include "morphkatz/common/logging.hpp"
#include "morphkatz/engine/rng.hpp"

#include <LIEF/LIEF.hpp>
#include <LIEF/PE.hpp>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iterator>

#if defined(_WIN32)
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <windows.h>
#  include <imagehlp.h>
#endif

namespace morphkatz::format {

PeImage::PeImage() = default;
PeImage::~PeImage() = default;
PeImage::PeImage(PeImage&&) noexcept = default;
PeImage& PeImage::operator=(PeImage&&) noexcept = default;

namespace {

// `IMAGE_SCN_MEM_EXECUTE` is a macro in <winnt.h> on Windows; fall back to a
// local constexpr on platforms where it isn't already defined (tests, CI on
// non-Windows) so the section-characteristics check compiles everywhere.
#ifndef IMAGE_SCN_MEM_EXECUTE
constexpr uint32_t IMAGE_SCN_MEM_EXECUTE = 0x20000000u;
#endif

std::vector<uint8_t> read_file(const std::filesystem::path& path, Error& out_err) {
    std::ifstream f(path, std::ios::binary);
    if (!f) {
        out_err = Error::make(ErrorKind::Io, "cannot open file", path.string());
        return {};
    }
    std::vector<uint8_t> buf{std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>()};
    if (buf.empty()) {
        out_err = Error::make(ErrorKind::Io, "file is empty", path.string());
    }
    return buf;
}

bool looks_like_pe(std::span<const uint8_t> data) noexcept {
    return data.size() >= 2 && data[0] == 'M' && data[1] == 'Z';
}

// Pre-LIEF compatibility gate. Operates directly on raw PE headers so we
// can bail out before invoking LIEF (silent mis-disassembly of managed PE
// or 32-bit binaries is the single worst existing failure mode). Returns a
// populated `Error` with `NotSupported` kind when the PE cannot be morphed
// by v1.0; returns an `Ok`-kind error ("neutral") when we should defer to
// LIEF's own diagnostics (truncated headers, unknown opt_magic, etc.).
Error check_pe_compat_v10(std::span<const uint8_t> data) noexcept {
    if (data.size() < 0x40) return Error::ok_();

    uint32_t e_lfanew = 0;
    std::memcpy(&e_lfanew, data.data() + 0x3C, sizeof(e_lfanew));
    if (e_lfanew == 0 ||
        static_cast<size_t>(e_lfanew) + 24 > data.size()) {
        return Error::ok_();
    }
    if (data[e_lfanew]     != 'P' || data[e_lfanew + 1] != 'E' ||
        data[e_lfanew + 2] != 0   || data[e_lfanew + 3] != 0) {
        return Error::ok_();
    }

    uint16_t machine = 0;
    std::memcpy(&machine, data.data() + e_lfanew + 4, sizeof(machine));

    constexpr uint16_t kMachineAmd64 = 0x8664;
    if (machine != kMachineAmd64) {
        char buf[256];
        std::snprintf(buf, sizeof(buf),
            "Unsupported PE machine type 0x%04x. v1.0 only handles "
            "x86-64 (AMD64); 32-bit (I386), ARM64, and other targets are "
            "planned - see docs/roadmap.md#multi-arch",
            static_cast<unsigned>(machine));
        return Error::make(ErrorKind::NotSupported, buf);
    }

    const size_t opt_off = static_cast<size_t>(e_lfanew) + 24;
    if (opt_off + 2 > data.size()) return Error::ok_();

    uint16_t opt_magic = 0;
    std::memcpy(&opt_magic, data.data() + opt_off, sizeof(opt_magic));

    // PE32+ -> DataDirectory[] starts at opt_off + 0x70; PE32 -> + 0x60.
    size_t data_dir_off = 0;
    if (opt_magic == 0x020B) {
        data_dir_off = opt_off + 0x70;
    } else if (opt_magic == 0x010B) {
        data_dir_off = opt_off + 0x60;
    } else {
        return Error::ok_();
    }

    // DataDirectory[14] == COM_DESCRIPTOR (CLR runtime header).
    const size_t clr_entry_off = data_dir_off + 14 * 8;
    if (clr_entry_off + 8 > data.size()) return Error::ok_();

    uint32_t clr_rva  = 0;
    uint32_t clr_size = 0;
    std::memcpy(&clr_rva,  data.data() + clr_entry_off,     sizeof(clr_rva));
    std::memcpy(&clr_size, data.data() + clr_entry_off + 4, sizeof(clr_size));
    if (clr_rva != 0 && clr_size != 0) {
        return Error::make(ErrorKind::NotSupported,
            "Managed (.NET) PE detected: COM_DESCRIPTOR data directory is "
            "populated. The .text section holds CLI metadata + IL bytecode "
            "rather than x86 - morphing it would corrupt the assembly. "
            "Support tracked in docs/roadmap.md#dotnet");
    }

    return Error::ok_();
}

}  // namespace

Result<std::unique_ptr<PeImage>> PeImage::load(const std::filesystem::path& path) {
    Error io_err = Error::ok_();
    auto bytes = read_file(path, io_err);
    if (!io_err.ok()) return io_err;

    const bool is_pe = looks_like_pe(bytes);
    return from_bytes(std::move(bytes), is_pe);
}

Result<std::unique_ptr<PeImage>> PeImage::from_bytes(std::vector<uint8_t> data, bool is_pe) {
    auto img = std::make_unique<PeImage>();
    img->data_  = std::move(data);
    img->is_pe_ = is_pe;

    if (!is_pe) {
        // Raw shellcode: treat whole file as one executable section at RVA 0x1000
        // (matches the Python reference's 0x1000 base).
        img->image_base_     = 0x1000;
        img->entry_point_va_ = 0x1000;
        CodeSection s;
        s.name         = ".code";
        s.image_base   = img->image_base_;
        s.virtual_addr = 0;
        s.virtual_size = img->data_.size();
        s.raw_offset   = 0;
        s.raw_size     = img->data_.size();
        s.characteristics = IMAGE_SCN_MEM_EXECUTE;
        img->code_sections_.push_back(std::move(s));
        return std::unique_ptr<PeImage>(std::move(img));
    }

    // v1.0 compatibility gates: refuse .NET and non-AMD64 PEs up-front
    // rather than letting LIEF + Zydis silently mis-disassemble them.
    if (auto compat_err = check_pe_compat_v10(img->data_); !compat_err.ok()) {
        return compat_err;
    }

    std::unique_ptr<LIEF::PE::Binary> pe;
    try {
        pe = LIEF::PE::Parser::parse(img->data_);
    } catch (const std::exception& e) {
        return Error::make(ErrorKind::ParseFormat, e.what());
    }
    if (!pe) {
        return Error::make(ErrorKind::ParseFormat, "LIEF failed to parse PE");
    }

    img->image_base_     = pe->optional_header().imagebase();
    img->entry_point_va_ = img->image_base_ + pe->optional_header().addressof_entrypoint();

    for (const auto& sec : pe->sections()) {
        const uint32_t ch = sec.characteristics();
        if ((ch & IMAGE_SCN_MEM_EXECUTE) == 0) continue;
        CodeSection cs;
        cs.name            = sec.name();
        cs.image_base      = img->image_base_;
        cs.virtual_addr    = sec.virtual_address();
        cs.virtual_size    = sec.virtual_size();
        cs.raw_offset      = sec.pointerto_raw_data();
        cs.raw_size        = sec.sizeof_raw_data();
        cs.characteristics = ch;
        img->code_sections_.push_back(std::move(cs));
    }

    img->lief_ = std::move(pe);

    MK_DEBUG("PE: base=0x{:x} entry=0x{:x} code_sections={}",
              img->image_base_, img->entry_point_va_, img->code_sections_.size());

    return std::unique_ptr<PeImage>(std::move(img));
}

std::vector<uint64_t> PeImage::code_entry_seeds() const {
    std::vector<uint64_t> seeds;
    if (entry_point_va_) seeds.push_back(entry_point_va_);

    if (!lief_) return seeds;

    // LIEF 0.15+ changed get_export() and tls() from returning references to
    // returning nullable pointers (no export table / no TLS directory is a
    // legitimate state). Null-guard before iterating.
    if (const auto* exp_table = lief_->get_export(); exp_table != nullptr) {
        for (const auto& exp : exp_table->entries()) {
            const auto rva = exp.address();
            if (rva) seeds.push_back(image_base_ + rva);
        }
    }
    if (const auto* tls = lief_->tls(); tls != nullptr) {
        for (const auto& cb : tls->callbacks()) {
            if (cb) seeds.push_back(cb);
        }
    }

    std::sort(seeds.begin(), seeds.end());
    seeds.erase(std::unique(seeds.begin(), seeds.end()), seeds.end());
    return seeds;
}

uint64_t PeImage::va_to_file(uint64_t va) const noexcept {
    for (const auto& s : code_sections_) {
        const uint64_t sec_va_start = image_base_ + s.virtual_addr;
        const uint64_t sec_va_end   = sec_va_start + s.virtual_size;
        if (va >= sec_va_start && va < sec_va_end) {
            return s.raw_offset + (va - sec_va_start);
        }
    }
    return UINT64_MAX;
}

uint64_t PeImage::file_to_va(uint64_t off) const noexcept {
    for (const auto& s : code_sections_) {
        if (off >= s.raw_offset && off < s.raw_offset + s.raw_size) {
            return image_base_ + s.virtual_addr + (off - s.raw_offset);
        }
    }
    return UINT64_MAX;
}

Result<void> PeImage::save(const std::filesystem::path& path) const {
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f) {
        return Error::make(ErrorKind::Io, "cannot open output", path.string());
    }
    f.write(reinterpret_cast<const char*>(data_.data()),
            static_cast<std::streamsize>(data_.size()));
    if (!f) {
        return Error::make(ErrorKind::Io, "short write", path.string());
    }
    return {};
}

Result<void> PeImage::fix_checksum() {
#if defined(_WIN32)
    if (!is_pe_) return {};

    DWORD old_sum = 0;
    DWORD new_sum = 0;
    // CheckSumMappedFile walks the mapped view and returns the checksum to
    // splice back into OptionalHeader.CheckSum.
    auto* hdr = ::CheckSumMappedFile(data_.data(),
                                     static_cast<DWORD>(data_.size()),
                                     &old_sum, &new_sum);
    if (!hdr) {
        return Error::make(ErrorKind::ParseFormat, "CheckSumMappedFile failed");
    }
    // CheckSumMappedFile returns a PIMAGE_NT_HEADERS; the CheckSum field
    // lives under OptionalHeader. Older MSVC layouts tolerated the top-level
    // access, newer SDKs (10.0.26100+) flag it correctly.
    hdr->OptionalHeader.CheckSum = new_sum;
    MK_DEBUG("PE: checksum 0x{:08x} -> 0x{:08x}", old_sum, new_sum);
    return {};
#else
    return {};
#endif
}

namespace {

// Decode e_lfanew (offset of the PE signature) from the DOS header. Returns
// SIZE_MAX on malformed input.
size_t pe_header_offset(std::span<const uint8_t> data) noexcept {
    if (data.size() < 0x40) return static_cast<size_t>(-1);
    uint32_t off = 0;
    std::memcpy(&off, data.data() + 0x3c, 4);
    if (off + 24 > data.size()) return static_cast<size_t>(-1);
    if (std::memcmp(data.data() + off, "PE\0\0", 4) != 0) {
        return static_cast<size_t>(-1);
    }
    return off;
}

// Locate the start of the data-directory array. Returns SIZE_MAX if the
// image is truncated or not PE32/PE32+.
size_t data_directory_offset(std::span<const uint8_t> data, size_t pe_off) noexcept {
    const size_t opt_hdr = pe_off + 24;
    if (opt_hdr + 2 > data.size()) return static_cast<size_t>(-1);
    uint16_t magic = 0;
    std::memcpy(&magic, data.data() + opt_hdr, 2);
    size_t off = 0;
    if (magic == 0x10b)       off = opt_hdr + 96;    // PE32
    else if (magic == 0x20b)  off = opt_hdr + 112;   // PE32+
    else                      return static_cast<size_t>(-1);
    if (off + 16 * 8 > data.size()) return static_cast<size_t>(-1);
    return off;
}

}  // namespace

Result<void> PeImage::set_entry_point_rva(uint32_t new_rva) {
    if (data_.size() < 0x40 || data_[0] != 'M' || data_[1] != 'Z') {
        return Error::make(ErrorKind::NotSupported,
            "set_entry_point_rva requires a PE image (no MZ signature)");
    }
    const auto pe_off = pe_header_offset(bytes());
    if (pe_off == static_cast<size_t>(-1)) {
        return Error::make(ErrorKind::ParseFormat, "malformed DOS/PE header");
    }
    // IMAGE_OPTIONAL_HEADER::AddressOfEntryPoint is at:
    //   PE\0\0 (4) + COFF (20) + 16 (offset within OptionalHeader)
    const size_t aep_off = pe_off + 4 + 20 + 16;
    if (aep_off + 4 > data_.size()) {
        return Error::make(ErrorKind::ParseFormat,
            "set_entry_point_rva: optional header truncated");
    }
    std::memcpy(data_.data() + aep_off, &new_rva, 4);
    entry_point_va_ = image_base_ + new_rva;
    MK_DEBUG("PE: AddressOfEntryPoint -> 0x{:x} (VA 0x{:x})",
              new_rva, entry_point_va_);
    return {};
}

Result<void> PeImage::strip_authenticode() {
    if (!is_pe_) return {};
    // Zero the IMAGE_DIRECTORY_ENTRY_SECURITY entry (index 4) and truncate the
    // overlay that the signature occupied, so Windows and tools like sigcheck
    // treat the file as unsigned. We edit `data_` in place — rebuilding
    // through LIEF here would overwrite any previously applied polymorphic
    // patches that live in the same byte buffer.
    const auto pe_off = pe_header_offset(bytes());
    if (pe_off == static_cast<size_t>(-1)) {
        return Error::make(ErrorKind::ParseFormat, "malformed DOS/PE header");
    }
    const auto dd_off = data_directory_offset(bytes(), pe_off);
    if (dd_off == static_cast<size_t>(-1)) {
        return Error::make(ErrorKind::ParseFormat, "missing data directories");
    }
    const size_t sec_entry = dd_off + 4 * 8;   // index 4 = IMAGE_DIRECTORY_ENTRY_SECURITY
    uint32_t sig_off = 0;
    uint32_t sig_sz  = 0;
    std::memcpy(&sig_off, data_.data() + sec_entry + 0, 4);
    std::memcpy(&sig_sz,  data_.data() + sec_entry + 4, 4);
    std::memset(data_.data() + sec_entry, 0, 8);

    // If the signature sits at the very end (the usual case), drop the overlay
    // so the file size matches what tools expect after stripping.
    if (sig_sz && sig_off && static_cast<size_t>(sig_off) + sig_sz == data_.size()) {
        data_.resize(sig_off);
    }
    // LIEF 0.15+ dropped Binary::remove_signature(); the equivalent in
    // 0.17 is iterating signatures() and removing them individually, which
    // would force LIEF to rebuild the PE and clobber our in-place patches.
    // The authoritative mutation is the direct byte edit above; the cached
    // `lief_` Binary is only used read-only downstream (code section
    // enumeration, export/TLS discovery), so leaving its stale signature
    // view in place is harmless.
    MK_DEBUG("PE: Authenticode stripped (dir entry zeroed, overlay {})",
              (sig_sz ? "truncated" : "absent"));
    return {};
}

Result<void> PeImage::set_timestamp(int64_t unix_ts) {
    if (!is_pe_) return {};
    // Patch the 4-byte TimeDateStamp field of IMAGE_FILE_HEADER directly in
    // `data_`. Using LIEF::PE::Builder here would splat LIEF's internal
    // copy of the (pre-patch) bytes over the buffer and silently discard
    // every polymorphic rewrite that Patcher::apply wrote earlier.
    const auto pe_off = pe_header_offset(bytes());
    if (pe_off == static_cast<size_t>(-1)) {
        return Error::make(ErrorKind::ParseFormat, "malformed DOS/PE header");
    }
    const size_t ts_off = pe_off + 8;   // PE\0\0 (4) + Machine (2) + NumberOfSections (2)
    if (ts_off + 4 > data_.size()) {
        return Error::make(ErrorKind::ParseFormat, "header truncated");
    }
    const auto value = static_cast<uint32_t>(unix_ts);
    std::memcpy(data_.data() + ts_off, &value, 4);
    if (lief_) {
        // LIEF 0.15+ renamed the setter from time_date_stamps (plural) to
        // time_date_stamp (singular) on PE::Header.
        try { lief_->header().time_date_stamp(value); } catch (...) {}
    }
    MK_DEBUG("PE: TimeDateStamp set to 0x{:08x} at off=0x{:x}", value, ts_off);
    return {};
}

namespace {

// DanS + Rich markers. See https://bytepointer.com/resources/pietrek_in_depth_ii.htm
// for the (undocumented) format. We search for the "Rich" tag in the DOS
// stub region, walk backwards until we hit "DanS" (XORed with the key), and
// modify bytes in place. The encoding step XORs every dword with the
// 4-byte key that sits in the 8 bytes after the "Rich" tag.
constexpr uint32_t kRichTag = 0x68636952u;   // "Rich" little-endian
constexpr uint32_t kDansTag = 0x536E6144u;   // "DanS" little-endian

// Find the Rich tag position in the first 4 KiB of the file; return SIZE_MAX
// if absent. The Rich header only exists in MSVC-linked binaries.
size_t find_rich(std::span<const uint8_t> data) noexcept {
    const size_t end = std::min<size_t>(data.size(), 0x1000);
    if (end < 8) return static_cast<size_t>(-1);
    for (size_t i = 0x80; i + 8 <= end; i += 4) {
        uint32_t w;
        std::memcpy(&w, data.data() + i, 4);
        if (w == kRichTag) return i;
    }
    return static_cast<size_t>(-1);
}

}  // namespace

Result<void> PeImage::scrub_rich_header(std::string_view mode,
                                        morphkatz::engine::Rng* rng) {
    // The Rich header lives in the DOS stub region and is legal to scrub
    // on any MZ-prefixed buffer, PE or not. We only early-out on the
    // literal "preserve" mode so tests can drive the function against
    // synthetic DOS-like blobs that LIEF would otherwise reject.
    if (mode == "preserve") return {};

    const auto pos = find_rich(bytes());
    if (pos == static_cast<size_t>(-1)) {
        MK_DEBUG("Rich header not found; nothing to do");
        return {};
    }
    if (pos + 8 > data_.size()) {
        return Error::make(ErrorKind::ParseFormat, "Rich header truncated");
    }

    uint32_t key = 0;
    std::memcpy(&key, data_.data() + pos + 4, 4);

    // Scan backwards for the XOR-encoded "DanS" sentinel; no match => nothing
    // to touch (e.g. linker never wrote one).
    size_t dans = static_cast<size_t>(-1);
    for (size_t i = pos; i >= 0x40 && i >= 4; i -= 4) {
        uint32_t w;
        std::memcpy(&w, data_.data() + (i - 4), 4);
        if ((w ^ key) == kDansTag) { dans = i - 4; break; }
        if (i < 4) break;
    }
    if (dans == static_cast<size_t>(-1)) {
        MK_DEBUG("Rich header DanS anchor missing; skipping scrub");
        return {};
    }

    if (mode == "strip") {
        std::memset(data_.data() + dans, 0, (pos + 8) - dans);
        MK_DEBUG("Rich header zeroed: {} bytes at off=0x{:x}",
                  (pos + 8) - dans, dans);
        return {};
    }
    if (mode == "randomize") {
        if (!rng) {
            return Error::make(ErrorKind::Invalid,
                "randomize Rich header requires an RNG");
        }
        // Every pair (compid, count) after "DanS" pads the header. Leave the
        // DanS/Rich sentinels intact to keep PE tooling happy; overwrite only
        // the entries between them.
        const size_t body_begin = dans + 16;     // DanS + 3 pad dwords
        const size_t body_end   = pos;           // just before Rich
        for (size_t i = body_begin; i + 4 <= body_end; i += 4) {
            const uint32_t r = static_cast<uint32_t>(rng->next_u64());
            const uint32_t w = r ^ key;
            std::memcpy(data_.data() + i, &w, 4);
        }
        MK_DEBUG("Rich header randomized: body [0x{:x}..0x{:x}) key=0x{:08x}",
                  body_begin, body_end, key);
        return {};
    }
    return Error::make(ErrorKind::Invalid,
        "rich-header mode must be preserve|strip|randomize");
}

}

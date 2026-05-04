#include "morphkatz/format/pe_tls.hpp"

#include "morphkatz/common/logging.hpp"
#include "morphkatz/format/pe_image.hpp"

#include <algorithm>
#include <cstring>

namespace morphkatz::format {

namespace {

inline uint16_t r16(std::span<const uint8_t> p, size_t o) noexcept {
    return static_cast<uint16_t>(p[o]) |
           (static_cast<uint16_t>(p[o + 1]) << 8);
}
inline uint32_t r32(std::span<const uint8_t> p, size_t o) noexcept {
    return static_cast<uint32_t>(p[o]) |
           (static_cast<uint32_t>(p[o + 1]) << 8) |
           (static_cast<uint32_t>(p[o + 2]) << 16) |
           (static_cast<uint32_t>(p[o + 3]) << 24);
}
inline uint64_t r64(std::span<const uint8_t> p, size_t o) noexcept {
    return static_cast<uint64_t>(r32(p, o)) |
           (static_cast<uint64_t>(r32(p, o + 4)) << 32);
}
inline void w64(std::span<uint8_t> p, size_t o, uint64_t v) noexcept {
    for (int i = 0; i < 8; ++i) {
        p[o + size_t(i)] = static_cast<uint8_t>((v >> (8 * i)) & 0xff);
    }
}

struct PeMeta {
    bool   ok        = false;
    bool   pe32_plus = false;
    size_t opt_off   = 0;
    uint64_t image_base = 0;
};

PeMeta parse_meta(std::span<const uint8_t> data) noexcept {
    PeMeta m;
    if (data.size() < 0x40) return m;
    const uint32_t e_lfanew = r32(data, 0x3c);
    if (e_lfanew + 24 > data.size()) return m;
    if (data[e_lfanew]     != 'P' || data[e_lfanew + 1] != 'E' ||
        data[e_lfanew + 2] != 0   || data[e_lfanew + 3] != 0) return m;
    const size_t opt = e_lfanew + 24;
    if (opt + 32 > data.size()) return m;
    const uint16_t magic = r16(data, opt);
    if (magic == 0x10b) {
        m.pe32_plus  = false;
        m.image_base = r32(data, opt + 28);
    } else if (magic == 0x20b) {
        m.pe32_plus  = true;
        m.image_base = r64(data, opt + 24);
    } else {
        return m;
    }
    m.opt_off = opt;
    m.ok      = true;
    return m;
}

uint32_t tls_dir_rva(std::span<const uint8_t> data, const PeMeta& m) noexcept {
    const size_t dd = m.pe32_plus ? m.opt_off + 112 : m.opt_off + 96;
    if (dd + 9 * 8 + 4 > data.size()) return 0;
    return r32(data, dd + 9 * 8);     // entry 9 = TLS
}

// Walk the section table to translate an RVA to a file offset.
uint64_t rva_to_file(std::span<const uint8_t> data, uint32_t rva) noexcept {
    const uint32_t e_lfanew = r32(data, 0x3c);
    const size_t coff = e_lfanew + 4;
    const uint16_t num_sections = r16(data, coff + 2);
    const uint16_t opt_size     = r16(data, coff + 16);
    const size_t   opt_off      = coff + 20;
    const size_t   sect_off     = opt_off + opt_size;
    for (uint16_t i = 0; i < num_sections; ++i) {
        const size_t off = sect_off + size_t(i) * 40;
        const uint32_t va  = r32(data, off + 12);
        const uint32_t vsz = r32(data, off + 8);
        const uint32_t rsz = r32(data, off + 16);
        const uint32_t rp  = r32(data, off + 20);
        const uint32_t end = va + std::max(vsz, rsz);
        if (rva >= va && rva < end) {
            return uint64_t(rp) + (rva - va);
        }
    }
    return UINT64_MAX;
}

}  // namespace

Result<TlsState> inspect_tls(const PeImage& image) {
    TlsState st;
    const auto data = image.bytes();
    const auto m = parse_meta(data);
    if (!m.ok) {
        return Error::make(ErrorKind::ParseFormat,
            "inspect_tls: not a PE32 / PE32+ image");
    }
    if (!m.pe32_plus) {
        return Error::make(ErrorKind::NotSupported,
            "inspect_tls: PE32 (32-bit) not supported (v1 is x64-only)");
    }
    const uint32_t tls_rva = tls_dir_rva(data, m);
    if (tls_rva == 0) {
        // No TLS directory. Caller falls back to EP-thunk.
        return st;
    }
    st.has_directory   = true;
    st.tls_struct_rva  = tls_rva;
    const uint64_t struct_off = rva_to_file(data, tls_rva);
    if (struct_off == UINT64_MAX || struct_off + 40 > data.size()) {
        return Error::make(ErrorKind::ParseFormat,
            "inspect_tls: TLS directory points outside the file");
    }
    // IMAGE_TLS_DIRECTORY64 layout:
    //   +0  StartAddressOfRawData (VA, 8B)
    //   +8  EndAddressOfRawData   (VA, 8B)
    //   +16 AddressOfIndex        (VA, 8B)
    //   +24 AddressOfCallBacks    (VA, 8B)
    //   +32 SizeOfZeroFill        (4B)
    //   +36 Characteristics       (4B)
    st.address_of_callbacks_va = r64(data, struct_off + 24);
    if (st.address_of_callbacks_va > m.image_base) {
        st.callback_array_rva = static_cast<uint32_t>(
            st.address_of_callbacks_va - m.image_base);
        const uint64_t arr_off = rva_to_file(data, st.callback_array_rva);
        if (arr_off != UINT64_MAX) {
            // Walk the array of VAs until we hit 0 or the bound.
            for (uint32_t i = 0; i < 1024; ++i) {
                if (arr_off + size_t(i) * 8 + 8 > data.size()) break;
                const uint64_t v = r64(data, size_t(arr_off + size_t(i) * 8));
                if (v == 0) break;
                st.existing_callbacks.push_back(v);
            }
        }
    }
    MK_DEBUG("inspect_tls: TLS dir at RVA 0x{:x}, AddressOfCallBacks=0x{:x}, "
             "{} existing callback(s)",
              tls_rva, st.address_of_callbacks_va,
              st.existing_callbacks.size());
    return st;
}

TlsArrayLayout
plan_tls_callback_array(const TlsState& state, uint64_t our_callback_va) {
    TlsArrayLayout out;
    const size_t total =
        static_cast<size_t>(1 + state.existing_callbacks.size() + 1) * 8;
    out.bytes.resize(total, 0);
    std::span<uint8_t> view{out.bytes.data(), out.bytes.size()};
    w64(view, 0, our_callback_va);
    for (size_t i = 0; i < state.existing_callbacks.size(); ++i) {
        w64(view, (i + 1) * 8, state.existing_callbacks[i]);
    }
    // Last 8 bytes are already zero from resize -> null terminator.
    out.entry_count = static_cast<uint32_t>(1 + state.existing_callbacks.size());
    return out;
}

Result<void> patch_address_of_callbacks(PeImage& image, uint64_t new_va) {
    auto& buf = image.buffer();
    const auto m = parse_meta({buf.data(), buf.size()});
    if (!m.ok) {
        return Error::make(ErrorKind::ParseFormat,
            "patch_address_of_callbacks: not a PE32 / PE32+ image");
    }
    if (!m.pe32_plus) {
        return Error::make(ErrorKind::NotSupported,
            "patch_address_of_callbacks: PE32 not supported");
    }
    const uint32_t rva = tls_dir_rva({buf.data(), buf.size()}, m);
    if (rva == 0) {
        return Error::make(ErrorKind::NotSupported,
            "patch_address_of_callbacks: PE has no TLS directory");
    }
    const uint64_t off = rva_to_file({buf.data(), buf.size()}, rva);
    if (off == UINT64_MAX || off + 40 > buf.size()) {
        return Error::make(ErrorKind::ParseFormat,
            "patch_address_of_callbacks: TLS directory truncated");
    }
    std::span<uint8_t> view{buf.data(), buf.size()};
    w64(view, static_cast<size_t>(off + 24), new_va);
    MK_DEBUG("PE: TLS AddressOfCallBacks -> 0x{:x}", new_va);
    return {};
}

}

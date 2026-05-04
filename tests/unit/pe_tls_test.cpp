#include "morphkatz/format/pe_tls.hpp"

#include "morphkatz/format/pe_image.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <memory>
#include <vector>

namespace {

using morphkatz::format::inspect_tls;
using morphkatz::format::patch_address_of_callbacks;
using morphkatz::format::PeImage;
using morphkatz::format::plan_tls_callback_array;
using morphkatz::format::TlsState;

inline void w16(std::vector<uint8_t>& b, size_t o, uint16_t v) {
    b[o]     = static_cast<uint8_t>(v & 0xff);
    b[o + 1] = static_cast<uint8_t>((v >> 8) & 0xff);
}
inline void w32(std::vector<uint8_t>& b, size_t o, uint32_t v) {
    b[o]     = static_cast<uint8_t>(v & 0xff);
    b[o + 1] = static_cast<uint8_t>((v >> 8) & 0xff);
    b[o + 2] = static_cast<uint8_t>((v >> 16) & 0xff);
    b[o + 3] = static_cast<uint8_t>((v >> 24) & 0xff);
}
inline void w64(std::vector<uint8_t>& b, size_t o, uint64_t v) {
    for (int i = 0; i < 8; ++i) {
        b[o + size_t(i)] = static_cast<uint8_t>((v >> (8 * i)) & 0xff);
    }
}
inline uint64_t r64(const std::vector<uint8_t>& b, size_t o) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) {
        v |= static_cast<uint64_t>(b[o + size_t(i)]) << (8 * i);
    }
    return v;
}

constexpr uint64_t kImageBase = 0x00400000ull;
constexpr size_t kElfanew  = 0x80;
constexpr size_t kSectTbl  = 0x188;
constexpr size_t kFileSize = 0x800;

// Synthetic PE32+ with one .rdata section that hosts the TLS directory
// + a callback array. With `tls_present=false`, data dir [9] is left
// at zero and no callback array is laid out.
//
//   .rdata raw=[0x400, 0x600), va=0x2000, vsz=0x200, rsz=0x200
//
// Layout inside .rdata when `tls_present=true`:
//   off 0x000 (rva 0x2000): IMAGE_TLS_DIRECTORY64 (40 bytes)
//                           AddressOfCallBacks = image_base + 0x2040
//   off 0x040 (rva 0x2040): callback array, N existing VAs + null term
struct PeFixture {
    std::vector<uint8_t> bytes;
    uint32_t tls_struct_rva     = 0;
    uint32_t cb_array_rva       = 0;
    uint64_t cb_array_va        = 0;
    std::vector<uint64_t> existing_callbacks;
};

PeFixture make_pe(bool tls_present, size_t num_existing_callbacks = 0) {
    PeFixture pe;
    pe.bytes.assign(kFileSize, 0);
    auto& b = pe.bytes;

    b[0] = 'M'; b[1] = 'Z';
    w32(b, 0x3c, static_cast<uint32_t>(kElfanew));

    b[kElfanew + 0] = 'P';
    b[kElfanew + 1] = 'E';
    b[kElfanew + 2] = 0;
    b[kElfanew + 3] = 0;

    const size_t coff = kElfanew + 4;
    w16(b, coff +  0, 0x8664);
    w16(b, coff +  2, 1);                  // NumberOfSections
    w16(b, coff + 16, 0xF0);
    w16(b, coff + 18, 0x22);

    const size_t opt = coff + 20;
    w16(b, opt + 0, 0x20b);                // PE32+
    w32(b, opt + 24, static_cast<uint32_t>(kImageBase & 0xffffffffu));
    w32(b, opt + 28, static_cast<uint32_t>(kImageBase >> 32));
    w32(b, opt + 32, 0x00001000);          // SectionAlignment
    w32(b, opt + 36, 0x00000200);          // FileAlignment
    w32(b, opt + 56, 0x00004000);          // SizeOfImage
    w32(b, opt + 60, 0x400);               // SizeOfHeaders
    w32(b, opt + 0x6c, 16);                // NumberOfRvaAndSizes

    constexpr uint32_t kRdataChars = 0x40000040u;   // INIT|READ
    auto write_section = [&](size_t off, const char* name,
                             uint32_t vsz, uint32_t va,
                             uint32_t rsz, uint32_t rptr,
                             uint32_t chars) {
        std::memset(b.data() + off, 0, 40);
        std::memcpy(b.data() + off, name, std::min<size_t>(8, std::strlen(name)));
        w32(b, off +  8, vsz);
        w32(b, off + 12, va);
        w32(b, off + 16, rsz);
        w32(b, off + 20, rptr);
        w32(b, off + 36, chars);
    };
    write_section(kSectTbl + 0 * 40, ".rdata",
                  /*vsz=*/0x200, /*va=*/0x2000,
                  /*rsz=*/0x200, /*raw=*/0x400, kRdataChars);

    if (tls_present) {
        // TLS directory entry @ data dir index 9.
        const size_t dd_tls = opt + 112 + 9 * 8;
        const uint32_t tls_struct_rva = 0x2000;
        const uint32_t tls_struct_size = 40;
        w32(b, dd_tls + 0, tls_struct_rva);
        w32(b, dd_tls + 4, tls_struct_size);
        pe.tls_struct_rva = tls_struct_rva;

        // IMAGE_TLS_DIRECTORY64 lives at file offset 0x400 (raw of .rdata).
        const size_t tls_off = 0x400;
        const uint64_t cb_array_va = kImageBase + 0x2040;
        pe.cb_array_rva = 0x2040;
        pe.cb_array_va  = cb_array_va;

        // StartAddressOfRawData / EndAddressOfRawData / AddressOfIndex:
        // We don't care about these for the test; leave zero.
        w64(b, tls_off + 24, cb_array_va);     // AddressOfCallBacks

        // Lay out N existing callbacks at file offset 0x440 + i*8,
        // followed by a null terminator. Use deterministic VAs so we
        // can assert on them.
        const size_t cb_off = 0x440;
        for (size_t i = 0; i < num_existing_callbacks; ++i) {
            const uint64_t va = kImageBase + 0x10000 + i * 0x100;
            w64(b, cb_off + i * 8, va);
            pe.existing_callbacks.push_back(va);
        }
        // Null terminator already zero by buffer init.
    }
    return pe;
}

std::unique_ptr<PeImage> wrap(std::vector<uint8_t>&& bytes) {
    auto r = PeImage::from_bytes(std::move(bytes), false);
    if (!r.ok()) return nullptr;
    return std::move(*r);
}

}  // namespace

TEST_CASE("inspect_tls: PE without TLS directory reports has_directory=false",
          "[format][pe_tls][unit]") {
    auto pe = make_pe(/*tls_present=*/false);
    auto img = wrap(std::move(pe.bytes));
    REQUIRE(img != nullptr);

    auto r = inspect_tls(*img);
    REQUIRE(r.ok());
    CHECK_FALSE(r->has_directory);
    CHECK(r->existing_callbacks.empty());
}

TEST_CASE("inspect_tls: PE with TLS directory but empty callback array",
          "[format][pe_tls][unit]") {
    auto pe = make_pe(/*tls_present=*/true, /*num_existing_callbacks=*/0);
    auto img = wrap(std::move(pe.bytes));
    REQUIRE(img != nullptr);

    auto r = inspect_tls(*img);
    REQUIRE(r.ok());
    REQUIRE(r->has_directory);
    CHECK(r->tls_struct_rva == pe.tls_struct_rva);
    CHECK(r->address_of_callbacks_va == pe.cb_array_va);
    CHECK(r->callback_array_rva == pe.cb_array_rva);
    CHECK(r->existing_callbacks.empty());
}

TEST_CASE("inspect_tls: walks existing callback array",
          "[format][pe_tls][unit]") {
    auto pe = make_pe(/*tls_present=*/true, /*num_existing_callbacks=*/3);
    auto img = wrap(std::move(pe.bytes));
    REQUIRE(img != nullptr);

    auto r = inspect_tls(*img);
    REQUIRE(r.ok());
    REQUIRE(r->has_directory);
    REQUIRE(r->existing_callbacks.size() == 3);
    for (size_t i = 0; i < 3; ++i) {
        CHECK(r->existing_callbacks[i] == pe.existing_callbacks[i]);
    }
}

TEST_CASE("plan_tls_callback_array: prepends our callback and null-terminates",
          "[format][pe_tls][unit]") {
    TlsState st;
    st.has_directory = true;
    st.existing_callbacks = { 0x111111, 0x222222 };

    const uint64_t our_va = 0xCAFEBABEDEADBEEFull;
    auto layout = plan_tls_callback_array(st, our_va);

    REQUIRE(layout.entry_count == 3);                  // 1 ours + 2 existing
    REQUIRE(layout.bytes.size() == (3 + 1) * 8);       // + null terminator

    // Slot 0 = our callback.
    uint64_t v = 0;
    std::memcpy(&v, layout.bytes.data() + 0,  8); CHECK(v == our_va);
    std::memcpy(&v, layout.bytes.data() + 8,  8); CHECK(v == 0x111111u);
    std::memcpy(&v, layout.bytes.data() + 16, 8); CHECK(v == 0x222222u);
    std::memcpy(&v, layout.bytes.data() + 24, 8); CHECK(v == 0u);
}

TEST_CASE("plan_tls_callback_array: empty existing list -> [ours, null]",
          "[format][pe_tls][unit]") {
    TlsState st;
    st.has_directory = true;

    auto layout = plan_tls_callback_array(st, 0xAAAA0000ull);
    REQUIRE(layout.entry_count == 1);
    REQUIRE(layout.bytes.size() == 16);                // 1 entry + null

    uint64_t v = 0;
    std::memcpy(&v, layout.bytes.data() + 0, 8); CHECK(v == 0xAAAA0000ull);
    std::memcpy(&v, layout.bytes.data() + 8, 8); CHECK(v == 0u);
}

TEST_CASE("patch_address_of_callbacks: writes the new VA at struct +24",
          "[format][pe_tls][unit]") {
    auto pe = make_pe(/*tls_present=*/true, /*num_existing_callbacks=*/0);
    auto img = wrap(std::move(pe.bytes));
    REQUIRE(img != nullptr);

    constexpr uint64_t kNewVa = 0x1122334455667788ull;
    auto r = patch_address_of_callbacks(*img, kNewVa);
    REQUIRE(r.ok());

    // The TLS struct lives at file offset 0x400; AddressOfCallBacks is at +24.
    const auto& buf = img->buffer();
    CHECK(r64(buf, 0x400 + 24) == kNewVa);

    // inspect_tls now reflects the patched value.
    auto r2 = inspect_tls(*img);
    REQUIRE(r2.ok());
    CHECK(r2->address_of_callbacks_va == kNewVa);
}

TEST_CASE("patch_address_of_callbacks: refuses when no TLS directory exists",
          "[format][pe_tls][unit]") {
    auto pe = make_pe(/*tls_present=*/false);
    auto img = wrap(std::move(pe.bytes));
    REQUIRE(img != nullptr);

    auto r = patch_address_of_callbacks(*img, 0xCAFEBABE);
    REQUIRE(!r.ok());
    CHECK(r.error().kind == morphkatz::ErrorKind::NotSupported);
}

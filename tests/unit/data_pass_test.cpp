// Round-trip tests for the data-section morphing pass.
//
// We exercise both the manual "wire the pieces yourself" path and
// the full `run_data_pass(..., PassMode::Full)` orchestration. The
// v2 stub no longer requires kernel32!VirtualProtect in the IAT
// (the pass marks the atom-bearing section IMAGE_SCN_MEM_WRITE
// instead), so the synthetic PE - which is too minimal to have a
// real IAT - can drive the full run_data_pass path now. Pre-A.2
// this test could only inline the steps because of the VP
// requirement.

#include "morphkatz/datapass/atom_discovery.hpp"
#include "morphkatz/datapass/decoder_stub.hpp"
#include "morphkatz/datapass/pass.hpp"
#include "morphkatz/format/pe_image.hpp"
#include "morphkatz/format/pe_section_appender.hpp"
#include "morphkatz/scan/bisect.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <memory>
#include <vector>

namespace {

using morphkatz::datapass::AssembledStub;
using morphkatz::datapass::Atom;
using morphkatz::datapass::AtomDiscoveryConfig;
using morphkatz::datapass::build_decoder_stub_ep_thunk;
using morphkatz::datapass::DirEntry;
using morphkatz::datapass::DirHeader;
using morphkatz::datapass::discover_atoms_raw;
using morphkatz::datapass::finalize_stub;
using morphkatz::datapass::kDirMagic;
using morphkatz::datapass::StubFixups;
using morphkatz::format::append_section;
using morphkatz::format::PeImage;
namespace SectionChars = morphkatz::format::SectionChars;
using morphkatz::scan::BisectAnchor;
using morphkatz::scan::ScanRange;

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
inline uint32_t r32(const std::vector<uint8_t>& b, size_t o) {
    return static_cast<uint32_t>(b[o]) |
           (static_cast<uint32_t>(b[o + 1]) << 8) |
           (static_cast<uint32_t>(b[o + 2]) << 16) |
           (static_cast<uint32_t>(b[o + 3]) << 24);
}

constexpr size_t kElfanew  = 0x80;
constexpr size_t kSectTbl  = 0x188;
constexpr size_t kFileSize = 0x800;

// PE layout (header slack 0x200..0x400, plus a small post-section pad):
//   .text  raw=[0x400, 0x500), va=0x1000, vsz=0x100
//   .rdata raw=[0x500, 0x600), va=0x2000, vsz=0x100
struct Synth {
    std::vector<uint8_t> bytes;
    uint64_t atom_offsets[3] = { 0x520, 0x540, 0x560 };
    uint32_t atom_lengths[3] = { 16, 8, 24 };
    static constexpr uint32_t kRdataRva = 0x2000;
    static constexpr uint32_t kRdataRaw = 0x500;
};

Synth make_pe() {
    Synth s;
    s.bytes.assign(kFileSize, 0);
    auto& b = s.bytes;

    b[0] = 'M'; b[1] = 'Z';
    w32(b, 0x3c, static_cast<uint32_t>(kElfanew));

    b[kElfanew + 0] = 'P';
    b[kElfanew + 1] = 'E';
    b[kElfanew + 2] = 0;
    b[kElfanew + 3] = 0;

    const size_t coff = kElfanew + 4;
    w16(b, coff +  0, 0x8664);
    w16(b, coff +  2, 2);
    w16(b, coff + 16, 0xF0);
    w16(b, coff + 18, 0x22);

    const size_t opt = coff + 20;
    w16(b, opt + 0, 0x20b);                // PE32+
    w32(b, opt + 16, 0x1000);              // AddressOfEntryPoint = 0x1000
    w32(b, opt + 24, 0x00400000);          // ImageBase low
    w32(b, opt + 32, 0x00001000);          // SectionAlignment
    w32(b, opt + 36, 0x00000200);          // FileAlignment
    w32(b, opt + 56, 0x00004000);          // SizeOfImage
    w32(b, opt + 60, 0x400);               // SizeOfHeaders
    w32(b, opt + 0x6c, 16);                // NumberOfRvaAndSizes

    constexpr uint32_t kCode  = 0x60000020u;
    constexpr uint32_t kRdata = 0x40000040u;
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
    write_section(kSectTbl + 0 * 40, ".text",
                  /*vsz=*/0x100, /*va=*/0x1000,
                  /*rsz=*/0x100, /*raw=*/0x400, kCode);
    write_section(kSectTbl + 1 * 40, ".rdata",
                  /*vsz=*/0x100, /*va=*/Synth::kRdataRva,
                  /*rsz=*/0x100, /*raw=*/Synth::kRdataRaw, kRdata);

    // Plant the three atom byte sequences inside .rdata so discovery
    // can pick them up and the encoder has something to XOR.
    for (size_t i = 0; i < 3; ++i) {
        const uint8_t fill = static_cast<uint8_t>(0xA0 + i);
        for (uint32_t j = 0; j < s.atom_lengths[i]; ++j) {
            b[s.atom_offsets[i] + j] = fill;
        }
    }
    return s;
}

std::unique_ptr<PeImage> wrap(std::vector<uint8_t>&& bytes) {
    auto r = PeImage::from_bytes(std::move(bytes), false);
    if (!r.ok()) return nullptr;
    return std::move(*r);
}

BisectAnchor anchor_for(uint64_t off, uint32_t len) {
    BisectAnchor a;
    a.status       = morphkatz::scan::BisectResult::Status::Found;
    a.offset       = static_cast<size_t>(off);
    a.length       = len;
    a.section      = ".rdata";
    a.section_kind = "data";
    a.bytes.assign(len, 0);
    ScanRange fr;
    fr.file_offset = static_cast<size_t>(off);
    fr.length      = len;
    a.fragments.push_back(fr);
    return a;
}

}  // namespace

TEST_CASE("data pass: discover -> stub -> append -> XOR -> EP round-trip",
          "[datapass][data_pass][unit]") {
    Synth s = make_pe();
    const auto pre_atom_bytes = s.bytes;     // snapshot for XOR comparison

    auto img = wrap(std::move(s.bytes));
    REQUIRE(img != nullptr);

    // ---- 1) Discover three atoms via the bisect channel -----------------
    std::vector<BisectAnchor> anchors;
    for (size_t i = 0; i < 3; ++i) {
        anchors.push_back(anchor_for(s.atom_offsets[i], s.atom_lengths[i]));
    }
    AtomDiscoveryConfig cfg;
    auto disc = discover_atoms_raw(img->bytes(), /*lief=*/nullptr,
                                   /*yara=*/nullptr, anchors, cfg);
    REQUIRE(disc.ok());
    REQUIRE(disc->atoms.size() == 3);

    // ---- 2) Build the decoder stub --------------------------------------
    constexpr uint32_t kKey = 0x5A;
    auto stub_r = build_decoder_stub_ep_thunk(disc->atoms, kKey);
    REQUIRE(stub_r.ok());
    AssembledStub& stub = *stub_r;
    REQUIRE(stub.atom_count == 3);

    // ---- 3) Translate atom file_offsets to RVAs (.rdata only here) ----
    auto file_to_rva = [&](uint64_t off) -> uint32_t {
        const auto in_rdata = off - Synth::kRdataRaw;
        return Synth::kRdataRva + static_cast<uint32_t>(in_rdata);
    };
    std::array<uint32_t, 3> atom_rvas{
        file_to_rva(s.atom_offsets[0]),
        file_to_rva(s.atom_offsets[1]),
        file_to_rva(s.atom_offsets[2])
    };

    // ---- 4) XOR-encode the atom bytes in place inside the image ---------
    {
        auto& buf = img->buffer();
        const uint8_t key_byte = static_cast<uint8_t>(kKey & 0xff);
        for (size_t i = 0; i < 3; ++i) {
            for (uint32_t j = 0; j < s.atom_lengths[i]; ++j) {
                buf[s.atom_offsets[i] + j] ^= key_byte;
            }
        }
    }

    // ---- 5) Append the .morph section with the stub bytes ---------------
    constexpr uint32_t kChars =
        SectionChars::kCntCode | SectionChars::kCntInitData |
        SectionChars::kMemRead | SectionChars::kMemExecute;
    auto sect_r = append_section(*img, ".morph", stub.bytes, kChars);
    REQUIRE(sect_r.ok());
    const auto& sect = *sect_r;

    // ---- 6) Finalize the stub's three live RIP-relative slots -----------
    //
    // The v2 stub has only three live patch slots (lea_imagebase,
    // lea_dir, jmp_orig); the legacy VP-call slots are reported as 0
    // by the builder and skipped by finalize_stub. We don't need a
    // VirtualProtect IAT at all because the production
    // `mark_atom_sections_writable` step (driven via run_data_pass in
    // the next test) marks .rdata writable so the loader maps it RW.
    constexpr uint32_t kOriginalAep = 0x1000;

    auto disp = [&](uint32_t imm_off, uint32_t target_rva) -> int32_t {
        const uint32_t rip_after = sect.virtual_addr + imm_off + 4;
        return static_cast<int32_t>(target_rva) -
               static_cast<int32_t>(rip_after);
    };

    StubFixups fx{};
    fx.lea_imagebase_off  = stub.patch.lea_imagebase_imm32;
    fx.lea_dir_off        = stub.patch.lea_dir_imm32;
    fx.call_vp_off_1      = stub.patch.call_vp_imm32_1st;   // 0 in v2
    fx.call_vp_off_2      = stub.patch.call_vp_imm32_2nd;   // 0 in v2
    fx.jmp_orig_off       = stub.patch.jmp_orig_imm32;
    // ImageBase = RVA 0; the LEA derives it as `rip_after + disp`.
    fx.imagebase_disp_imm = disp(stub.patch.lea_imagebase_imm32,
                                 /*target_rva=*/0);
    fx.dir_offset_imm     = disp(stub.patch.lea_dir_imm32,
                                 sect.virtual_addr + stub.dir_offset);
    fx.jmp_orig_imm       = disp(stub.patch.jmp_orig_imm32, kOriginalAep);

    auto& buf = img->buffer();
    REQUIRE(sect.raw_offset + stub.bytes.size() <= buf.size());
    std::span<uint8_t> stub_view{ buf.data() + sect.raw_offset,
                                  stub.bytes.size() };
    REQUIRE(finalize_stub(stub_view, fx).ok());

    // ---- 7) Patch DirEntry::target_rva for each atom ----------------------
    for (size_t i = 0; i < 3; ++i) {
        const uint32_t entry_off = stub.dir_entry_offsets[i];
        std::memcpy(stub_view.data() + entry_off, &atom_rvas[i], 4);
    }

    // ---- 8) Patch AddressOfEntryPoint to the stub -----------------------
    REQUIRE(img->set_entry_point_rva(sect.virtual_addr).ok());

    // -----------------------------------------------------------------
    // Assertions: structural invariants that the runtime decoder relies on.
    // -----------------------------------------------------------------
    const auto& after = img->buffer();

    SECTION("PE structural fields") {
        // NumberOfSections went from 2 -> 3.
        const size_t coff = kElfanew + 4;
        const auto num_sections =
            static_cast<uint16_t>(after[coff + 2] |
                                  (uint16_t(after[coff + 3]) << 8));
        CHECK(num_sections == 3);

        // SizeOfImage covers the new section.
        const size_t opt = coff + 20;
        CHECK(r32(after, opt + 56) >=
              sect.virtual_addr + sect.virtual_size);

        // AddressOfEntryPoint == sect.virtual_addr.
        CHECK(r32(after, opt + 16) == sect.virtual_addr);
    }

    SECTION("Atom bytes are XOR-encoded on disk") {
        for (size_t i = 0; i < 3; ++i) {
            const uint8_t key_byte = static_cast<uint8_t>(kKey & 0xff);
            for (uint32_t j = 0; j < s.atom_lengths[i]; ++j) {
                CHECK(after[s.atom_offsets[i] + j] ==
                      static_cast<uint8_t>(pre_atom_bytes[s.atom_offsets[i] + j]
                                           ^ key_byte));
            }
        }
    }

    SECTION("Atom directory was written into the appended section") {
        const size_t hdr_off = sect.raw_offset + stub.dir_offset;
        DirHeader hdr{};
        std::memcpy(&hdr, after.data() + hdr_off, sizeof(hdr));
        CHECK(hdr.magic == kDirMagic);
        CHECK(hdr.count == 3);
        CHECK(hdr.key   == kKey);

        // Each DirEntry: target_rva matches what we just wrote, length
        // equals the atom's length.
        for (size_t i = 0; i < 3; ++i) {
            DirEntry e{};
            std::memcpy(&e,
                        after.data() + sect.raw_offset +
                            stub.dir_entry_offsets[i],
                        sizeof(e));
            CHECK(e.target_rva == atom_rvas[i]);
            CHECK(e.length     == s.atom_lengths[i]);
        }
    }

    SECTION("Stub placeholders were replaced with real displacements") {
        auto rd32 = [&](size_t off) {
            uint32_t v = 0;
            std::memcpy(&v, after.data() + sect.raw_offset + off, 4);
            return v;
        };
        CHECK(rd32(stub.patch.lea_imagebase_imm32) != 0xDEADBEEFu);
        CHECK(rd32(stub.patch.lea_dir_imm32)       != 0xDEADBEEFu);
        CHECK(rd32(stub.patch.jmp_orig_imm32)      != 0xDEADBEEFu);
        // VP slots are no-ops in v2: builder reported them as 0, so we
        // can't probe their displacements (offset 0 is the prologue's
        // `push rbp`, not a placeholder).
        CHECK(stub.patch.call_vp_imm32_1st == 0);
        CHECK(stub.patch.call_vp_imm32_2nd == 0);
    }
}

TEST_CASE("data pass: encode-only mode XORs atoms and skips section/EP",
          "[datapass][data_pass][unit]") {
    // Drives run_data_pass directly in PassMode::EncodeOnly. This works
    // against the synthetic PE (unlike the full pipeline above) because
    // EncodeOnly skips the kernel32!VirtualProtect IAT lookup, the stub
    // emission, the section append, and the EP redirect - it's
    // literally "XOR the atom bytes in place".
    Synth s = make_pe();
    const auto pre = s.bytes;

    auto img = wrap(std::move(s.bytes));
    REQUIRE(img != nullptr);

    std::vector<Atom> atoms;
    atoms.reserve(3);
    for (size_t i = 0; i < 3; ++i) {
        Atom a;
        a.file_offset = s.atom_offsets[i];
        a.length      = s.atom_lengths[i];
        a.section     = ".rdata";
        a.source      = "test";
        a.bytes.assign(s.atom_lengths[i], 0);
        atoms.push_back(std::move(a));
    }

    constexpr uint32_t kKey = 0x42u;
    morphkatz::datapass::DataPassConfig cfg;
    cfg.xor_key = kKey;
    cfg.mode    = morphkatz::datapass::PassMode::EncodeOnly;

    auto rep_r = morphkatz::datapass::run_data_pass(*img, atoms, cfg);
    REQUIRE(rep_r.ok());
    const auto& rep = *rep_r;

    CHECK(rep.encoded);
    CHECK(rep.atoms_encoded == 3);
    CHECK(rep.morph_section_size == 0);
    CHECK(rep.morph_section_rva == 0);
    CHECK_FALSE(rep.entry_point_changed);
    CHECK(rep.decoder_placement == "encode_only");

    const auto& after = img->buffer();

    SECTION("Atom bytes are XOR-encoded on disk") {
        const uint8_t kb = static_cast<uint8_t>(kKey & 0xff);
        for (size_t i = 0; i < 3; ++i) {
            for (uint32_t j = 0; j < s.atom_lengths[i]; ++j) {
                CHECK(after[s.atom_offsets[i] + j] ==
                      static_cast<uint8_t>(pre[s.atom_offsets[i] + j] ^ kb));
            }
        }
    }

    SECTION("PE structure is unchanged: no section appended, EP intact") {
        // Same NumberOfSections (2), same AddressOfEntryPoint (0x1000),
        // same file size as the synthetic. EncodeOnly's whole point is
        // not to alter the PE shape; only the .rdata payload moves.
        const size_t coff = kElfanew + 4;
        const auto num_sections =
            static_cast<uint16_t>(after[coff + 2] |
                                  (uint16_t(after[coff + 3]) << 8));
        CHECK(num_sections == 2);

        const size_t opt = coff + 20;
        CHECK(r32(after, opt + 16) == 0x1000);
        CHECK(after.size() == kFileSize);
    }

    SECTION("XORing again with the same key is a clean round-trip") {
        // The encode-only artifact is non-runnable, but a second pass
        // with the same key should restore the original bytes - this
        // is the property a recovery script (or a future
        // `--data-morph decode-only`) would rely on.
        for (size_t i = 0; i < 3; ++i) {
            for (uint32_t j = 0; j < s.atom_lengths[i]; ++j) {
                img->buffer()[s.atom_offsets[i] + j] ^=
                    static_cast<uint8_t>(kKey & 0xff);
            }
        }
        for (size_t i = 0; i < 3; ++i) {
            for (uint32_t j = 0; j < s.atom_lengths[i]; ++j) {
                CHECK(img->buffer()[s.atom_offsets[i] + j] ==
                      pre[s.atom_offsets[i] + j]);
            }
        }
    }
}

TEST_CASE("data pass: PassMode::Full marks .rdata writable and emits "
          "VP-free stub",
          "[datapass][data_pass][unit]") {
    // End-to-end exercise of `run_data_pass(..., PassMode::Full)`
    // against the synthetic PE. Validates the v2 invariants:
    //   1. .rdata's PE Characteristics gets IMAGE_SCN_MEM_WRITE OR'd in.
    //   2. The appended .morph section's stub bytes contain no
    //      `FF 15` indirect-call shape (no VirtualProtect).
    //   3. The pass succeeds without a kernel32!VirtualProtect import
    //      (the synthetic PE has none).
    Synth s = make_pe();
    auto img = wrap(std::move(s.bytes));
    REQUIRE(img != nullptr);

    // Build atoms by hand (the synthetic PE has no real strings to
    // discover and no YARA rule loaded; we feed the pass the same
    // shape `discover_atoms_raw` would have produced).
    std::vector<Atom> atoms;
    atoms.reserve(3);
    for (size_t i = 0; i < 3; ++i) {
        Atom a;
        a.file_offset = s.atom_offsets[i];
        a.length      = s.atom_lengths[i];
        a.section     = ".rdata";
        a.source      = "test";
        a.bytes.assign(s.atom_lengths[i], 0);
        atoms.push_back(std::move(a));
    }

    constexpr uint32_t kKey = 0x77u;
    morphkatz::datapass::DataPassConfig cfg;
    cfg.xor_key   = kKey;
    cfg.placement = morphkatz::datapass::DecoderPlacement::EpThunk;
    cfg.mode      = morphkatz::datapass::PassMode::Full;

    auto rep_r = morphkatz::datapass::run_data_pass(*img, atoms, cfg);
    REQUIRE(rep_r.ok());
    const auto& rep = *rep_r;

    CHECK(rep.encoded);
    CHECK(rep.atoms_encoded == 3);
    CHECK(rep.entry_point_changed);
    CHECK(rep.decoder_placement == "ep_thunk");
    CHECK(rep.morph_section_size > 0);
    CHECK(rep.morph_section_rva  > 0);

    const auto& after = img->buffer();

    SECTION(".rdata Characteristics gained IMAGE_SCN_MEM_WRITE") {
        // Walk the section table; locate .rdata; verify the writable
        // bit is set.
        const size_t coff = kElfanew + 4;
        const auto opt_size =
            static_cast<uint16_t>(after[coff + 16] |
                                  (uint16_t(after[coff + 17]) << 8));
        const size_t opt_off  = coff + 20;
        const size_t sect_off = opt_off + opt_size;
        const auto num_sections =
            static_cast<uint16_t>(after[coff + 2] |
                                  (uint16_t(after[coff + 3]) << 8));
        bool found_rdata = false;
        for (uint16_t i = 0; i < num_sections; ++i) {
            const size_t off = sect_off + size_t(i) * 40;
            std::string n;
            for (int k = 0; k < 8; ++k) {
                const auto c = static_cast<char>(after[off + size_t(k)]);
                if (c == 0) break;
                n.push_back(c);
            }
            if (n == ".rdata") {
                const uint32_t chars = r32(after, off + 36);
                CHECK((chars & 0x80000000u) != 0);
                found_rdata = true;
            }
        }
        CHECK(found_rdata);
    }

    SECTION("Stub bytes have no `FF 15` indirect call (no VirtualProtect)") {
        // The .morph section starts at rep.morph_section_rva (RVA).
        // Translate to file offset by walking the section table.
        const size_t coff = kElfanew + 4;
        const auto opt_size =
            static_cast<uint16_t>(after[coff + 16] |
                                  (uint16_t(after[coff + 17]) << 8));
        const size_t sect_off = coff + 20 + opt_size;
        const auto num_sections =
            static_cast<uint16_t>(after[coff + 2] |
                                  (uint16_t(after[coff + 3]) << 8));
        size_t   morph_raw_off = 0;
        uint32_t morph_raw_sz  = 0;
        for (uint16_t i = 0; i < num_sections; ++i) {
            const size_t off = sect_off + size_t(i) * 40;
            const uint32_t va  = r32(after, off + 12);
            if (va == rep.morph_section_rva) {
                morph_raw_sz  = r32(after, off + 16);
                morph_raw_off = r32(after, off + 20);
                break;
            }
        }
        REQUIRE(morph_raw_off > 0);
        REQUIRE(morph_raw_sz  > 0);
        REQUIRE(morph_raw_off + morph_raw_sz <= after.size());

        // The stub prefix is everything before the directory header.
        // We don't know dir_offset from outside, so we conservatively
        // scan the whole appended payload - the directory itself is
        // pure data and never contains `FF 15` by accident (the
        // 16-byte DirHeader starts with the 'XKPM' magic 0x4D504B58
        // = bytes 58 4B 50 4D, and DirEntry rows are
        // {target_rva, length} which would only collide if a
        // target_rva ended in 0xFF15 - improbable for our synthetic
        // RVAs in [0x2000, 0x2100)).
        for (size_t i = 0;
             i + 6 <= morph_raw_sz;
             ++i) {
            const uint8_t b0 = after[morph_raw_off + i + 0];
            const uint8_t b1 = after[morph_raw_off + i + 1];
            CHECK_FALSE((b0 == 0xFF && b1 == 0x15));
        }
    }

    SECTION("Atoms are XOR-encoded on disk") {
        // pre-XOR bytes are 0xA0/0xA1/0xA2 fills (see make_pe());
        // post-XOR bytes are those XORed with the low key byte.
        const uint8_t kb = static_cast<uint8_t>(kKey & 0xff);
        for (size_t i = 0; i < 3; ++i) {
            const uint8_t pre_byte = static_cast<uint8_t>(0xA0 + i);
            const uint8_t expected = static_cast<uint8_t>(pre_byte ^ kb);
            for (uint32_t j = 0; j < s.atom_lengths[i]; ++j) {
                CHECK(after[s.atom_offsets[i] + j] == expected);
            }
        }
    }
}

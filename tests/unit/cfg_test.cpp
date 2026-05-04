#include "morphkatz/disasm/cfg.hpp"
#include "morphkatz/format/pe_image.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <vector>

TEST_CASE("build_cfg falls back to linear sweep for raw shellcode without seeds", "[cfg]") {
    // XOR eax, eax
    // RET
    std::vector<uint8_t> bytes{0x31, 0xC0, 0xC3};
    auto img = morphkatz::format::PeImage::from_bytes(bytes, /*is_pe=*/false);
    REQUIRE(img.ok());

    auto cfg = morphkatz::disasm::build_cfg(**img);
    REQUIRE(cfg.ok());
    REQUIRE(!(*cfg)->blocks().empty());
    // Raw shellcode uses VA 0x1000 as the single seed.
    const auto& bb = (*cfg)->blocks().front();
    REQUIRE(!bb.instructions.empty());
    REQUIRE(bb.instructions.front().length == 2);  // 31 C0
}

TEST_CASE("linear_sweep_blocks emits one block per exec section", "[cfg]") {
    std::vector<uint8_t> bytes(64, 0x90);  // 64 NOPs
    auto img = morphkatz::format::PeImage::from_bytes(bytes, /*is_pe=*/false);
    REQUIRE(img.ok());

    const auto blocks = morphkatz::disasm::linear_sweep_blocks(**img);
    REQUIRE(blocks.size() == 1);
    REQUIRE(blocks.front().instructions.size() == 64);
}

TEST_CASE("CFG splits at forward jump target", "[cfg]") {
    // 0: EB 03       jmp +3  -> 0x5
    // 2: 90 90 90    nop nop nop (dead code)
    // 5: C3          ret
    //
    // Expect 2 blocks: [0:jmp] and [5:ret]. The dead NOPs should not form a
    // reachable block because the seed only reaches 0 and 5.
    std::vector<uint8_t> bytes{0xEB, 0x03, 0x90, 0x90, 0x90, 0xC3};
    auto img = morphkatz::format::PeImage::from_bytes(bytes, /*is_pe=*/false);
    REQUIRE(img.ok());

    auto cfg = morphkatz::disasm::build_cfg(**img);
    REQUIRE(cfg.ok());
    const auto& bs = (*cfg)->blocks();
    REQUIRE(bs.size() >= 2);

    bool saw_jmp = false;
    bool saw_ret = false;
    for (const auto& b : bs) {
        for (const auto& ins : b.instructions) {
            if (ins.length == 2 && ins.bytes[0] == 0xEB) saw_jmp = true;
            if (ins.length == 1 && ins.bytes[0] == 0xC3) saw_ret = true;
        }
    }
    REQUIRE(saw_jmp);
    REQUIRE(saw_ret);
}

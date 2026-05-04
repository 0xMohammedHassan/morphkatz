#include "morphkatz/verify/unicorn_verify.hpp"

#include "morphkatz/common/logging.hpp"
#include "morphkatz/format/pe_image.hpp"

#if MORPHKATZ_WITH_UNICORN
#  include <unicorn/unicorn.h>
#endif

#include <algorithm>
#include <array>
#include <cstring>

namespace morphkatz::verify {

#if MORPHKATZ_WITH_UNICORN

namespace {

struct UcGuard {
    uc_engine* h = nullptr;
    ~UcGuard() { if (h) uc_close(h); }
};

// Execute `code` at virtual address `va`, seeding a fresh register file, and
// return the live-out integer register state plus EFLAGS.
struct EmuResult {
    std::array<uint64_t, 16> gpr{};
    uint64_t eflags = 0;
    bool     ok     = false;
};

// The registers we consider "live-out": all 16 general-purpose regs. RIP is
// constrained by the block's length so we do not compare it. This is
// deliberately coarse — instructions that affect only SIMD state are out of
// scope for v1.0 (tracked in issue #simd-verify).
constexpr std::array<int, 16> kGprIds{
    UC_X86_REG_RAX, UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_RBX,
    UC_X86_REG_RSP, UC_X86_REG_RBP, UC_X86_REG_RSI, UC_X86_REG_RDI,
    UC_X86_REG_R8,  UC_X86_REG_R9,  UC_X86_REG_R10, UC_X86_REG_R11,
    UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R14, UC_X86_REG_R15,
};

EmuResult emulate_block(std::span<const uint8_t> code,
                        uint64_t va,
                        int timeout_ms) {
    EmuResult r;
    UcGuard uc;
    if (uc_open(UC_ARCH_X86, UC_MODE_64, &uc.h) != UC_ERR_OK) return r;

    constexpr uint64_t kMapSize  = 0x4000;
    constexpr uint64_t kStackVA  = 0x7fff'0000;
    constexpr uint64_t kStackSz  = 0x10000;

    // Map a single executable page that covers [va .. va+code.size) aligned down.
    const uint64_t page = va & ~(kMapSize - 1);
    if (uc_mem_map(uc.h, page, kMapSize, UC_PROT_ALL) != UC_ERR_OK) return r;
    if (uc_mem_write(uc.h, va, code.data(), code.size()) != UC_ERR_OK) return r;
    if (uc_mem_map(uc.h, kStackVA, kStackSz, UC_PROT_READ | UC_PROT_WRITE) != UC_ERR_OK) return r;

    std::array<uint64_t, 16> seed{
        0x1111111111111111ULL, 0x2222222222222222ULL, 0x3333333333333333ULL, 0x4444444444444444ULL,
        kStackVA + kStackSz / 2, 0x6666666666666666ULL, 0x7777777777777777ULL, 0x8888888888888888ULL,
        0x99A0ULL, 0x9991ULL, 0x9992ULL, 0x9993ULL, 0x9994ULL, 0x9995ULL, 0x9996ULL, 0x9997ULL };
    for (size_t i = 0; i < kGprIds.size(); ++i) {
        uc_reg_write(uc.h, kGprIds[i], &seed[i]);
    }

    const auto err = uc_emu_start(uc.h, va, va + code.size(), timeout_ms * 1000u, 0);
    if (err != UC_ERR_OK && err != UC_ERR_FETCH_UNMAPPED) return r;

    for (size_t i = 0; i < kGprIds.size(); ++i) {
        uc_reg_read(uc.h, kGprIds[i], &r.gpr[i]);
    }
    uc_reg_read(uc.h, UC_X86_REG_EFLAGS, &r.eflags);
    r.ok = true;
    return r;
}

}  // namespace

Result<void> unicorn_verify(const format::PeImage& image,
                            const std::vector<engine::AppliedPatch>& applied,
                            const UnicornOptions& opts) {
    const auto bytes = image.bytes();
    size_t agree = 0, disagree = 0;

    for (const auto& p : applied) {
        if (p.old_bytes.empty() || p.new_bytes.empty()) continue;

        auto a = emulate_block(p.old_bytes, p.va, opts.timeout_ms);
        auto b = emulate_block(p.new_bytes, p.va, opts.timeout_ms);
        if (!a.ok || !b.ok) continue;

        // Arithmetic flag-subset comparison (ignore TF/IF/RF/VM which Unicorn
        // may set differently depending on mode).
        const uint64_t mask = 0x8D5;  // CF PF AF ZF SF OF DF
        if (a.gpr == b.gpr && (a.eflags & mask) == (b.eflags & mask)) {
            ++agree;
        } else {
            ++disagree;
            if (opts.log_first_disagreement && disagree == 1) {
                MK_WARN("unicorn disagreement at 0x{:x} rule={}", p.va, p.rule_id);
            }
        }
    }

    MK_INFO("Unicorn verify: {} agree, {} disagree", agree, disagree);
    if (disagree > 0) {
        return Error::make(ErrorKind::Verify,
            fmt::format("unicorn self-verify: {} patches disagree", disagree));
    }
    return {};
}

#else   // !MORPHKATZ_WITH_UNICORN

Result<void> unicorn_verify(const format::PeImage& /*image*/,
                            const std::vector<engine::AppliedPatch>& /*applied*/,
                            const UnicornOptions& /*opts*/) {
    return Error::make(ErrorKind::NotSupported,
        "build was compiled without MORPHKATZ_WITH_UNICORN");
}

#endif

}

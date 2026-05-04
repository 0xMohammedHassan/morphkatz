#include "morphkatz/verify/re_disasm_check.hpp"

#include "morphkatz/common/logging.hpp"
#include "morphkatz/disasm/decoder.hpp"
#include "morphkatz/format/pe_image.hpp"

#include <algorithm>
#include <span>

namespace morphkatz::verify {

Result<void> redisasm_check(const format::PeImage& image,
                            const std::vector<engine::AppliedPatch>& applied) {
    disasm::Decoder dec;
    const auto bytes = image.bytes();
    size_t ok = 0, bad = 0;

    for (const auto& p : applied) {
        if (p.file_offset + p.new_bytes.size() > bytes.size()) {
            MK_WARN("re-disasm: patch out of range at 0x{:x} rule={}",
                     p.file_offset, p.rule_id);
            ++bad;
            continue;
        }
        std::span<const uint8_t> span{bytes.data() + p.file_offset, p.new_bytes.size()};
        size_t consumed = 0;
        bool   local_ok = true;
        while (consumed < span.size()) {
            ir::Instruction ins;
            const auto r = disasm::decode_one(
                span.subspan(consumed), p.va + consumed, p.file_offset + consumed, ins);
            if (!r.ok() || ins.length == 0) { local_ok = false; break; }
            consumed += ins.length;
        }
        if (local_ok && consumed == span.size()) {
            ++ok;
        } else {
            ++bad;
            MK_WARN("re-disasm failed at 0x{:x} rule={} consumed={}/{}",
                     p.va, p.rule_id, consumed, span.size());
        }
    }

    if (bad > 0) {
        return Error::make(ErrorKind::Verify,
            fmt::format("re-disasm: {} of {} patches failed to re-decode", bad, ok + bad));
    }
    MK_INFO("Re-disasm check: {} patches OK", ok);
    return {};
}

}

#include "morphkatz/scan/defender_target.hpp"

#include "morphkatz/common/logging.hpp"
#include "morphkatz/scan/pe_scan_ranges.hpp"
#include "morphkatz/scan/threat_classify.hpp"

#include <algorithm>
#include <fstream>
#include <iterator>
#include <unordered_set>
#include <utility>

namespace morphkatz::scan {

namespace {

Result<std::vector<uint8_t>> slurp(const std::filesystem::path& p) {
    std::ifstream f(p, std::ios::binary);
    if (!f) {
        return Error::make(ErrorKind::Io, "cannot open file", p.string());
    }
    std::vector<uint8_t> buf{
        std::istreambuf_iterator<char>(f),
        std::istreambuf_iterator<char>()
    };
    return buf;
}

}  // namespace

struct DefenderTarget::Impl {
    std::filesystem::path             target_path;
    std::vector<uint8_t>              target_bytes;
    std::shared_ptr<IDefenderScanner> scanner;
    std::string                       engine_label;
    bool                              probed = false;

    std::vector<Threat>          pre_threats;
    std::vector<Anchor>          anchors;
};

DefenderTarget::DefenderTarget() : impl_(std::make_unique<Impl>()) {}
DefenderTarget::~DefenderTarget() = default;
DefenderTarget::DefenderTarget(DefenderTarget&&) noexcept = default;
DefenderTarget& DefenderTarget::operator=(DefenderTarget&&) noexcept = default;

Result<DefenderTarget> DefenderTarget::from_file(
        std::filesystem::path           target,
        std::shared_ptr<IDefenderScanner> scanner) {
    if (!scanner) {
        return Error::make(ErrorKind::Invalid,
            "DefenderTarget requires a non-null scanner");
    }
    DefenderTarget t;
    auto buf = slurp(target);
    if (!buf.ok()) return buf.error();
    t.impl_->target_bytes = std::move(*buf);
    t.impl_->target_path  = std::move(target);
    t.impl_->engine_label = scanner->engine_label();
    t.impl_->scanner      = std::move(scanner);
    return t;
}

Result<void> DefenderTarget::probe() {
    if (impl_->probed) return {};

    auto verdict = impl_->scanner->scan_file(impl_->target_path);
    if (!verdict.ok()) return verdict.error();

    impl_->pre_threats = verdict->threats;
    if (!verdict->infected) {
        // Nothing to learn from a clean reference. The orchestrator
        // can still post-scan, just without prior anchors.
        impl_->probed = true;
        MK_INFO("DefenderTarget: reference is clean, skipping bisect");
        return {};
    }

    MultiBisectOptions bopts;
    bopts.name_hint                = impl_->target_path.filename().string();
    bopts.pe_image_for_section_map = impl_->target_bytes;

    // Use PE-aware scoped bisection by default. Falls back to legacy
    // slice-and-scan for non-PE targets (compute_pe_scan_ranges
    // returns an empty vector). Scope `Sections` masks only inside
    // section payloads minus parsed data-directory windows so the
    // scanner always receives a structurally valid PE.
    auto ranges_r = compute_pe_scan_ranges(impl_->target_bytes,
                                           ScanScope::Sections);
    if (!ranges_r.ok()) return ranges_r.error();
    bopts.scan_ranges = std::move(*ranges_r);
    if (!bopts.scan_ranges.empty()) {
        size_t scope_bytes = 0;
        for (const auto& r : bopts.scan_ranges) scope_bytes += r.length;
        MK_INFO("DefenderTarget: scoped bisect ranges={} bytes={}",
                bopts.scan_ranges.size(), scope_bytes);
    } else {
        MK_INFO("DefenderTarget: non-PE or unparseable target; "
                "falling back to legacy slice-and-scan");
    }

    auto br = bisect_multi(*impl_->scanner,
                           std::span<const uint8_t>(impl_->target_bytes),
                           bopts);
    if (!br.ok()) {
        // Bisection IO failure is fatal; ML/Clean/MidpointSpan are not.
        return br.error();
    }

    const std::string default_threat =
        impl_->pre_threats.empty() ? std::string{}
                                   : impl_->pre_threats.front().name;

    for (const auto& sub : br->anchors) {
        Anchor a;
        a.bytes        = sub.bytes;
        a.file_offset  = sub.offset;
        a.section      = sub.section;
        a.section_kind = sub.section_kind;
        a.status       = sub.status;
        // We don't have per-anchor threat attribution from
        // bisect_multi - all anchors share the input verdict's threats
        // unless a specific peel narrowed them. Use the first
        // pre-threat name as a stable default; the report block also
        // exposes the full pre/post lists.
        a.threat_name  = default_threat;
        impl_->anchors.push_back(std::move(a));
        MK_INFO("DefenderTarget: anchor at +0x{:x} ({} bytes) section={} status={}",
                sub.offset, sub.length,
                sub.section.empty() ? "?" : sub.section,
                static_cast<int>(sub.status));
    }

    if (br->status == MultiBisectResult::Status::MlDetection &&
        impl_->anchors.empty()) {
        MK_WARN("DefenderTarget: detection is !ml, no byte anchors learned");
    }
    MK_INFO("DefenderTarget: bisect status={} anchors={} scans={}",
            static_cast<int>(br->status),
            impl_->anchors.size(),
            br->scan_count);

    impl_->probed = true;
    return {};
}

double DefenderTarget::priority_for_va(uint64_t va,
                                       std::span<const uint8_t> old_bytes,
                                       std::span<const uint8_t> new_bytes) const noexcept {
    (void)new_bytes;  // Defender doesn't care what we replace with - any
                      // mutation to the anchor window helps.
    if (impl_->anchors.empty() || old_bytes.empty()) return 0.0;

    // Treat `va` as a file offset for boost lookup. The orchestrator's
    // rule matcher passes physical-offset-aligned addresses through the
    // same code path it uses for YARA; mixing VA vs RVA is a known
    // calibration knob across the codebase.
    const uint64_t lo = va;
    const uint64_t hi = va + old_bytes.size();

    // Additive boost (matches yara_target::PriorityMap::boost_for
    // convention): final weight = base * (1 + sum of boosts), so a
    // confirmed Defender anchor gets a 4x multiplier and a midpoint-
    // span anchor gets 2x relative to the unboosted weight.
    double best = 0.0;
    for (const auto& a : impl_->anchors) {
        const uint64_t a_lo = a.file_offset;
        const uint64_t a_hi = a.file_offset + a.bytes.size();
        if (lo < a_hi && a_lo < hi) {
            const double boost = (a.status == BisectResult::Status::Found)
                ? 3.0 : 1.0;
            best = std::max(best, boost);
        }
    }
    return best;
}

Result<DefenderTarget::DiffStats>
DefenderTarget::evaluate_after_mutation(const std::filesystem::path& mutated_path) {
    if (!impl_->probed) {
        return Error::make(ErrorKind::Invalid,
            "DefenderTarget::evaluate_after_mutation called before probe()");
    }
    auto verdict = impl_->scanner->scan_file(mutated_path);
    if (!verdict.ok()) return verdict.error();

    DiffStats out;
    std::unordered_set<std::string> pre_names;
    for (const auto& t : impl_->pre_threats) pre_names.insert(t.name);
    std::unordered_set<std::string> post_names;
    for (const auto& t : verdict->threats) post_names.insert(t.name);

    for (const auto& n : pre_names) {
        if (post_names.find(n) == post_names.end()) out.broken.push_back(n);
        else                                         out.persisted.push_back(n);
    }
    for (const auto& n : post_names) {
        if (pre_names.find(n) == pre_names.end()) out.introduced.push_back(n);
    }
    std::sort(out.broken.begin(),     out.broken.end());
    std::sort(out.persisted.begin(),  out.persisted.end());
    std::sort(out.introduced.begin(), out.introduced.end());
    return out;
}

const std::vector<Threat>& DefenderTarget::pre_threats() const noexcept {
    return impl_->pre_threats;
}
const std::vector<DefenderTarget::Anchor>& DefenderTarget::anchors() const noexcept {
    return impl_->anchors;
}
const std::string& DefenderTarget::engine_label() const noexcept {
    return impl_->engine_label;
}
bool DefenderTarget::probed() const noexcept { return impl_->probed; }

}

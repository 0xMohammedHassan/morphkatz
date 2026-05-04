#include "morphkatz/engine/patcher.hpp"

#include "morphkatz/common/logging.hpp"
#include "morphkatz/disasm/cfg.hpp"
#include "morphkatz/engine/pad_policy.hpp"
#include "morphkatz/format/pe_image.hpp"
#include "morphkatz/report/diff_report.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <deque>
#include <unordered_map>
#include <vector>

namespace morphkatz::engine {

namespace {

// Minimal Aho-Corasick automaton specialised for byte alphabets. Built on
// demand for the set of (from,to) raw-byte pairs queued via queue_raw(); the
// in-place "I know the file offset" path bypasses this.
class Aho {
public:
    void add(std::vector<uint8_t> pattern, std::vector<uint8_t> replacement, std::string rule_id) {
        patterns_.push_back({std::move(pattern), std::move(replacement), std::move(rule_id)});
    }
    void build() {
        nodes_.clear();
        // Upper bound on trie size: one node per byte across all patterns,
        // plus the root. Reserving once lets us safely hold references into
        // `nodes_` during insertion; otherwise each push_back may reallocate
        // the underlying storage and invalidate any cached `go`-map reference
        // (this was a latent bug that crashed every raw-rule scan).
        size_t upper = 1;
        for (const auto& p : patterns_) upper += p.from.size();
        nodes_.reserve(upper);
        nodes_.push_back({});
        for (size_t pi = 0; pi < patterns_.size(); ++pi) {
            uint32_t n = 0;
            for (uint8_t c : patterns_[pi].from) {
                auto& go = nodes_[n].go;
                auto  it = go.find(c);
                if (it == go.end()) {
                    const uint32_t next = static_cast<uint32_t>(nodes_.size());
                    nodes_.push_back({});
                    // `go` references the reserved storage; still valid
                    // because the push_back cannot reallocate.
                    go.emplace(c, next);
                    n = next;
                } else {
                    n = it->second;
                }
            }
            nodes_[n].match = static_cast<int32_t>(pi);
        }
        std::deque<uint32_t> q;
        for (auto& [c, n] : nodes_[0].go) {
            nodes_[n].fail = 0;
            q.push_back(n);
        }
        while (!q.empty()) {
            const auto u = q.front(); q.pop_front();
            for (auto& [c, v] : nodes_[u].go) {
                auto f = nodes_[u].fail;
                while (f != UINT32_MAX) {
                    auto it = nodes_[f].go.find(c);
                    if (it != nodes_[f].go.end()) { nodes_[v].fail = it->second; break; }
                    if (f == 0) { nodes_[v].fail = 0; break; }
                    f = nodes_[f].fail;
                }
                if (nodes_[nodes_[v].fail].match >= 0 && nodes_[v].match < 0) {
                    nodes_[v].match = nodes_[nodes_[v].fail].match;
                }
                q.push_back(v);
            }
        }
    }

    struct Hit { size_t file_off; size_t pattern_index; };

    [[nodiscard]] std::vector<Hit> scan(std::span<const uint8_t> haystack,
                                        size_t base_file_off) const {
        std::vector<Hit> hits;
        uint32_t n = 0;
        for (size_t i = 0; i < haystack.size(); ++i) {
            const uint8_t c = haystack[i];
            while (true) {
                auto it = nodes_[n].go.find(c);
                if (it != nodes_[n].go.end()) { n = it->second; break; }
                if (n == 0) break;
                n = nodes_[n].fail;
            }
            if (nodes_[n].match >= 0) {
                const auto& pat = patterns_[static_cast<size_t>(nodes_[n].match)];
                const size_t start = i + 1 - pat.from.size();
                hits.push_back({base_file_off + start, static_cast<size_t>(nodes_[n].match)});
            }
        }
        return hits;
    }

    [[nodiscard]] const auto& patterns() const noexcept { return patterns_; }

private:
    struct Node {
        std::unordered_map<uint8_t, uint32_t> go;
        uint32_t fail = UINT32_MAX;
        int32_t  match = -1;
    };
    struct Pat {
        std::vector<uint8_t> from;
        std::vector<uint8_t> to;
        std::string          rule_id;
    };
    std::vector<Node> nodes_;
    std::vector<Pat>  patterns_;
};

struct QueuedDirect {
    uint64_t file_off = 0;
    uint64_t va       = 0;
    std::vector<uint8_t> old_bytes;
    std::vector<uint8_t> new_bytes;   // already padded to old length
    std::string rule_id;
    std::string block_id;
};

}  // namespace

struct Patcher::Impl {
    std::vector<QueuedDirect> direct;
    Aho                       aho;
    bool                      aho_dirty = false;

    // Rule id -> observed file offsets, to suppress duplicate direct/raw hits.
    std::unordered_map<uint64_t, std::string> file_off_to_rule;
};

Patcher::Patcher() : impl_(std::make_unique<Impl>()) {}
Patcher::~Patcher() = default;

void Patcher::queue_block(const disasm::BasicBlock& block,
                          std::vector<rules::Candidate> chosen,
                          PadPolicy& pad,
                          report::DiffReport& report) {
    for (auto& cand : chosen) {
        QueuedDirect q;
        q.file_off = cand.source.file_off;
        q.va       = cand.source.va;
        q.old_bytes.assign(cand.source.bytes.data(),
                           cand.source.bytes.data() + cand.source.length);
        q.rule_id  = cand.rule->id;
        q.block_id = block.id();

        std::vector<uint8_t> body = std::move(cand.new_bytes);
        const int delta = static_cast<int>(cand.source.length) - static_cast<int>(body.size());
        auto padded = pad.pad(body, delta);
        if (!padded.ok()) {
            MK_TRACE("pad rejected (delta={}) rule={} at va=0x{:x}",
                      delta, q.rule_id, q.va);
            continue;
        }
        q.new_bytes = std::move(*padded);
        report.record_direct(q.va, q.file_off, q.old_bytes, q.new_bytes, q.rule_id);
        impl_->direct.push_back(std::move(q));
    }
}

void Patcher::queue_raw(std::span<const uint8_t> from,
                        std::span<const uint8_t> to,
                        std::string rule_id) {
    if (from.empty() || from.size() != to.size()) {
        MK_WARN("raw rule {}: size mismatch or empty pattern; skipped", rule_id);
        return;
    }
    impl_->aho.add(std::vector<uint8_t>(from.begin(), from.end()),
                   std::vector<uint8_t>(to.begin(),   to.end()),
                   std::move(rule_id));
    impl_->aho_dirty = true;
}

size_t Patcher::queued_count() const noexcept {
    return impl_->direct.size() + impl_->aho.patterns().size();
}

size_t Patcher::rollback(format::PeImage& image,
                         std::span<const AppliedPatch> applied) {
    auto bytes = image.bytes();
    size_t restored = 0;
    // Walk in reverse to undo overlapping patches in the order opposite to
    // application. For the current design direct and raw patches never
    // overlap, but reverse order is the safer default.
    for (auto it = applied.rbegin(); it != applied.rend(); ++it) {
        const auto& ap = *it;
        const auto off = static_cast<size_t>(ap.file_offset);
        if (off + ap.old_bytes.size() > bytes.size()) continue;
        std::memcpy(bytes.data() + off, ap.old_bytes.data(), ap.old_bytes.size());
        ++restored;
    }
    return restored;
}

std::vector<AppliedPatch> Patcher::apply(format::PeImage& image,
                                        report::DiffReport* report) {
    std::vector<AppliedPatch> out;
    auto bytes = image.bytes();

    // 1) Direct-offset patches (from own disassembly). Resolve collisions by
    //    first-writer-wins and by matching the old bytes exactly (lossy =
    //    something already changed).
    for (const auto& q : impl_->direct) {
        if (q.file_off + q.new_bytes.size() > bytes.size()) continue;
        const auto off = static_cast<size_t>(q.file_off);
        const bool match_old = std::equal(q.old_bytes.begin(), q.old_bytes.end(),
                                          bytes.begin() + off);
        if (!match_old) {
            MK_TRACE("skip rule {} at off=0x{:x}: bytes already mutated",
                      q.rule_id, q.file_off);
            continue;
        }
        std::memcpy(bytes.data() + off, q.new_bytes.data(), q.new_bytes.size());
        AppliedPatch ap;
        ap.file_offset = q.file_off;
        ap.va          = q.va;
        ap.old_bytes   = q.old_bytes;
        ap.new_bytes   = q.new_bytes;
        ap.rule_id     = q.rule_id;
        ap.block_id    = q.block_id;
        out.push_back(std::move(ap));
    }

    // 2) Raw-byte rules via Aho-Corasick, scanning only executable sections.
    if (impl_->aho_dirty) {
        impl_->aho.build();
        impl_->aho_dirty = false;
    }
    if (!impl_->aho.patterns().empty()) {
        for (const auto& sec : image.code_sections()) {
            if (sec.raw_offset + sec.raw_size > bytes.size()) continue;
            auto body = std::span<const uint8_t>(bytes.data() + sec.raw_offset, sec.raw_size);
            for (const auto& hit : impl_->aho.scan(body, sec.raw_offset)) {
                const auto& pat = impl_->aho.patterns()[hit.pattern_index];
                const auto off = hit.file_off;
                if (off + pat.from.size() > bytes.size()) continue;
                if (!std::equal(pat.from.begin(), pat.from.end(), bytes.begin() + off)) continue;
                std::memcpy(bytes.data() + off, pat.to.data(), pat.to.size());
                AppliedPatch ap;
                ap.file_offset = off;
                ap.va          = image.file_to_va(off);
                ap.old_bytes.assign(pat.from.begin(), pat.from.end());
                ap.new_bytes.assign(pat.to.begin(),   pat.to.end());
                ap.rule_id     = pat.rule_id;
                if (report) {
                    report->record_direct(ap.va, ap.file_offset,
                                          ap.old_bytes, ap.new_bytes, ap.rule_id);
                }
                out.push_back(std::move(ap));
            }
        }
    }

    return out;
}

}

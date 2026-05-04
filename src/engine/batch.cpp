#include "morphkatz/engine/batch.hpp"

#include "morphkatz/common/logging.hpp"
#include "morphkatz/engine/orchestrator.hpp"
#include "morphkatz/report/diff_report.hpp"

#include <nlohmann/json.hpp>

#include <filesystem>
#include <fstream>
#include <string>
#include <unordered_set>
#include <vector>

namespace morphkatz::engine {

namespace {

// Splitmix64 — tiny, well-known seed mixer. Produces statistically
// independent u64 streams from adjacent counter values, so two users
// running with seed 0 vs seed 1 still get totally different morphs.
//
// Reference: Steele/Lea/Flood "Fast splittable pseudorandom number
// generators" (OOPSLA 2014).
uint64_t splitmix64(uint64_t& state) noexcept {
    uint64_t z = (state += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

// Insert a "_v<idx>" stem suffix before the extension. For "foo.exe" with
// idx=3 this returns "foo_v3.exe". For an extensionless path it simply
// appends the suffix.
std::filesystem::path suffix_variant(const std::filesystem::path& p, int idx) {
    const auto parent = p.parent_path();
    const auto stem   = p.stem().string();
    const auto ext    = p.extension().string();
    std::string fname = stem + "_v" + std::to_string(idx) + ext;
    return parent.empty() ? std::filesystem::path{fname} : parent / fname;
}

nlohmann::json metrics_to_json(const report::Metrics& m) {
    return {
        {"bytes_changed",     m.bytes_changed},
        {"bytes_total",       m.bytes_total},
        {"bytes_changed_pct", m.bytes_changed_pct},
        {"entropy_before",    m.entropy_before},
        {"entropy_after",     m.entropy_after},
        {"sha256_before",     m.sha256_before},
        {"sha256_after",      m.sha256_after},
        {"richhash_before",   m.richhash_before},
        {"richhash_after",    m.richhash_after},
    };
}

}  // namespace

Result<void> run_variants(cli::Options opts) {
    const int n = std::max(1, opts.variants);

    // Root of the splitmix64 stream. If the user didn't pass --seed we
    // still use a fixed sentinel so the *derivation* is deterministic
    // given the same invocation; the sentinel below was produced once
    // from std::random_device during development and never rotates.
    uint64_t seed_state = opts.seed.value_or(0xD1B54A32D192ED03ULL);

    MK_INFO("Batch mode: emitting {} variant(s) from seed {}",
            n,
            opts.seed ? std::to_string(*opts.seed) : std::string("<default>"));

    const auto base_output = opts.output;
    const auto base_report = opts.report_path;

    nlohmann::json summary = {
        {"tool",     "morphkatz"},
        {"input",    opts.input.string()},
        {"count",    n},
        {"variants", nlohmann::json::array()},
    };

    std::unordered_set<std::string> unique_sha;
    unique_sha.reserve(static_cast<size_t>(n));

    for (int i = 0; i < n; ++i) {
        cli::Options vopts = opts;
        const uint64_t v_seed = splitmix64(seed_state);
        vopts.seed     = v_seed;
        vopts.variants = 1;                 // prevent recursion
        vopts.in_place = false;             // never overwrite input in batch
        vopts.backup   = false;             // one .bak per batch at most
        vopts.output   = suffix_variant(base_output, i);
        vopts.report_path = base_report
            ? std::optional<std::filesystem::path>{suffix_variant(*base_report, i)}
            : std::nullopt;

        // Only the first variant writes the backup — all subsequent ones
        // read the same input, so repeated .bak writes are wasteful.
        if (i == 0) vopts.backup = opts.backup;

        Orchestrator orch(vopts);
        if (auto r = orch.run(); !r.ok()) {
            return Error::make(r.error().kind,
                "variant " + std::to_string(i) + " failed: " + r.error().what,
                r.error().where);
        }

        const auto& m = orch.metrics();
        if (!m.sha256_after.empty()) unique_sha.insert(m.sha256_after);

        nlohmann::json entry = {
            {"index",   i},
            {"seed",    v_seed},
            {"output",  vopts.output.string()},
            {"report",  vopts.report_path
                           ? vopts.report_path->string()
                           : std::string{}},
        };
        if (m.populated) {
            entry["metrics"] = metrics_to_json(m);
        }
        summary["variants"].push_back(std::move(entry));
    }

    summary["distinct_sha256_count"] = unique_sha.size();

    // Aggregate min/max/mean of the per-variant change percentage so a
    // quick `jq .summary_stats` call answers "did this run actually
    // produce diverse morphs?".
    double min_pct = 0.0, max_pct = 0.0, sum_pct = 0.0;
    int populated_count = 0;
    for (const auto& v : summary["variants"]) {
        if (!v.contains("metrics")) continue;
        const double pct = v["metrics"]["bytes_changed_pct"].get<double>();
        if (populated_count == 0) { min_pct = max_pct = pct; }
        else {
            if (pct < min_pct) min_pct = pct;
            if (pct > max_pct) max_pct = pct;
        }
        sum_pct += pct;
        ++populated_count;
    }
    summary["summary_stats"] = {
        {"min_bytes_changed_pct",  populated_count ? min_pct : 0.0},
        {"max_bytes_changed_pct",  populated_count ? max_pct : 0.0},
        {"mean_bytes_changed_pct", populated_count ? sum_pct / populated_count : 0.0},
    };

    if (base_report) {
        auto summary_path = *base_report;
        summary_path += ".summary.json";
        std::ofstream f(summary_path, std::ios::trunc);
        if (!f) {
            return Error::make(ErrorKind::Io,
                "cannot write batch summary",
                summary_path.string());
        }
        f << summary.dump(2);
        MK_INFO("Batch summary: {} ({} distinct output SHA-256)",
                summary_path.string(), unique_sha.size());
    } else {
        MK_INFO("Batch complete: {} distinct output SHA-256 "
                "(pass --report to persist the rollup)",
                unique_sha.size());
    }

    return {};
}

}

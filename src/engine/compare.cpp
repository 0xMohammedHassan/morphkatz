#include "morphkatz/engine/compare.hpp"

#include "morphkatz/analysis/binary_diff.hpp"
#include "morphkatz/common/logging.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <sstream>
#include <string>
#include <unordered_set>
#include <vector>

namespace morphkatz::engine {

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

nlohmann::json profile_to_json(const analysis::ByteProfile& p,
                               const std::filesystem::path& path) {
    return {
        {"path",     path.string()},
        {"size",     p.size},
        {"sha256",   p.sha256},
        {"entropy",  p.entropy},
        {"richhash", p.richhash},
    };
}

nlohmann::json diff_to_json(size_t i, size_t j, const analysis::BinaryDiff& d) {
    return {
        {"a",                 i},
        {"b",                 j},
        {"aligned_bytes",     std::min(d.a.size, d.b.size)},
        {"aligned_bytes_diff", d.aligned_bytes_diff},
        {"aligned_bytes_same", d.aligned_bytes_same},
        {"aligned_hamming_pct", d.aligned_hamming_pct},
        {"histogram_cosine",  d.histogram_cosine},
        {"alphabet_jaccard",  d.alphabet_jaccard},
        {"size_delta",        static_cast<int64_t>(d.b.size) -
                              static_cast<int64_t>(d.a.size)},
    };
}

std::string build_html(const std::vector<std::filesystem::path>& paths,
                       const std::vector<analysis::ByteProfile>& profiles,
                       const std::vector<analysis::BinaryDiff>&  pairs,
                       size_t distinct_sha) {
    std::ostringstream os;
    os << R"(<!doctype html><html lang="en"><head>
<meta charset="utf-8"><title>MorphKatz compare</title>
<style>
body{font-family:system-ui,sans-serif;margin:2rem;color:#1b1b1f;}
h1{margin-bottom:.25rem}h2{margin-top:2rem}
table{border-collapse:collapse;margin:.5rem 0}
th,td{border:1px solid #d1d5db;padding:.35rem .6rem;font-variant-numeric:tabular-nums}
th{background:#f3f4f6;text-align:left}
code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.9em}
.small{color:#6b7280;font-size:.85em}
</style></head><body>)";
    os << "<h1>MorphKatz compare</h1>";
    os << "<p class=\"small\">" << paths.size()
       << " inputs, " << distinct_sha << " distinct SHA-256.</p>";

    os << "<h2>Inputs</h2><table><thead><tr>"
          "<th>#</th><th>path</th><th>size</th><th>entropy</th>"
          "<th>sha256</th><th>rich</th></tr></thead><tbody>";
    for (size_t i = 0; i < profiles.size(); ++i) {
        const auto& p = profiles[i];
        os << "<tr><td>" << i << "</td><td><code>" << paths[i].string()
           << "</code></td><td>" << p.size << "</td><td>"
           << p.entropy << "</td><td><code>" << p.sha256
           << "</code></td><td>" << p.richhash << "</td></tr>";
    }
    os << "</tbody></table>";

    os << "<h2>Pairwise diff</h2><table><thead><tr>"
          "<th>a</th><th>b</th><th>|&Delta;| bytes</th>"
          "<th>hamming %</th><th>histogram cosine</th>"
          "<th>alphabet jaccard</th></tr></thead><tbody>";
    for (const auto& d : pairs) {
        // Indices are recoverable from (a.size, b.size, a.sha256, b.sha256)
        // only statistically, so just stream the diffs in insertion order
        // which mirrors the JSON "pairs" ordering.
        os << "<tr><td><code>" << d.a.sha256.substr(0, 12)
           << "</code></td><td><code>" << d.b.sha256.substr(0, 12)
           << "</code></td><td>" << d.aligned_bytes_diff << "</td><td>"
           << d.aligned_hamming_pct << "</td><td>"
           << d.histogram_cosine << "</td><td>"
           << d.alphabet_jaccard << "</td></tr>";
    }
    os << "</tbody></table></body></html>";
    return os.str();
}

}  // namespace

Result<void> run_compare(const cli::CompareOptions& opts) {
    if (opts.inputs.size() < 2) {
        return Error::make(ErrorKind::Invalid,
            "compare: need at least 2 inputs");
    }
    MK_INFO("Compare mode: {} inputs", opts.inputs.size());

    std::vector<analysis::ByteProfile> profiles;
    profiles.reserve(opts.inputs.size());
    for (const auto& p : opts.inputs) {
        auto r = slurp(p);
        if (!r.ok()) return r.error();
        profiles.push_back(analysis::profile_bytes(*r));
    }

    // Re-read each file only once for aligned-byte pairs (we already have
    // the profile, but diff_bytes() needs the raw spans for hamming).
    // Keep the buffers alive for the duration of the pairwise loop.
    std::vector<std::vector<uint8_t>> buffers;
    buffers.reserve(opts.inputs.size());
    for (const auto& p : opts.inputs) {
        auto r = slurp(p);
        if (!r.ok()) return r.error();
        buffers.push_back(std::move(*r));
    }

    std::vector<analysis::BinaryDiff> pairs;
    pairs.reserve(opts.inputs.size() * (opts.inputs.size() - 1) / 2);
    for (size_t i = 0; i < buffers.size(); ++i) {
        for (size_t j = i + 1; j < buffers.size(); ++j) {
            pairs.push_back(analysis::diff_bytes(buffers[i], buffers[j]));
        }
    }

    std::unordered_set<std::string> distinct;
    for (const auto& p : profiles) distinct.insert(p.sha256);

    // Stdout summary: one row per pair. Keeps the tool useful without
    // --report for quick eyeballing.
    std::printf("compare: %zu files, %zu distinct SHA-256\n",
                opts.inputs.size(), distinct.size());
    size_t k = 0;
    for (size_t i = 0; i < opts.inputs.size(); ++i) {
        for (size_t j = i + 1; j < opts.inputs.size(); ++j) {
            const auto& d = pairs[k++];
            std::printf("  [%zu]<->[%zu]  hamming %.2f%%  "
                        "cosine %.4f  jaccard %.4f  dsize %+lld\n",
                        i, j,
                        d.aligned_hamming_pct,
                        d.histogram_cosine,
                        d.alphabet_jaccard,
                        static_cast<long long>(
                            static_cast<int64_t>(d.b.size) -
                            static_cast<int64_t>(d.a.size)));
        }
    }

    if (opts.report_path) {
        const auto& rp = *opts.report_path;
        nlohmann::json j = {
            {"tool",                  "morphkatz"},
            {"mode",                  "compare"},
            {"distinct_sha256_count", distinct.size()},
            {"inputs",                nlohmann::json::array()},
            {"pairs",                 nlohmann::json::array()},
        };
        for (size_t i = 0; i < opts.inputs.size(); ++i) {
            j["inputs"].push_back(
                profile_to_json(profiles[i], opts.inputs[i]));
        }
        k = 0;
        for (size_t i = 0; i < opts.inputs.size(); ++i) {
            for (size_t jj = i + 1; jj < opts.inputs.size(); ++jj) {
                j["pairs"].push_back(diff_to_json(i, jj, pairs[k++]));
            }
        }

        const auto ext = rp.extension().string();
        std::ofstream f(rp, std::ios::trunc);
        if (!f) {
            return Error::make(ErrorKind::Io,
                "cannot write compare report", rp.string());
        }
        if (ext == ".html" || ext == ".htm") {
            f << build_html(opts.inputs, profiles, pairs, distinct.size());
        } else {
            f << j.dump(2);
        }
        MK_INFO("Compare report: {}", rp.string());
    }

    return {};
}

}

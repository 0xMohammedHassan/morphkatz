#include "morphkatz/scan/scan_subcommand.hpp"

#include "morphkatz/analysis/metrics.hpp"
#include "morphkatz/common/logging.hpp"
#include "morphkatz/scan/bisect.hpp"
#include "morphkatz/scan/mpcmdrun_scanner.hpp"
#include "morphkatz/scan/pe_scan_ranges.hpp"
#include "morphkatz/scan/preconditions.hpp"
#include "morphkatz/scan/threat_classify.hpp"

#include <nlohmann/json.hpp>

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <sstream>
#include <string>
#include <utility>

namespace morphkatz::scan {

namespace {

const char* status_name(BisectResult::Status s) noexcept {
    switch (s) {
        case BisectResult::Status::Found:        return "found";
        case BisectResult::Status::Clean:        return "clean";
        case BisectResult::Status::MlDetection:  return "ml_detection";
        case BisectResult::Status::MidpointSpan: return "midpoint_span";
        case BisectResult::Status::NoOp:         return "noop";
    }
    return "unknown";
}

// Map a CLI scope string to the typed enum. Returns std::nullopt for
// the sentinel "raw" value so callers can skip computing ranges (the
// bisect then falls back to legacy slice-and-scan).
std::optional<ScanScope> parse_scope(std::string_view s) noexcept {
    if (s == "sections")     return ScanScope::Sections;
    if (s == "sections-all") return ScanScope::SectionsAll;
    if (s == "code")         return ScanScope::CodeOnly;
    if (s == "data")         return ScanScope::DataOnly;
    if (s == "raw")          return ScanScope::Raw;
    return std::nullopt;
}

size_t total_range_bytes(const std::vector<ScanRange>& v) noexcept {
    size_t n = 0;
    for (const auto& r : v) n += r.length;
    return n;
}

const char* multi_status_name(MultiBisectResult::Status s) noexcept {
    switch (s) {
        case MultiBisectResult::Status::Done:             return "done";
        case MultiBisectResult::Status::ExhaustedAnchors: return "exhausted_anchors";
        case MultiBisectResult::Status::ExhaustedScans:   return "exhausted_scans";
        case MultiBisectResult::Status::Clean:            return "clean";
        case MultiBisectResult::Status::MlDetection:      return "ml_detection";
        case MultiBisectResult::Status::NoOp:             return "noop";
    }
    return "unknown";
}

std::string hex_of(std::span<const uint8_t> bytes, size_t cap) {
    std::ostringstream os;
    const size_t n = std::min(bytes.size(), cap);
    for (size_t i = 0; i < n; ++i) {
        if (i) os << ' ';
        char buf[3] = {};
        std::snprintf(buf, sizeof(buf), "%02x", bytes[i]);
        os << buf;
    }
    if (n < bytes.size()) os << " ...";
    return os.str();
}

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

nlohmann::json verdict_to_json(const ScanVerdict& v) {
    auto threats = nlohmann::json::array();
    for (const auto& t : v.threats) {
        threats.push_back({
            {"name",     t.name},
            {"severity", t.severity},
            {"is_ml",    t.is_ml},
            {"is_pua",   t.is_pua},
        });
    }
    return {
        {"infected",      v.infected},
        {"threats",       std::move(threats)},
        {"engine",        v.engine_version},
        {"vdm",           v.vdm_version},
        {"elapsed_ms",    v.elapsed.count()},
        {"raw_exit_code", v.raw_exit_code},
    };
}

nlohmann::json fragments_to_json(const std::vector<ScanRange>& frags) {
    auto arr = nlohmann::json::array();
    for (const auto& f : frags) {
        arr.push_back({{"file_offset", f.file_offset},
                       {"length",      f.length}});
    }
    return arr;
}

nlohmann::json bisect_to_json(const BisectResult& b) {
    return {
        {"status",      status_name(b.status)},
        {"offset",      b.offset},
        {"length",      b.length},
        {"section",     b.section},
        {"section_kind",b.section_kind},
        {"fragments",   fragments_to_json(b.fragments)},
        {"scan_count",  b.scan_count},
        {"elapsed_ms",  b.elapsed.count()},
        {"hex",         hex_of(b.bytes, 64)},
        {"midpoint_span_warning",
                        b.status == BisectResult::Status::MidpointSpan},
    };
}

nlohmann::json multi_bisect_to_json(const MultiBisectResult& mb) {
    auto anchors = nlohmann::json::array();
    for (const auto& a : mb.anchors) {
        anchors.push_back({
            {"status",       status_name(a.status)},
            {"offset",       a.offset},
            {"length",       a.length},
            {"section",      a.section},
            {"section_kind", a.section_kind},
            {"fragments",    fragments_to_json(a.fragments)},
            {"hex",          hex_of(a.bytes, 64)},
        });
    }
    return {
        {"mode",       "all"},
        {"status",     multi_status_name(mb.status)},
        {"anchors",    std::move(anchors)},
        {"scan_count", mb.scan_count},
        {"elapsed_ms", mb.elapsed.count()},
    };
}

std::string build_html(const cli::ScanOptions& opts,
                       const DefenderState&    state,
                       const ScanVerdict&      verdict,
                       const std::optional<BisectResult>&      bisect_opt,
                       const std::optional<MultiBisectResult>& multi_opt,
                       size_t                                  scope_bytes) {
    std::ostringstream os;
    os << R"(<!doctype html><html lang="en"><head>
<meta charset="utf-8"><title>MorphKatz scan</title>
<style>
body{font-family:system-ui,sans-serif;margin:2rem;color:#1b1b1f;}
h1{margin-bottom:.25rem}h2{margin-top:1.5rem}
table{border-collapse:collapse;margin:.5rem 0}
th,td{border:1px solid #d1d5db;padding:.35rem .6rem;font-variant-numeric:tabular-nums}
th{background:#f3f4f6;text-align:left}
code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.9em}
.bad{color:#b91c1c;font-weight:600}
.ok{color:#15803d;font-weight:600}
.small{color:#6b7280;font-size:.85em}
</style></head><body>)";
    os << "<h1>MorphKatz scan</h1>";
    os << "<p class=\"small\">Engine: <code>MpCmdRun-Tier1</code></p>";

    os << "<h2>Input</h2><table><tr><th>path</th><td><code>"
       << opts.input.string() << "</code></td></tr></table>";

    os << "<h2>Verdict</h2><p>";
    if (verdict.infected) {
        os << "<span class=\"bad\">INFECTED</span> - "
           << verdict.threats.size() << " threat(s)";
    } else {
        os << "<span class=\"ok\">CLEAN</span>";
    }
    os << "</p>";

    if (!verdict.threats.empty()) {
        os << "<table><thead><tr><th>name</th><th>severity</th><th>ml</th>"
           << "<th>pua</th></tr></thead><tbody>";
        for (const auto& t : verdict.threats) {
            os << "<tr><td><code>" << t.name << "</code></td><td>"
               << t.severity << "</td><td>" << (t.is_ml ? "yes" : "")
               << "</td><td>" << (t.is_pua ? "yes" : "") << "</td></tr>";
        }
        os << "</tbody></table>";
    }

    if (bisect_opt) {
        const auto& b = *bisect_opt;
        os << "<h2>Bisection (single anchor)</h2><table>"
           << "<tr><th>scope</th><td>" << opts.bisect_scope
           << " (" << scope_bytes << " bytes)</td></tr>"
           << "<tr><th>status</th><td>" << status_name(b.status) << "</td></tr>"
           << "<tr><th>offset</th><td>0x" << std::hex << b.offset << std::dec << "</td></tr>"
           << "<tr><th>length</th><td>" << b.length << " bytes</td></tr>"
           << "<tr><th>fragments</th><td>" << b.fragments.size() << "</td></tr>"
           << "<tr><th>section</th><td>" << b.section << " (" << b.section_kind << ")</td></tr>"
           << "<tr><th>scans</th><td>" << b.scan_count << "</td></tr>"
           << "<tr><th>elapsed</th><td>" << b.elapsed.count() << " ms</td></tr>"
           << "<tr><th>hex</th><td><code>" << hex_of(b.bytes, 64) << "</code></td></tr>"
           << "</table>";
    }

    if (multi_opt) {
        const auto& m = *multi_opt;
        os << "<h2>Bisection (multi-anchor)</h2>"
           << "<p class=\"small\">scope=<code>" << opts.bisect_scope
           << "</code> (" << scope_bytes << " bytes) &middot; status=<code>"
           << multi_status_name(m.status)
           << "</code> &middot; anchors=" << m.anchors.size()
           << " &middot; scans=" << m.scan_count
           << " &middot; elapsed=" << m.elapsed.count() << " ms</p>";
        if (!m.anchors.empty()) {
            os << "<table><thead><tr>"
               << "<th>#</th><th>status</th><th>offset</th><th>length</th>"
               << "<th>section</th><th>hex</th></tr></thead><tbody>";
            size_t i = 0;
            for (const auto& a : m.anchors) {
                os << "<tr><td>" << ++i << "</td>"
                   << "<td>" << status_name(a.status) << "</td>"
                   << "<td>0x" << std::hex << a.offset << std::dec << "</td>"
                   << "<td>" << a.length << "</td>"
                   << "<td>" << a.section << " (" << a.section_kind << ")</td>"
                   << "<td><code>" << hex_of(a.bytes, 48) << "</code></td>"
                   << "</tr>";
            }
            os << "</tbody></table>";
        }
    }

    os << "<h2>Defender preferences</h2><pre>" << state_to_string(state) << "</pre>";
    (void)state;
    os << "</body></html>";
    return os.str();
}

}  // namespace

Result<void> run_scan(const cli::ScanOptions& opts) {
    if (opts.engine != "cli") {
        return Error::make(ErrorKind::NotSupported,
            "scan: --engine '" + opts.engine + "' is reserved for v0.2; "
            "use --engine cli for now");
    }
    if (opts.bisect_mode != "single" && opts.bisect_mode != "all") {
        return Error::make(ErrorKind::NotSupported,
            "scan: --bisect-mode '" + opts.bisect_mode +
            "' is unknown; use 'single' or 'all'");
    }
    const auto scope = parse_scope(opts.bisect_scope);
    if (!scope) {
        return Error::make(ErrorKind::NotSupported,
            "scan: --bisect-scope '" + opts.bisect_scope +
            "' is unknown; use sections, sections-all, code, data, or raw");
    }

    MK_INFO("Scan mode: input={} bisect={} bisect_mode={} bisect_scope={}",
            opts.input.string(), opts.bisect, opts.bisect_mode,
            opts.bisect_scope);

    MpCmdRunScanner::Options sopts;
    if (opts.mpcmdrun_path) sopts.mpcmdrun_path = *opts.mpcmdrun_path;
    if (opts.temp_dir)      sopts.temp_dir      = *opts.temp_dir;
    sopts.timeout              = std::chrono::milliseconds(opts.timeout_ms);
    sopts.enforce_preconditions = opts.strict_preconditions;

    const auto state = query_state();
    if (!state.defender_present) {
        MK_WARN("Defender hive not detected; scanner will likely fail at "
                "discovery. Pass --mpcmdrun <path> to override.");
    }

    auto scanner_r = MpCmdRunScanner::create(std::move(sopts));
    if (!scanner_r.ok()) return scanner_r.error();
    auto scanner = std::move(*scanner_r);

    auto verdict_r = scanner->scan_file(opts.input);
    if (!verdict_r.ok()) return verdict_r.error();
    const auto verdict = std::move(*verdict_r);

    std::printf("scan: %s -> %s%s\n",
                opts.input.filename().string().c_str(),
                verdict.infected ? "INFECTED" : "CLEAN",
                verdict.infected ? "" : " (no threats)");
    for (const auto& t : verdict.threats) {
        std::printf("  threat=%-50s severity=%s%s\n",
                    t.name.c_str(),
                    t.severity.c_str(),
                    t.is_ml ? " [ML]" : "");
    }

    std::optional<BisectResult>      bisect_out;
    std::optional<MultiBisectResult> multi_out;
    std::vector<ScanRange>           computed_ranges;
    if (opts.bisect && verdict.infected) {
        auto bytes_r = slurp(opts.input);
        if (!bytes_r.ok()) return bytes_r.error();

        // Compute the PE-aware mask scope. Empty result on non-PE
        // input or `raw` scope; the bisect helpers fall back to
        // legacy slice-and-scan in that case.
        auto ranges_r = compute_pe_scan_ranges(*bytes_r, *scope);
        if (!ranges_r.ok()) return ranges_r.error();
        computed_ranges = std::move(*ranges_r);
        if (computed_ranges.empty() && *scope != ScanScope::Raw) {
            MK_WARN("Scan: --bisect-scope '{}' produced no ranges (non-PE "
                    "input?); falling back to legacy slice-and-scan",
                    opts.bisect_scope);
        } else {
            MK_INFO("Scan: bisect scope='{}' ranges={} bytes={}",
                    opts.bisect_scope, computed_ranges.size(),
                    total_range_bytes(computed_ranges));
        }

        if (opts.bisect_mode == "all") {
            MultiBisectOptions bopts;
            bopts.name_hint = opts.input.filename().string();
            bopts.pe_image_for_section_map = *bytes_r;
            bopts.scan_ranges              = computed_ranges;
            auto br = bisect_multi(*scanner, std::span<const uint8_t>(*bytes_r), bopts);
            if (!br.ok()) return br.error();
            std::printf("  bisect (all): scope=%s status=%s anchors=%zu scans=%d elapsed=%lldms\n",
                        opts.bisect_scope.c_str(),
                        multi_status_name(br->status), br->anchors.size(),
                        br->scan_count,
                        static_cast<long long>(br->elapsed.count()));
            size_t idx = 0;
            for (const auto& a : br->anchors) {
                std::printf("    [%zu] status=%s offset=0x%zx len=%zu section=%s frags=%zu\n",
                            ++idx, status_name(a.status), a.offset, a.length,
                            a.section.empty() ? "?" : a.section.c_str(),
                            a.fragments.size());
            }
            multi_out = std::move(*br);
        } else {
            BisectOptions bopts;
            bopts.name_hint = opts.input.filename().string();
            bopts.pe_image_for_section_map = *bytes_r;
            bopts.scan_ranges              = computed_ranges;
            auto br = bisect_single(*scanner, std::span<const uint8_t>(*bytes_r), bopts);
            if (!br.ok()) return br.error();
            std::printf("  bisect: scope=%s status=%s offset=0x%zx len=%zu section=%s frags=%zu scans=%d elapsed=%lldms\n",
                        opts.bisect_scope.c_str(),
                        status_name(br->status), br->offset, br->length,
                        br->section.c_str(), br->fragments.size(),
                        br->scan_count,
                        static_cast<long long>(br->elapsed.count()));
            bisect_out = std::move(*br);
        }
    }

    if (opts.report_path) {
        const auto& rp = *opts.report_path;
        const auto ext = rp.extension().string();

        auto bytes_r = slurp(opts.input);
        nlohmann::json input_block = {
            {"path", opts.input.string()},
            {"size", bytes_r.ok() ? bytes_r->size() : size_t{0}},
        };
        if (bytes_r.ok()) {
            input_block["sha256"] = analysis::sha256_hex(*bytes_r);
        }

        nlohmann::json j = {
            {"tool",       "morphkatz"},
            {"mode",       "scan"},
            {"engine",     {{"label", "MpCmdRun-Tier1"},
                            {"exe_version", verdict.engine_version},
                            {"vdm_version", verdict.vdm_version}}},
            {"preconditions", {
                {"defender_present",    state.defender_present},
                {"spynet_reporting",    state.spynet_reporting.value_or(0xffffffff)},
                {"submit_samples",      state.submit_samples_consent.value_or(0xffffffff)},
                {"rtp_off",             state.disable_realtime_monitoring.value_or(0xffffffff)},
                {"strict",              opts.strict_preconditions},
            }},
            {"input",      input_block},
            {"verdict",    verdict_to_json(verdict)},
        };
        if (bisect_out || multi_out) {
            nlohmann::json b = bisect_out
                ? bisect_to_json(*bisect_out)
                : multi_bisect_to_json(*multi_out);
            b["scope"]       = opts.bisect_scope;
            b["scope_bytes"] = total_range_bytes(computed_ranges);
            j["bisect"]      = std::move(b);
        }

        std::ofstream f(rp, std::ios::trunc);
        if (!f) {
            return Error::make(ErrorKind::Io,
                "cannot write scan report", rp.string());
        }
        if (ext == ".html" || ext == ".htm") {
            f << build_html(opts, state, verdict, bisect_out, multi_out,
                            total_range_bytes(computed_ranges));
        } else {
            f << j.dump(2);
        }
        MK_INFO("Scan report: {}", rp.string());
    }

    return {};
}

}

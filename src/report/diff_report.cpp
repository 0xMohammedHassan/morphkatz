#include "morphkatz/report/diff_report.hpp"

#include "morphkatz/common/logging.hpp"

#include <Zydis/Zydis.h>
#include <fmt/format.h>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <fstream>
#include <string>
#include <string_view>

namespace morphkatz::report {

namespace {

std::string hex(std::span<const uint8_t> bytes) {
    std::string out;
    out.reserve(bytes.size() * 3);
    for (size_t i = 0; i < bytes.size(); ++i) {
        if (i) out.push_back(' ');
        out.append(fmt::format("{:02X}", bytes[i]));
    }
    return out;
}

std::string html_escape(std::string_view s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        switch (c) {
            case '&':  out += "&amp;";  break;
            case '<':  out += "&lt;";   break;
            case '>':  out += "&gt;";   break;
            case '"':  out += "&quot;"; break;
            case '\'': out += "&#39;";  break;
            default:   out.push_back(c); break;
        }
    }
    return out;
}

std::string disasm_one(std::span<const uint8_t> bytes, uint64_t va) {
    ZydisDecoder dec;
    if (ZYAN_FAILED(ZydisDecoderInit(&dec, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64))) {
        return {};
    }
    ZydisDecodedInstruction ins;
    ZydisDecodedOperand     ops[ZYDIS_MAX_OPERAND_COUNT];
    if (ZYAN_FAILED(ZydisDecoderDecodeFull(&dec, bytes.data(), bytes.size(), &ins, ops))) {
        return {};
    }
    ZydisFormatter fmt;
    ZydisFormatterInit(&fmt, ZYDIS_FORMATTER_STYLE_INTEL);
    char buf[256]{};
    ZydisFormatterFormatInstruction(&fmt, &ins, ops, ins.operand_count_visible,
                                    buf, sizeof(buf), va, nullptr);
    return buf;
}

}  // namespace

DiffReport::DiffReport(std::filesystem::path input, std::filesystem::path output)
    : input_(std::move(input)), output_(std::move(output)) {}

void DiffReport::record_direct(uint64_t va, uint64_t file_off,
                               std::vector<uint8_t> old_bytes,
                               std::vector<uint8_t> new_bytes,
                               std::string rule_id) {
    DiffEntry e;
    e.va          = va;
    e.file_offset = file_off;
    e.old_bytes   = std::move(old_bytes);
    e.new_bytes   = std::move(new_bytes);
    e.rule_id     = std::move(rule_id);
    e.old_disasm  = disasm_one(e.old_bytes, e.va);
    e.new_disasm  = disasm_one(e.new_bytes, e.va);
    e.status      = "applied";
    entries_.push_back(std::move(e));
}

void DiffReport::record_raw(uint64_t file_off,
                            std::vector<uint8_t> old_bytes,
                            std::vector<uint8_t> new_bytes,
                            std::string rule_id) {
    DiffEntry e;
    e.file_offset = file_off;
    e.old_bytes   = std::move(old_bytes);
    e.new_bytes   = std::move(new_bytes);
    e.rule_id     = std::move(rule_id);
    e.status      = "applied";
    entries_.push_back(std::move(e));
}

void DiffReport::mark_status(uint64_t file_off, std::string status) {
    for (auto& e : entries_) {
        if (e.file_offset == file_off) {
            e.status = std::move(status);
            return;
        }
    }
}

void DiffReport::record_yara(std::vector<std::string> pre_hits,
                             std::vector<std::string> post_hits) {
    yara_.pre_hits  = std::move(pre_hits);
    yara_.post_hits = std::move(post_hits);
    auto sorted_pre  = yara_.pre_hits;
    auto sorted_post = yara_.post_hits;
    std::sort(sorted_pre.begin(),  sorted_pre.end());
    std::sort(sorted_post.begin(), sorted_post.end());
    yara_.broken.clear();
    std::set_difference(sorted_pre.begin(),  sorted_pre.end(),
                        sorted_post.begin(), sorted_post.end(),
                        std::back_inserter(yara_.broken));
}

Result<void> DiffReport::write(const std::filesystem::path& out_path) const {
    const auto ext = out_path.extension().string();
    if (ext == ".html" || ext == ".htm") return write_html(out_path);
    return write_json(out_path);
}

Result<void> DiffReport::write_json(const std::filesystem::path& out_path) const {
    nlohmann::json j;
    j["tool"]   = "morphkatz";
    j["input"]  = input_.string();
    j["output"] = output_.string();
    j["count"]  = entries_.size();

    if (metrics_.populated) {
        j["metrics"] = {
            {"bytes_changed",     metrics_.bytes_changed},
            {"bytes_total",       metrics_.bytes_total},
            {"bytes_changed_pct", metrics_.bytes_changed_pct},
            {"entropy_before",    metrics_.entropy_before},
            {"entropy_after",     metrics_.entropy_after},
            {"sha256_before",     metrics_.sha256_before},
            {"sha256_after",      metrics_.sha256_after},
            {"richhash_before",   metrics_.richhash_before},
            {"richhash_after",    metrics_.richhash_after},
        };
    }

    auto& arr   = j["patches"];
    arr = nlohmann::json::array();
    for (const auto& e : entries_) {
        nlohmann::json o;
        o["va"]          = e.va;
        o["file_offset"] = e.file_offset;
        o["rule_id"]     = e.rule_id;
        o["status"]      = e.status;
        o["old_hex"]     = hex(e.old_bytes);
        o["new_hex"]     = hex(e.new_bytes);
        o["old_disasm"]  = e.old_disasm;
        o["new_disasm"]  = e.new_disasm;
        arr.push_back(std::move(o));
    }

    if (!yara_.pre_hits.empty() || !yara_.post_hits.empty()) {
        j["yara"] = {
            {"pre",    yara_.pre_hits},
            {"post",   yara_.post_hits},
            {"broken", yara_.broken},
        };
    }

    if (defender_.used) {
        nlohmann::json anchors = nlohmann::json::array();
        for (const auto& a : defender_.anchors) {
            anchors.push_back({
                {"file_offset", a.file_offset},
                {"length",      a.bytes.size()},
                {"hex",         hex(a.bytes)},
                {"section",     a.section},
                {"section_kind",a.section_kind},
                {"threat",      a.threat_name},
                {"status",      a.status},
            });
        }
        j["defender"] = {
            {"engine_label",   defender_.engine_label},
            {"engine_version", defender_.engine_version},
            {"vdm_version",    defender_.vdm_version},
            {"pre_threats",    defender_.pre_threats},
            {"post_threats",   defender_.post_threats},
            {"broken",         defender_.broken},
            {"persisted",      defender_.persisted},
            {"introduced",     defender_.introduced},
            {"anchors",        std::move(anchors)},
        };
    }

    if (data_pass_.used) {
        nlohmann::json atoms = nlohmann::json::array();
        for (const auto& a : data_pass_.atoms) {
            atoms.push_back({
                {"file_offset", a.file_offset},
                {"length",      a.length},
                {"section",     a.section},
                {"source",      a.source},
            });
        }
        j["data_pass"] = {
            {"mode",                    data_pass_.mode},
            {"decoder_placement",       data_pass_.decoder_placement},
            {"atoms_total",             data_pass_.atoms_total},
            {"atoms_encoded",           data_pass_.atoms_encoded},
            {"atoms_skipped_reloc",     data_pass_.atoms_skipped_reloc},
            {"atoms_skipped_directory", data_pass_.atoms_skipped_directory},
            {"atoms_skipped_section",   data_pass_.atoms_skipped_section},
            {"atoms_skipped_size",      data_pass_.atoms_skipped_size},
            {"atoms_skipped_other",     data_pass_.atoms_skipped_other},
            {"yara_candidates",         data_pass_.yara_candidates},
            {"bisect_candidates",       data_pass_.bisect_candidates},
            {"bytes_total",             data_pass_.bytes_total},
            {"morph_section_size",      data_pass_.morph_section_size},
            {"morph_section_rva",       data_pass_.morph_section_rva},
            {"entry_point_changed",     data_pass_.entry_point_changed},
            {"skip_reason",             data_pass_.skip_reason},
            {"atoms",                   std::move(atoms)},
        };
    }

    std::ofstream f(out_path);
    if (!f) return Error::make(ErrorKind::Io, "cannot open report path", out_path.string());
    f << j.dump(2);
    MK_INFO("Wrote JSON report: {}", out_path.string());
    return {};
}

Result<void> DiffReport::write_html(const std::filesystem::path& out_path) const {
    std::ofstream f(out_path);
    if (!f) return Error::make(ErrorKind::Io, "cannot open report path", out_path.string());

    f << "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
      << "<title>MorphKatz diff report</title>"
      << "<style>"
      << "body{font-family:ui-monospace,Menlo,Consolas,monospace;margin:2rem;}"
      << "h1{font-size:1.2rem;margin-bottom:0.2rem;}"
      << "table{border-collapse:collapse;width:100%;}"
      << "th,td{border-bottom:1px solid #ddd;padding:6px 10px;vertical-align:top;font-size:12px;text-align:left;}"
      << "tr.applied td{background:#f7fff4;}"
      << "tr.skipped td{background:#fff7ec;}"
      << "tr.rolled-back td{background:#ffecec;}"
      << "code{white-space:pre;}"
      << "</style></head><body>"
      << "<h1>MorphKatz diff report</h1>"
      << "<p>input: <code>" << html_escape(input_.string())
      << "</code> &rarr; output: <code>"
      << html_escape(output_.string()) << "</code><br>"
      << "patches: " << entries_.size();
    if (metrics_.populated) {
        f << "</p><h2 style=\"font-size:1rem\">Summary metrics</h2>"
          << "<table><tbody>"
          << "<tr><td>bytes changed</td><td>"
          << metrics_.bytes_changed << " / " << metrics_.bytes_total
          << " (" << fmt::format("{:.3f}", metrics_.bytes_changed_pct)
          << " %)</td></tr>"
          << "<tr><td>entropy (bits/byte)</td><td>"
          << fmt::format("{:.4f}", metrics_.entropy_before)
          << " &rarr; " << fmt::format("{:.4f}", metrics_.entropy_after)
          << "</td></tr>"
          << "<tr><td>SHA-256 before</td><td><code>"
          << html_escape(metrics_.sha256_before) << "</code></td></tr>"
          << "<tr><td>SHA-256 after</td><td><code>"
          << html_escape(metrics_.sha256_after)  << "</code></td></tr>"
          << "<tr><td>Rich hash</td><td><code>"
          << fmt::format("0x{:08x}", metrics_.richhash_before)
          << " &rarr; "
          << fmt::format("0x{:08x}", metrics_.richhash_after)
          << "</code></td></tr>"
          << "</tbody></table><p>";
    }
    if (!yara_.pre_hits.empty() || !yara_.post_hits.empty()) {
        f << "<br>YARA pre: " << yara_.pre_hits.size()
          << ", post: " << yara_.post_hits.size()
          << ", broken: " << yara_.broken.size();
        if (!yara_.broken.empty()) {
            f << " (";
            for (size_t k = 0; k < yara_.broken.size(); ++k) {
                if (k) f << ", ";
                f << html_escape(yara_.broken[k]);
            }
            f << ")";
        }
    }
    if (defender_.used) {
        f << "<br>Defender (" << html_escape(defender_.engine_label)
          << ") pre: " << defender_.pre_threats.size()
          << ", post: " << defender_.post_threats.size()
          << ", broken: " << defender_.broken.size()
          << ", persisted: " << defender_.persisted.size();
        if (!defender_.broken.empty()) {
            f << " (broke: ";
            for (size_t k = 0; k < defender_.broken.size(); ++k) {
                if (k) f << ", ";
                f << html_escape(defender_.broken[k]);
            }
            f << ")";
        }
    }
    if (data_pass_.used) {
        f << "<br>Data-morph (" << html_escape(data_pass_.mode)
          << ", placement=" << html_escape(data_pass_.decoder_placement)
          << "): atoms="    << data_pass_.atoms_encoded
          << "/"            << data_pass_.atoms_total
          << ", bytes="     << data_pass_.bytes_total
          << ", morph_section=" << data_pass_.morph_section_size << " B";
        if (data_pass_.morph_section_rva) {
            f << " @ RVA "
              << fmt::format("0x{:x}", data_pass_.morph_section_rva);
        }
        if (data_pass_.entry_point_changed) {
            f << ", EP relinked";
        }
        if (!data_pass_.skip_reason.empty()) {
            f << " <strong>(skipped: "
              << html_escape(data_pass_.skip_reason)
              << ")</strong>";
        }
    }
    f << "</p>"
      << "<table><thead><tr>"
      << "<th>#</th><th>VA</th><th>off</th><th>rule</th><th>status</th>"
      << "<th>old bytes</th><th>old disasm</th>"
      << "<th>new bytes</th><th>new disasm</th></tr></thead><tbody>";

    size_t i = 0;
    for (const auto& e : entries_) {
        f << "<tr class=\"" << html_escape(e.status) << "\">"
          << "<td>" << (++i)                    << "</td>"
          << "<td>" << fmt::format("0x{:x}", e.va)     << "</td>"
          << "<td>" << fmt::format("0x{:x}", e.file_offset) << "</td>"
          << "<td>" << html_escape(e.rule_id)    << "</td>"
          << "<td>" << html_escape(e.status)     << "</td>"
          << "<td><code>" << hex(e.old_bytes) << "</code></td>"
          << "<td>" << html_escape(e.old_disasm) << "</td>"
          << "<td><code>" << hex(e.new_bytes) << "</code></td>"
          << "<td>" << html_escape(e.new_disasm) << "</td>"
          << "</tr>";
    }
    f << "</tbody></table>";

    if (data_pass_.used && !data_pass_.atoms.empty()) {
        f << "<h2 style=\"font-size:1rem\">Data-morph atoms</h2>"
          << "<table><thead><tr>"
          << "<th>#</th><th>file_offset</th><th>length</th>"
          << "<th>section</th><th>source</th>"
          << "</tr></thead><tbody>";
        size_t di = 0;
        for (const auto& a : data_pass_.atoms) {
            f << "<tr><td>" << (++di) << "</td>"
              << "<td>" << fmt::format("0x{:x}", a.file_offset) << "</td>"
              << "<td>" << a.length << "</td>"
              << "<td>" << html_escape(a.section) << "</td>"
              << "<td>" << html_escape(a.source) << "</td>"
              << "</tr>";
        }
        f << "</tbody></table>";
    }

    if (defender_.used && !defender_.anchors.empty()) {
        f << "<h2 style=\"font-size:1rem\">Defender anchors</h2>"
          << "<table><thead><tr>"
          << "<th>#</th><th>offset</th><th>length</th><th>section</th>"
          << "<th>threat</th><th>status</th><th>bytes</th>"
          << "</tr></thead><tbody>";
        size_t ai = 0;
        for (const auto& a : defender_.anchors) {
            f << "<tr><td>" << (++ai) << "</td>"
              << "<td>" << fmt::format("0x{:x}", a.file_offset) << "</td>"
              << "<td>" << a.bytes.size() << "</td>"
              << "<td>" << html_escape(a.section)
              << " (" << html_escape(a.section_kind) << ")</td>"
              << "<td>" << html_escape(a.threat_name) << "</td>"
              << "<td>" << html_escape(a.status) << "</td>"
              << "<td><code>" << hex(a.bytes) << "</code></td>"
              << "</tr>";
        }
        f << "</tbody></table>";
    }

    f << "</body></html>";
    MK_INFO("Wrote HTML report: {}", out_path.string());
    return {};
}

}

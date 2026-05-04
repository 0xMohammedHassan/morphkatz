#pragma once

#include "morphkatz/common/error.hpp"

#include <cstdint>
#include <filesystem>
#include <memory>
#include <string>
#include <vector>

namespace morphkatz::report {

// Single entry = single patch applied (or queued but skipped). Written verbatim
// into both the JSON and HTML variants.
struct DiffEntry {
    uint64_t    va          = 0;
    uint64_t    file_offset = 0;
    std::vector<uint8_t> old_bytes;
    std::vector<uint8_t> new_bytes;
    std::string old_disasm;
    std::string new_disasm;
    std::string rule_id;
    std::string status;      // "applied" | "skipped" | "rolled-back"
};

// Optional YARA-rule before/after summary attached to the report.
struct YaraSummary {
    std::vector<std::string> pre_hits;
    std::vector<std::string> post_hits;
    std::vector<std::string> broken;     // pre_hits \ post_hits
};

// Optional Microsoft Defender feedback block attached to the report
// when `--target-defender <ref>` is used. Populated by the orchestrator
// after the post-mutation rescan; mirrors the shape of `YaraSummary`
// plus engine identification so the reader can tell which signature
// database produced the verdict.
struct DefenderSummary {
    bool                       used         = false;
    std::string                engine_label;          // "MpCmdRun-Tier1"
    std::string                engine_version;
    std::string                vdm_version;
    std::vector<std::string>   pre_threats;           // names from probe scan
    std::vector<std::string>   post_threats;          // names from post-mutation scan
    std::vector<std::string>   broken;                // pre \ post
    std::vector<std::string>   persisted;             // pre intersect post
    std::vector<std::string>   introduced;            // post \ pre

    struct Anchor {
        std::vector<uint8_t> bytes;
        uint64_t             file_offset = 0;
        std::string          section;
        std::string          section_kind;
        std::string          threat_name;
        std::string          status;                  // "found"|"midpoint_span"
    };
    std::vector<Anchor> anchors;
};

// Whole-binary metrics captured by the orchestrator before and after the
// rewrite + finalize pipeline. These are the first things a user of any
// morpher wants to see (how different is the output? how did entropy
// move? did the Rich hash change?) so they ride at the top of the
// generated report.
struct Metrics {
    size_t      bytes_changed     = 0;
    size_t      bytes_total       = 0;
    double      bytes_changed_pct = 0.0;
    double      entropy_before    = 0.0;
    double      entropy_after     = 0.0;
    std::string sha256_before;
    std::string sha256_after;
    uint32_t    richhash_before   = 0;
    uint32_t    richhash_after    = 0;
    bool        populated         = false;
};

// Counters + per-atom listing produced by the data-section morph pass.
// Populated by the orchestrator before `set_data_pass(...)` is called;
// fields are cumulative across YARA + bisect channels.
//
// `mode` is one of "off" / "plan" / "on" so the report writer can
// disambiguate "atoms found but skipped because user only asked for a
// dry run" from "no atoms found".
struct DataPassMetrics {
    bool        used                    = false;
    std::string mode;                            // "off"|"plan"|"on"
    std::string decoder_placement;               // "ep_thunk"|"tls_callback"|"none"
    uint32_t    atoms_total             = 0;     // accepted + skipped
    uint32_t    atoms_encoded           = 0;     // accepted (will be encoded under "on")
    uint32_t    atoms_skipped_reloc     = 0;
    uint32_t    atoms_skipped_directory = 0;
    uint32_t    atoms_skipped_section   = 0;     // not in .rdata/.data
    uint32_t    atoms_skipped_size      = 0;     // too small or too large
    uint32_t    atoms_skipped_other     = 0;     // dup, budget, etc.
    uint32_t    yara_candidates         = 0;
    uint32_t    bisect_candidates       = 0;
    uint64_t    bytes_total             = 0;
    uint64_t    morph_section_size      = 0;
    uint32_t    morph_section_rva       = 0;
    bool        entry_point_changed     = false;
    std::string skip_reason;                     // populated when encoding skipped

    struct Atom {
        uint64_t    file_offset = 0;
        uint32_t    length      = 0;
        std::string section;
        std::string source;
    };
    std::vector<Atom> atoms;
};

class DiffReport {
public:
    DiffReport(std::filesystem::path input, std::filesystem::path output);

    void record_direct(uint64_t va, uint64_t file_off,
                       std::vector<uint8_t> old_bytes,
                       std::vector<uint8_t> new_bytes,
                       std::string rule_id);
    void record_raw(uint64_t file_off,
                    std::vector<uint8_t> old_bytes,
                    std::vector<uint8_t> new_bytes,
                    std::string rule_id);
    void mark_status(uint64_t file_off, std::string status);

    // Attach the YARA pre/post summary. Called once by the orchestrator.
    void record_yara(std::vector<std::string> pre_hits,
                     std::vector<std::string> post_hits);

    // Attach the whole-binary metrics. Called once by the orchestrator
    // after `finalize()` so we have both the pre- and post-rewrite
    // snapshots.
    void set_metrics(Metrics m) noexcept { metrics_ = std::move(m); }

    // Attach the Defender summary. Called once by the orchestrator
    // when `--target-defender` is in effect; the JSON/HTML writers
    // skip the block when `defender.used` is false.
    void set_defender(DefenderSummary d) { defender_ = std::move(d); }

    // Attach the data-pass summary. Called once by the orchestrator
    // when `--data-morph plan|on` is in effect.
    void set_data_pass(DataPassMetrics d) { data_pass_ = std::move(d); }

    [[nodiscard]] const std::vector<DiffEntry>& entries() const noexcept { return entries_; }
    [[nodiscard]] const YaraSummary& yara() const noexcept { return yara_; }
    [[nodiscard]] const Metrics& metrics() const noexcept { return metrics_; }
    [[nodiscard]] const DefenderSummary& defender() const noexcept { return defender_; }
    [[nodiscard]] const DataPassMetrics& data_pass() const noexcept { return data_pass_; }

    // Picks JSON or HTML based on the extension of `out_path`.
    Result<void> write(const std::filesystem::path& out_path) const;
    Result<void> write_json(const std::filesystem::path& out_path) const;
    Result<void> write_html(const std::filesystem::path& out_path) const;

private:
    std::filesystem::path input_;
    std::filesystem::path output_;
    std::vector<DiffEntry> entries_;
    YaraSummary     yara_{};
    Metrics         metrics_{};
    DefenderSummary defender_{};
    DataPassMetrics data_pass_{};
};

}

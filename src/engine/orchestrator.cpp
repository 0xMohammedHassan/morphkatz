#include "morphkatz/engine/orchestrator.hpp"

#include "morphkatz/analysis/flag_liveness.hpp"
#include "morphkatz/analysis/metrics.hpp"
#include "morphkatz/common/logging.hpp"
#include "morphkatz/datapass/atom_discovery.hpp"
#include "morphkatz/datapass/pass.hpp"
#include "morphkatz/disasm/cfg.hpp"
#include "morphkatz/disasm/decoder.hpp"
#include "morphkatz/engine/pad_policy.hpp"
#include "morphkatz/engine/patcher.hpp"
#include "morphkatz/engine/polymorph.hpp"
#include "morphkatz/engine/rng.hpp"
#include "morphkatz/format/pe_image.hpp"
#include "morphkatz/report/diff_report.hpp"
#include "morphkatz/rules/rule_loader.hpp"
#include "morphkatz/rules/rule_matcher.hpp"
#include "morphkatz/scan/defender_target.hpp"
#include "morphkatz/scan/mpcmdrun_scanner.hpp"
#include "morphkatz/verify/re_disasm_check.hpp"
#include "morphkatz/verify/unicorn_verify.hpp"
#include "morphkatz/yara/yara_target.hpp"

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <memory>
#include <optional>

namespace morphkatz::engine {

struct Orchestrator::Impl {
    cli::Options options;

    std::unique_ptr<format::PeImage>   image;
    std::unique_ptr<rules::RulePack>   rules;
    std::unique_ptr<yara_target::PriorityMap> yara_priority;
    std::unique_ptr<engine::Rng>       rng;
    std::unique_ptr<engine::PadPolicy> pad_policy;
    std::unique_ptr<engine::Polymorph> polymorph;
    std::unique_ptr<report::DiffReport> report;
    report::Metrics metrics_cache{};

    // --target-defender wiring. The DefenderTarget owns the scanner
    // shared_ptr; we keep a separate alias so the test mock can be
    // injected without going through MpCmdRun discovery.
    std::shared_ptr<scan::IDefenderScanner> defender_scanner;
    std::optional<scan::DefenderTarget>     defender_target;

    Result<void> load_image();
    Result<void> backup();
    Result<void> load_rules();
    Result<void> load_yara();
    Result<void> load_defender();
    Result<void> build_engines();
    Result<void> rewrite();
    Result<void> data_pass(bool& early_return_after_plan);
    Result<void> verify(const std::vector<engine::AppliedPatch>& applied);
    Result<void> finalize();
    Result<void> write_report();
};

Orchestrator::Orchestrator(cli::Options opts) : impl_(std::make_unique<Impl>()) {
    impl_->options = std::move(opts);
}

Orchestrator::~Orchestrator() = default;

const report::Metrics& Orchestrator::metrics() const noexcept {
    return impl_->metrics_cache;
}

Result<void> Orchestrator::run() {
    const auto t0 = std::chrono::steady_clock::now();
    // Tag every error with the stage that produced it. Turns opaque
    // "ErrorKind::Invalid" bubbles into something a user or test author
    // can actually act on.
    auto tag = [](const char* stage, const Error& e) -> Error {
        return Error::make(e.kind,
            std::string(stage) + ": " + (e.what.empty() ? "<no message>" : e.what),
            e.where);
    };
    if (auto r = impl_->load_image();    !r.ok()) return tag("load_image",    r.error());
    if (auto r = impl_->backup();        !r.ok()) return tag("backup",        r.error());
    if (auto r = impl_->load_rules();    !r.ok()) return tag("load_rules",    r.error());
    if (auto r = impl_->load_yara();     !r.ok()) return tag("load_yara",     r.error());
    if (auto r = impl_->load_defender(); !r.ok()) return tag("load_defender", r.error());
    if (auto r = impl_->build_engines(); !r.ok()) return tag("build_engines", r.error());

    // Snapshot the original bytes before any mutation so the report can
    // show real before/after metrics. We deliberately copy here; the
    // morph pipeline mutates `image->bytes()` in place.
    const auto image_before =
        std::vector<uint8_t>(impl_->image->bytes().begin(),
                             impl_->image->bytes().end());

    // Pre-patch YARA scan — lets the report show which rules were broken.
    std::vector<std::string> pre_hits;
    if (impl_->yara_priority) {
        pre_hits = impl_->yara_priority->scan(impl_->image->bytes());
        MK_INFO("YARA pre-patch: {} rule hit(s)", pre_hits.size());
    }

    if (auto r = impl_->rewrite();       !r.ok()) return tag("rewrite",       r.error());

    // Data-section morphing pass (atom discovery in v1; encoding lands
    // in Phase 2 of the plan). On `--data-morph plan`, the helper sets
    // `early_return_after_plan = true` so we skip finalize() and just
    // emit the report with the atom listing.
    bool plan_only_short_circuit = false;
    if (auto r = impl_->data_pass(plan_only_short_circuit); !r.ok()) {
        return tag("data_pass", r.error());
    }
    if (plan_only_short_circuit) {
        if (auto r = impl_->write_report(); !r.ok()) {
            return tag("write_report", r.error());
        }
        MK_INFO("--data-morph plan: dry run complete; no output written");
        return {};
    }

    if (auto r = impl_->finalize();      !r.ok()) return tag("finalize",      r.error());

    // Post-patch YARA scan.
    if (impl_->yara_priority) {
        const auto post = impl_->yara_priority->scan(impl_->image->bytes());
        const size_t broken = (pre_hits.size() >= post.size())
                                  ? pre_hits.size() - post.size() : 0;
        MK_INFO("YARA post-patch: {} rule hit(s), {} rule(s) broken",
                 post.size(), broken);
        if (impl_->report) {
            impl_->report->record_yara(pre_hits, post);
        }
    }

    // Populate whole-binary metrics on the report. `after` is read from
    // the in-memory image; on a --dry-run the save to disk is skipped
    // but the metrics still reflect what the output would have been.
    if (impl_->report) {
        const std::span<const uint8_t> before(image_before.data(), image_before.size());
        const auto after_span = impl_->image->bytes();

        report::Metrics m;
        m.bytes_total       = std::max(before.size(), after_span.size());
        m.bytes_changed     = analysis::byte_diff_count(before, after_span);
        m.bytes_changed_pct = (m.bytes_total == 0) ? 0.0
            : (static_cast<double>(m.bytes_changed) * 100.0
               / static_cast<double>(m.bytes_total));
        m.entropy_before    = analysis::shannon_entropy(before);
        m.entropy_after     = analysis::shannon_entropy(after_span);
        m.sha256_before     = analysis::sha256_hex(before);
        m.sha256_after      = analysis::sha256_hex(after_span);
        m.richhash_before   = analysis::rich_hash(before);
        m.richhash_after    = analysis::rich_hash(after_span);
        m.populated         = true;
        impl_->metrics_cache = m;
        impl_->report->set_metrics(std::move(m));
    } else {
        // Even without a report, preserve the SHA+percent-changed snapshot
        // so batch mode can aggregate across variants.
        const std::span<const uint8_t> before(image_before.data(), image_before.size());
        const auto after_span = impl_->image->bytes();
        report::Metrics m;
        m.bytes_total       = std::max(before.size(), after_span.size());
        m.bytes_changed     = analysis::byte_diff_count(before, after_span);
        m.bytes_changed_pct = (m.bytes_total == 0) ? 0.0
            : (static_cast<double>(m.bytes_changed) * 100.0
               / static_cast<double>(m.bytes_total));
        m.entropy_before    = analysis::shannon_entropy(before);
        m.entropy_after     = analysis::shannon_entropy(after_span);
        m.sha256_before     = analysis::sha256_hex(before);
        m.sha256_after      = analysis::sha256_hex(after_span);
        m.richhash_before   = analysis::rich_hash(before);
        m.richhash_after    = analysis::rich_hash(after_span);
        m.populated         = true;
        impl_->metrics_cache = std::move(m);
    }

    // Defender post-mutation evaluation. We must do this AFTER finalize()
    // because the scanner reads the saved file from disk; on --dry-run
    // there is no file and we just record the pre-scan threats.
    if (impl_->defender_target && impl_->report) {
        report::DefenderSummary ds;
        ds.used         = true;
        ds.engine_label = impl_->defender_target->engine_label();
        for (const auto& t : impl_->defender_target->pre_threats()) {
            ds.pre_threats.push_back(t.name);
        }
        for (const auto& a : impl_->defender_target->anchors()) {
            report::DefenderSummary::Anchor ra;
            ra.bytes        = a.bytes;
            ra.file_offset  = a.file_offset;
            ra.section      = a.section;
            ra.section_kind = a.section_kind;
            ra.threat_name  = a.threat_name;
            switch (a.status) {
                case scan::BisectResult::Status::Found:
                    ra.status = "found"; break;
                case scan::BisectResult::Status::MidpointSpan:
                    ra.status = "midpoint_span"; break;
                default:
                    ra.status = "noop"; break;
            }
            ds.anchors.push_back(std::move(ra));
        }

        if (!impl_->options.dry_run) {
            auto diff_r = impl_->defender_target->evaluate_after_mutation(
                impl_->options.output);
            if (diff_r.ok()) {
                ds.broken     = std::move(diff_r->broken);
                ds.persisted  = std::move(diff_r->persisted);
                ds.introduced = std::move(diff_r->introduced);
                ds.post_threats = ds.persisted;
                for (const auto& n : ds.introduced) ds.post_threats.push_back(n);
                MK_INFO("Defender post-scan: broken={} persisted={} introduced={}",
                         ds.broken.size(), ds.persisted.size(), ds.introduced.size());
            } else {
                MK_WARN("Defender post-scan failed: {}", diff_r.error().what);
            }
        }
        impl_->report->set_defender(std::move(ds));
    }

    if (auto r = impl_->write_report();  !r.ok()) return tag("write_report",  r.error());
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - t0).count();
    MK_INFO("Done in {} ms", elapsed);
    return {};
}

Result<void> Orchestrator::Impl::load_image() {
    auto r = format::PeImage::load(options.input);
    if (!r.ok()) return r.error();
    image = std::move(*r);
    MK_INFO("Loaded {}: {} ({} code sections)",
             options.input.string(),
             image->is_pe() ? "PE" : "raw shellcode",
             image->code_sections().size());
    return {};
}

Result<void> Orchestrator::Impl::backup() {
    if (!options.backup || options.dry_run) return {};
    auto dst = options.input;
    dst += ".bak";
    std::error_code ec;
    std::filesystem::copy_file(options.input, dst,
        std::filesystem::copy_options::overwrite_existing, ec);
    if (ec) {
        return Error::make(ErrorKind::Io, "backup failed: " + ec.message(), dst.string());
    }
    MK_INFO("Backup written: {}", dst.string());
    return {};
}

Result<void> Orchestrator::Impl::load_rules() {
    rules::LoaderOptions lopt;
    lopt.profile = options.profile;
    lopt.default_rules_dir = options.default_rules_dir;
    for (const auto& p : options.extra_rule_paths) lopt.extra_paths.push_back(p);

    auto r = rules::load_all(lopt);
    if (!r.ok()) return r.error();
    rules = std::move(*r);
    MK_INFO("Loaded {} rules from {} pack(s)",
             rules->rule_count(), rules->pack_count());
    return {};
}

Result<void> Orchestrator::Impl::load_yara() {
    if (!options.yara_target) return {};
#if MORPHKATZ_WITH_YARA
    auto r = yara_target::load(*options.yara_target);
    if (!r.ok()) return r.error();
    yara_priority = std::move(*r);
    MK_INFO("YARA target: {} atoms across {} rules",
             yara_priority->atom_count(), yara_priority->rule_count());
    return {};
#else
    MK_WARN("--target ignored: build without MORPHKATZ_WITH_YARA");
    return {};
#endif
}

namespace {

// Case-insensitive substring search. Used to detect Defender threat
// families ("Mimikatz" matching "HackTool:Win32/Mimikatz!pz").
bool icontains(std::string_view hay, std::string_view needle) noexcept {
    if (needle.empty()) return true;
    if (hay.size() < needle.size()) return false;
    auto tolower_b = [](char c) noexcept -> char {
        return (c >= 'A' && c <= 'Z') ? static_cast<char>(c + 32) : c;
    };
    for (size_t i = 0; i + needle.size() <= hay.size(); ++i) {
        bool match = true;
        for (size_t j = 0; j < needle.size(); ++j) {
            if (tolower_b(hay[i + j]) != tolower_b(needle[j])) {
                match = false; break;
            }
        }
        if (match) return true;
    }
    return false;
}

// Map a Defender threat name onto the basename of a bundled YARA hint
// pack under `<rules>/yara/x64/`. Returns empty if no family is known.
std::string match_family_yara(const std::vector<scan::Threat>& threats) {
    for (const auto& t : threats) {
        if (icontains(t.name, "Mimikatz"))   return "mimikatz";
        // Future: cobaltstrike, donut, adaptix - paths exist in
        // rules/x64/targeted/ today, YARA hint packs to follow.
    }
    return {};
}

}  // namespace

Result<void> Orchestrator::Impl::load_defender() {
    if (!options.defender_target) return {};

    // Build the Tier-1 scanner; auto-discover MpCmdRun.exe and apply
    // the strict precondition gate (cloud + sample submission off).
    // Test harnesses inject a mock scanner via a thread-local hook on
    // top of this default; production runs pay the discovery cost.
    scan::MpCmdRunScanner::Options sopts;
    sopts.enforce_preconditions = true;
    auto scanner_r = scan::MpCmdRunScanner::create(std::move(sopts));
    if (!scanner_r.ok()) {
        return Error::make(scanner_r.error().kind,
            "DefenderTarget setup failed: " + scanner_r.error().what,
            scanner_r.error().where);
    }
    defender_scanner = std::move(*scanner_r);

    auto target_r = scan::DefenderTarget::from_file(
        *options.defender_target, defender_scanner);
    if (!target_r.ok()) return target_r.error();
    defender_target.emplace(std::move(*target_r));

    MK_INFO("Defender target: {}", options.defender_target->string());
    if (auto pr = defender_target->probe(); !pr.ok()) {
        return Error::make(pr.error().kind,
            "DefenderTarget probe failed: " + pr.error().what,
            pr.error().where);
    }
    MK_INFO("Defender probe: {} pre-threat(s), {} anchor(s)",
             defender_target->pre_threats().size(),
             defender_target->anchors().size());

    // YARA hint pack auto-load. Skipped when:
    //  - the user disabled it (--no-auto-yara), or
    //  - they already passed --target (which `load_yara()` honoured), or
    //  - we don't recognise the threat family.
#if MORPHKATZ_WITH_YARA
    if (options.auto_yara && !yara_priority &&
        !options.yara_target && !options.default_rules_dir.empty()) {
        const auto family = match_family_yara(defender_target->pre_threats());
        if (!family.empty()) {
            const auto path = options.default_rules_dir / "yara" / "x64" /
                              (family + ".yar");
            std::error_code ec;
            if (std::filesystem::is_regular_file(path, ec)) {
                auto y = yara_target::load(path);
                if (y.ok()) {
                    yara_priority = std::move(*y);
                    MK_INFO("YARA auto-loaded: {} ({} atoms / {} rules) "
                            "matched family={}",
                            path.string(),
                            yara_priority->atom_count(),
                            yara_priority->rule_count(),
                            family);
                } else {
                    MK_WARN("YARA auto-load skipped: {} -> {}",
                            path.string(), y.error().what);
                }
            }
        }
    }
#endif
    return {};
}

Result<void> Orchestrator::Impl::build_engines() {
    rng = std::make_unique<Rng>(options.seed);
    pad_policy = std::make_unique<PadPolicy>(*rng);
    polymorph  = std::make_unique<Polymorph>(*rng);
    report     = std::make_unique<report::DiffReport>(options.input, options.output);
    return {};
}

Result<void> Orchestrator::Impl::rewrite() {
    MK_INFO("Analysing {} ({} bytes)...",
             options.input.filename().string(), image->bytes().size());

    // M3: build a CFG; fall back to linear sweep if recursive descent fails
    // (e.g. shellcode with no reliable seed).
    auto cfg_res = disasm::build_cfg(*image);
    std::vector<disasm::BasicBlock> fallback;
    const std::vector<disasm::BasicBlock>* blocks_ptr = nullptr;
    if (cfg_res.ok()) {
        blocks_ptr = &(*cfg_res)->blocks();
    } else {
        MK_WARN("CFG build failed ({}), falling back to linear sweep", cfg_res.error().what);
        fallback = disasm::linear_sweep_blocks(*image);
        blocks_ptr = &fallback;
    }
    const auto& blocks = *blocks_ptr;

    MK_INFO("Disassembled {} basic blocks", blocks.size());

    // Build a synthetic Cfg view for the liveness analysis if the real one
    // failed (fallback path already populated `fallback`). This avoids the
    // need to duplicate the liveness algorithm for the sweep case.
    std::unique_ptr<disasm::Cfg> synthetic_cfg;
    const disasm::Cfg* cfg_for_liveness = nullptr;
    if (cfg_res.ok()) {
        cfg_for_liveness = cfg_res->get();
    } else {
        synthetic_cfg = std::make_unique<disasm::Cfg>(fallback);
        cfg_for_liveness = synthetic_cfg.get();
    }
    const auto liveness = analysis::compute_flag_liveness(*cfg_for_liveness);
    MK_INFO("Flag liveness: {} blocks analysed", cfg_for_liveness->blocks().size());

    rules::RuleMatcher matcher(*rules,
                               yara_priority.get(),
                               &liveness,
                               defender_target ? &(*defender_target) : nullptr);
    Patcher patcher;

    // Raw-byte rules (targeted/*.yaml) bypass the per-instruction matcher and
    // are handled by the Aho-Corasick scan inside `patcher.apply()`.
    size_t raw_rule_count = 0;
    for (const auto& r : rules->rules()) {
        if (r.raw_from && r.raw_to) {
            patcher.queue_raw(*r.raw_from, *r.raw_to, r.id);
            ++raw_rule_count;
        }
    }
    if (raw_rule_count) {
        MK_INFO("Queued {} raw-byte target rule(s) for whole-image scan",
                 raw_rule_count);
    }

    size_t candidate_total = 0;
    for (const auto& bb : blocks) {
        auto cands = matcher.evaluate(bb);
        candidate_total += cands.size();
        const auto chosen = polymorph->select(bb, cands, options.mutation_budget);
        patcher.queue_block(bb, chosen, *pad_policy, *report);
    }
    MK_INFO("Generated {} candidate rewrites, applying {} after polymorphic selection",
             candidate_total, patcher.queued_count());

    auto applied = patcher.apply(*image, report.get());
    MK_INFO("Applied {} patches", applied.size());

    if (options.verify != cli::Verify::None) {
        if (auto r = verify(applied); !r.ok()) {
            if (options.rollback_on_verify_failure) {
                const auto restored = Patcher::rollback(*image, applied);
                MK_WARN("Verification failed ({}); rolled back {} patch(es)",
                         r.error().what, restored);
                for (const auto& ap : applied) {
                    if (report) report->mark_status(ap.file_offset, "rolled-back");
                }
                return {};
            }
            return r.error();
        }
    }

    return {};
}

Result<void> Orchestrator::Impl::data_pass(bool& early_return_after_plan) {
    early_return_after_plan = false;

    // ---- Defender-driven auto-escalation -----------------------------
    // When `--target-defender` is set and the user did NOT pin
    // `--data-morph` themselves, decide whether to flip the pass on
    // automatically. Trigger: any pre-mutation bisect anchor whose
    // section_kind is `data` (i.e. landed in `.rdata`/`.data`); these
    // are the layered signatures our instruction passes can't break.
    if (defender_target &&
        !options.data_morph_explicit &&
        options.data_morph == cli::DataMorphMode::Off) {
        for (const auto& a : defender_target->anchors()) {
            if (a.section_kind == "data") {
                MK_INFO("--target-defender: bisect anchor in {} ({} bytes); "
                        "auto-escalating to --data-morph on",
                         a.section, a.bytes.size());
                options.data_morph = cli::DataMorphMode::On;
                break;
            }
        }
    }

    if (options.data_morph == cli::DataMorphMode::Off) return {};

    // Build discovery config from CLI knobs.
    datapass::AtomDiscoveryConfig cfg;
    cfg.min_length = options.data_morph_min_len;
    cfg.max_length = options.data_morph_max_len;

    // Bisect channel: hand the orchestrator's pre-mutation anchors (from
    // `--target-defender`) to discovery. Empty when no defender target.
    std::vector<scan::BisectAnchor> bisect_anchors;
    if (defender_target) {
        for (const auto& a : defender_target->anchors()) {
            scan::BisectAnchor b;
            b.status       = a.status;
            b.offset       = static_cast<size_t>(a.file_offset);
            b.length       = a.bytes.size();
            b.bytes        = a.bytes;
            b.section      = a.section;
            b.section_kind = a.section_kind;
            // BisectAnchor has no fragments here; the discovery layer
            // falls back to (offset,length,bytes) when fragments empty.
            bisect_anchors.push_back(std::move(b));
        }
    }

    auto disc = datapass::discover_atoms(*image, yara_priority.get(),
                                         bisect_anchors, cfg);
    if (!disc.ok()) {
        // Don't kill the run for a missing data-pass discovery: log and
        // skip. The user explicitly opted in via --data-morph, so we
        // still record an empty data-pass block in the report.
        MK_WARN("data-morph: discovery failed: {}", disc.error().what);
    }

    // Translate the discovery result into report::DataPassMetrics. The
    // counters and the per-atom listing are populated whether we are in
    // plan or on mode; only the encoder knob differs (which is wired up
    // in Phase 2 of the plan).
    report::DataPassMetrics dpm;
    dpm.used = true;
    switch (options.data_morph) {
        case cli::DataMorphMode::Off:        dpm.mode = "off";         break;
        case cli::DataMorphMode::Plan:       dpm.mode = "plan";        break;
        case cli::DataMorphMode::EncodeOnly: dpm.mode = "encode_only"; break;
        case cli::DataMorphMode::On:         dpm.mode = "on";          break;
    }
    switch (options.decoder_placement) {
        case cli::DecoderPlacement::Auto:        dpm.decoder_placement = "auto";        break;
        case cli::DecoderPlacement::EpThunk:     dpm.decoder_placement = "ep_thunk";    break;
        case cli::DecoderPlacement::TlsCallback: dpm.decoder_placement = "tls_callback";break;
    }
    if (disc.ok()) {
        dpm.atoms_total       = static_cast<uint32_t>(disc->atoms.size() +
                                                       disc->skipped.size());
        dpm.atoms_encoded     = static_cast<uint32_t>(disc->atoms.size());
        dpm.yara_candidates   = disc->yara_candidates_total;
        dpm.bisect_candidates = disc->bisect_candidates_total;
        dpm.bytes_total       = disc->bytes_total;
        for (const auto& a : disc->atoms) {
            report::DataPassMetrics::Atom o;
            o.file_offset = a.file_offset;
            o.length      = a.length;
            o.section     = a.section;
            o.source      = a.source;
            dpm.atoms.push_back(std::move(o));
        }
        for (const auto& s : disc->skipped) {
            switch (s.reason) {
                case datapass::SkipReason::OverlapsRelocation:
                    ++dpm.atoms_skipped_reloc;     break;
                case datapass::SkipReason::OverlapsDirectory:
                    ++dpm.atoms_skipped_directory; break;
                case datapass::SkipReason::NotInDataSection:
                case datapass::SkipReason::OverlapsTlsCallbackBody:
                    ++dpm.atoms_skipped_section;   break;
                case datapass::SkipReason::TooSmall:
                case datapass::SkipReason::TooLarge:
                    ++dpm.atoms_skipped_size;      break;
                default:
                    ++dpm.atoms_skipped_other;     break;
            }
        }
    }
    if (report) report->set_data_pass(std::move(dpm));

    if (options.data_morph == cli::DataMorphMode::Plan) {
        MK_INFO("data-morph plan: {} atom(s) ready for encoding "
                "(skipped: {}); skipping finalize because mode=plan",
                 disc.ok() ? disc->atoms.size() : 0,
                 disc.ok() ? disc->skipped.size() : 0);
        early_return_after_plan = true;
        return {};
    }

    // --data-morph on / encode-only: invoke the encoder. The pass is
    // intentionally best-effort: if the binary is unsuitable (e.g.
    // VirtualProtect not imported, no header slack), we record the
    // skip reason in the report and let `finalize()` save the binary
    // unchanged for the data sections. Users running under
    // `--target-defender` can then re-run with a different target /
    // more aggressive instruction pass without losing the diagnostic
    // trail.
    if (options.data_morph == cli::DataMorphMode::On ||
        options.data_morph == cli::DataMorphMode::EncodeOnly) {
        if (!disc.ok() || disc->atoms.empty()) {
            MK_WARN("--data-morph: no atoms discovered; nothing to "
                    "encode (this is a no-op, not a failure)");
            return {};
        }

        // Strip Authenticode early when --data-morph is engaged: any
        // section appended past the existing payload invalidates the
        // signature, so we save the user a confusing post-scan failure
        // by zeroing the directory now. The pre-existing
        // `--strip-signature` flag is honoured the same way in
        // finalize(); doing it twice is a harmless no-op.
        // (EncodeOnly doesn't append a section, so Authenticode would
        // technically survive there, but the in-place XOR mutates
        // .rdata and any signature would still fail verification - so
        // we strip in both modes to keep the post-scan trail consistent.)
        if (image->is_pe()) {
            (void)image->strip_authenticode();
        }

        datapass::DataPassConfig dpcfg;
        dpcfg.section_name = ".morph";
        dpcfg.mode = (options.data_morph == cli::DataMorphMode::EncodeOnly)
                         ? datapass::PassMode::EncodeOnly
                         : datapass::PassMode::Full;
        // Derive a stable per-build XOR key from the seed. We only use
        // the low byte of the key today (single-byte XOR), but we feed
        // the full 32 bits through so v1.1's per-atom keys can diverge
        // without breaking the on-disk directory layout.
        const uint64_t seed_value = options.seed.value_or(0xC0FFEEull);
        dpcfg.xor_key = static_cast<uint32_t>((seed_value * 0x9E3779B97F4A7C15ull) >> 32);
        if ((dpcfg.xor_key & 0xff) == 0) dpcfg.xor_key |= 0x5Au;
        switch (options.decoder_placement) {
            case cli::DecoderPlacement::Auto:
                dpcfg.placement = datapass::DecoderPlacement::Auto; break;
            case cli::DecoderPlacement::EpThunk:
                dpcfg.placement = datapass::DecoderPlacement::EpThunk; break;
            case cli::DecoderPlacement::TlsCallback:
                dpcfg.placement = datapass::DecoderPlacement::TlsCallback; break;
        }

        auto pass_r = datapass::run_data_pass(*image, disc->atoms, dpcfg);
        if (!pass_r.ok()) {
            MK_WARN("data-morph: encoding failed: {}", pass_r.error().what);
            // Re-stamp the report's data-pass block with the failure so
            // a downstream user sees something useful.
            if (report) {
                auto cur = report->data_pass();
                cur.decoder_placement = "skipped";
                report->set_data_pass(std::move(cur));
            }
            return {};
        }
        if (report) {
            auto cur = report->data_pass();
            cur.decoder_placement   = pass_r->decoder_placement;
            cur.morph_section_size  = pass_r->morph_section_size;
            cur.morph_section_rva   = pass_r->morph_section_rva;
            cur.entry_point_changed = pass_r->entry_point_changed;
            if (!pass_r->encoded) cur.skip_reason = pass_r->skip_reason;
            report->set_data_pass(std::move(cur));
        }
    }
    return {};
}

Result<void> Orchestrator::Impl::verify(const std::vector<AppliedPatch>& applied) {
    if (options.verify == cli::Verify::Redisasm || options.verify == cli::Verify::Unicorn) {
        if (auto r = verify::redisasm_check(*image, applied); !r.ok()) return r.error();
    }
#if MORPHKATZ_WITH_UNICORN
    if (options.verify == cli::Verify::Unicorn) {
        verify::UnicornOptions uo;
        uo.timeout_ms = options.verify_timeout_ms;
        if (auto r = verify::unicorn_verify(*image, applied, uo); !r.ok()) return r.error();
    }
#endif
    return {};
}

Result<void> Orchestrator::Impl::finalize() {
    if (options.rich_header_mode != "preserve") {
        if (auto r = image->scrub_rich_header(options.rich_header_mode, rng.get()); !r.ok()) {
            return r.error();
        }
    }
    if (options.reproducible_timestamp) {
        if (auto r = image->set_timestamp(*options.reproducible_timestamp); !r.ok()) return r.error();
    }
    if (options.strip_signature) {
        if (auto r = image->strip_authenticode(); !r.ok()) return r.error();
    }
    if (options.fix_checksum) {
        if (auto r = image->fix_checksum(); !r.ok()) return r.error();
    }
    if (options.dry_run) {
        MK_INFO("--dry-run: not writing output");
        return {};
    }
    return image->save(options.output);
}

Result<void> Orchestrator::Impl::write_report() {
    if (!options.report_path) return {};
    return report->write(*options.report_path);
}

}

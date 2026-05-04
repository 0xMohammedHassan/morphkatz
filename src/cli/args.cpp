#include "morphkatz/cli/args.hpp"
#include "morphkatz/common/version.hpp"
#include "morphkatz/common/wide.hpp"

#include <CLI/CLI.hpp>

#include <filesystem>
#include <sstream>
#include <utility>
#include <vector>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

namespace morphkatz::cli {

namespace {

// Resolve the directory containing the currently running executable.
// Returns an empty path on failure; callers treat that as "not found".
std::filesystem::path exe_dir() {
#if defined(_WIN32)
    wchar_t buf[MAX_PATH] = {};
    const DWORD n = ::GetModuleFileNameW(nullptr, buf, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) return {};
    return std::filesystem::path{buf}.parent_path();
#else
    return {};
#endif
}

// Best-effort locate the bundled `rules/` directory. Probes a handful
// of locations relative to the executable so a user who unzips the
// release tarball gets sensible behavior without setting --rules.
std::filesystem::path resolve_default_rules_dir() {
    const auto base = exe_dir();
    if (base.empty()) return {};
    const std::filesystem::path candidates[] = {
        base / "rules",
        base / ".." / "rules",
        base / ".." / ".." / "rules",
        base / ".." / ".." / ".." / "rules",   // build/<preset>/<cfg>/ → repo root
    };
    for (const auto& c : candidates) {
        std::error_code ec;
        if (std::filesystem::is_directory(c, ec)) {
            return std::filesystem::weakly_canonical(c, ec);
        }
    }
    return {};
}

void install(CLI::App& app,
             Options& opts,
             CompareOptions& copts,
             ScanOptions& sopts,
             CLI::App*& sub_compare_out,
             CLI::App*& sub_scan_out,
             bool& show_version) {
    // Override argv[0] so the usage line reads "morphkatz" instead of a
    // full Windows path like "C:\Users\...\build\Release\morphkatz.exe".
    app.name("morphkatz");
    app.description("MorphKatz - polymorphic machine-code rewriter for Windows x64 binaries.");
    app.footer("Examples:\n"
               "  morphkatz payload.exe --seed 42 --report report.json\n"
               "  morphkatz shell.bin --profile aggressive --verify unicorn\n"
               "  morphkatz target.exe --target yara/*.yar -vv\n"
               "  morphkatz payload.exe --seed 1 --variants 8 --report batch.json\n"
               "  morphkatz compare v0.bin v1.bin v2.bin --report cmp.json\n"
               "\n"
               "Full docs: https://github.com/0xMohammedHassan/morphkatz\n");
    app.get_formatter()->column_width(36);
    app.set_version_flag("--version,-V", "", "Print version and exit");
    app.require_subcommand(0, 1);

    // NB: CLI11 treats a bound version flag as opt-in; we expose our own richer
    // version printer from main(). This flag here exists so --version parses
    // without tripping "missing input" validation.
    app.add_flag_callback("--print-version-banner",
        [&]() { show_version = true; },
        "Alias for --version (internal)");

    // Required when the user doesn't invoke a subcommand; we validate
    // this post-parse instead of via CLI11's ->required() so that
    // `morphkatz compare a b` doesn't fail on "missing input".
    app.add_option("input", opts.input, "Input PE executable or raw shellcode")
        ->check(CLI::ExistingFile);

    auto* g_io = app.add_option_group("Input/output");
    g_io->add_option("-o,--output", opts.output, "Output path (default: <input>.patched)");
    g_io->add_flag("--backup,!--no-backup", opts.backup, "Write <input>.bak (default: on)");
    g_io->add_flag("--in-place", opts.in_place, "Overwrite input (requires --no-backup)");

    auto* g_mode = app.add_option_group("Modes");
    std::map<std::string, Profile> profile_map{
        {"safe", Profile::Safe}, {"normal", Profile::Normal}, {"aggressive", Profile::Aggressive}};
    g_mode->add_option("--profile", opts.profile, "Rewrite profile")
        ->transform(CLI::CheckedTransformer(profile_map, CLI::ignore_case))
        ->default_str("normal");
    g_mode->add_option("--target", opts.yara_target,
                      "YARA rules file; prioritise rewrites that break listed atoms")
        ->check(CLI::ExistingFile);
    g_mode->add_option("--rules", opts.extra_rule_paths,
                      "Extra YAML rule packs (file or directory, repeatable)")
        ->expected(0, -1);

    auto* g_poly = app.add_option_group("Polymorphism");
    g_poly->add_option("--seed", opts.seed,
                      "Reproducible run (u64). Omitted = cryptographic random.");
    g_poly->add_option("--mutation-budget", opts.mutation_budget,
                      "Max rewrites per basic block (-1 = unlimited)");
    g_poly->add_option("--variants", opts.variants,
                      "Emit N deterministic morphs (each with a splitmix64-derived seed). "
                      "Outputs go to <output>_v<i>.<ext>; requires --seed for reproducibility.")
        ->check(CLI::Range(1, 1000));

    auto* g_verify = app.add_option_group("Verification");
    std::map<std::string, Verify> verify_map{
        {"none", Verify::None}, {"redisasm", Verify::Redisasm}, {"unicorn", Verify::Unicorn}};
    g_verify->add_option("--verify", opts.verify, "Post-patch verification strategy")
        ->transform(CLI::CheckedTransformer(verify_map, CLI::ignore_case))
        ->default_str("redisasm");
    g_verify->add_option("--verify-timeout-ms", opts.verify_timeout_ms, "Per-block emulator timeout")
        ->check(CLI::Range(1, 300'000));
    g_verify->add_flag("--rollback-on-verify-failure,!--no-rollback-on-verify-failure",
                       opts.rollback_on_verify_failure,
                       "Restore original bytes when verify fails (default: on)");

    auto* g_pe = app.add_option_group("PE options");
    g_pe->add_flag("--fix-checksum,!--no-fix-checksum", opts.fix_checksum, "Recompute PE checksum");
    g_pe->add_flag("--strip-signature", opts.strip_signature, "Remove Authenticode signature if present");
    g_pe->add_option("--reproducible-timestamp", opts.reproducible_timestamp,
                    "Override TimeDateStamp with this unix timestamp");
    g_pe->add_option("--rich-header", opts.rich_header_mode,
                    "preserve (default) | strip | randomize the Rich header")
        ->check(CLI::IsMember({"preserve", "strip", "randomize"}));

    auto* g_report = app.add_option_group("Reporting");
    g_report->add_option("--report", opts.report_path,
                        "Write a diff report (.json or .html based on extension)");
    g_report->add_flag("--dry-run", opts.dry_run, "Analyse and report without writing output");
    g_report->add_flag("--stats", opts.stats, "Print per-rule hit counts at end");
    g_report->add_flag("-v,--verbose", opts.verbosity, "Repeatable (-v, -vv, -vvv)");
    g_report->add_flag("-q,--quiet", opts.quiet, "Suppress stderr log sink");
    g_report->add_option("--log-file", opts.log_file, "Write full log to this file");

    auto* g_scan = app.add_option_group("Detection feedback");
    g_scan->add_option("--target-defender", opts.defender_target,
                       "Reference binary to pre-/post-scan with Microsoft Defender. "
                       "Anchors learned via multi-anchor bisection feed the rule "
                       "matcher's priority weighting.")
        ->check(CLI::ExistingFile);
    g_scan->add_flag("--auto-yara,!--no-auto-yara", opts.auto_yara,
                     "Auto-load a bundled YARA hint pack when --target-defender "
                     "flags a known family (default: on). Ignored when --target "
                     "is explicitly set.");

    auto* g_data = app.add_option_group("Data-section morphing");
    std::map<std::string, DataMorphMode> dm_map{
        {"off", DataMorphMode::Off},
        {"plan", DataMorphMode::Plan},
        {"encode-only", DataMorphMode::EncodeOnly},
        {"encode_only", DataMorphMode::EncodeOnly},
        {"encodeonly",  DataMorphMode::EncodeOnly},
        {"on", DataMorphMode::On}};
    auto* dm_opt = g_data->add_option("--data-morph", opts.data_morph,
                       "Atom-mutation pass for .rdata/.data: "
                       "off (default), plan (dry-run; print atoms and exit), "
                       "encode-only (XOR atoms in place, no decoder; output "
                       "passes static scan but will not run; for "
                       "detection-engineering only), "
                       "on (encode atoms + emit runtime decoder).");
    dm_opt->transform(CLI::CheckedTransformer(dm_map, CLI::ignore_case))
        ->default_str("off");
    // Track explicit user choice so --target-defender's auto-escalation
    // can stand down when the user pinned a value. CLI11 routes the
    // parsed value through `each` once per occurrence; we only need
    // the side effect, not the value itself.
    dm_opt->each([&](const std::string&) { opts.data_morph_explicit = true; });
    std::map<std::string, DecoderPlacement> dp_map{
        {"auto", DecoderPlacement::Auto},
        {"ep-thunk", DecoderPlacement::EpThunk},
        {"ep_thunk", DecoderPlacement::EpThunk},
        {"epthunk",  DecoderPlacement::EpThunk},
        {"tls-callback", DecoderPlacement::TlsCallback},
        {"tls_callback", DecoderPlacement::TlsCallback},
        {"tlscallback",  DecoderPlacement::TlsCallback}};
    g_data->add_option("--decoder-placement", opts.decoder_placement,
                       "Where to install the runtime decoder: "
                       "auto (default; prefer TLS, fall back to EP), "
                       "ep-thunk (always patch AddressOfEntryPoint), or "
                       "tls-callback (always install as first TLS callback).")
        ->transform(CLI::CheckedTransformer(dp_map, CLI::ignore_case))
        ->default_str("auto");
    g_data->add_option("--data-morph-min-len", opts.data_morph_min_len,
                       "Minimum atom length to encode (bytes; default 4)")
        ->check(CLI::Range(1, 1 << 16));
    g_data->add_option("--data-morph-max-len", opts.data_morph_max_len,
                       "Maximum atom length to encode (bytes; default 4096)")
        ->check(CLI::Range(1, 1 << 20));

    // ----------------------------------------------------------------
    // `compare` subcommand - pairwise byte/histogram diff of 2+ files.
    // ----------------------------------------------------------------
    auto* sub_cmp = app.add_subcommand("compare",
        "Compare 2+ binaries (bytes, SHA-256, entropy, byte-histogram cosine).");
    sub_cmp->add_option("inputs", copts.inputs,
                        "Two or more existing files to compare")
        ->expected(2, -1)
        ->check(CLI::ExistingFile)
        ->required();
    sub_cmp->add_option("--report", copts.report_path,
                        "Write comparison report (.json or .html by extension)");
    sub_cmp->add_flag("-v,--verbose", copts.verbosity, "Repeatable (-v, -vv, -vvv)");
    sub_cmp->add_flag("-q,--quiet",   copts.quiet,     "Suppress stderr log sink");
    sub_cmp->add_option("--log-file", copts.log_file,  "Write full log to this file");
    sub_compare_out = sub_cmp;

    // ----------------------------------------------------------------
    // `scan` subcommand - run the configured Defender scanner against
    // a single file, optionally bisecting to find the offending byte
    // window. Mirrors the `compare` subcommand wiring.
    // ----------------------------------------------------------------
    auto* sub_scan = app.add_subcommand("scan",
        "Scan a file with Microsoft Defender (Tier-1, MpCmdRun-backed). "
        "Use --bisect to isolate the smallest detected byte window.");
    sub_scan->add_option("input", sopts.input,
                         "File to scan (PE, shellcode, or any blob)")
        ->check(CLI::ExistingFile)
        ->required();
    sub_scan->add_flag("--bisect", sopts.bisect,
                       "Find the smallest detected chunk via half-and-half bisection");
    sub_scan->add_option("--bisect-mode", sopts.bisect_mode,
                       "single (v1) | all (reserved for v1.1)")
        ->check(CLI::IsMember({"single", "all"}));
    sub_scan->add_option("--bisect-scope", sopts.bisect_scope,
                       "PE-aware mask scope: sections (default; section "
                       "raw data minus parsed data-directory windows), "
                       "sections-all (incl. directories), code, data, or "
                       "raw (legacy slice-and-scan, can give false-clean "
                       "verdicts on truncated PEs).")
        ->check(CLI::IsMember({"sections", "sections-all", "code", "data", "raw"}));
    sub_scan->add_option("--engine", sopts.engine,
                       "cli (Tier-1, MpCmdRun) | amsi (reserved for v0.2)")
        ->check(CLI::IsMember({"cli", "amsi"}));
    sub_scan->add_option("--report", sopts.report_path,
                       "Write structured scan report (.json or .html by extension)");
    sub_scan->add_flag("--strict-preconditions,!--no-strict-preconditions",
                       sopts.strict_preconditions,
                       "Hard-fail when MAPS/SubmitSamples/RTP aren't off (default: on)");
    sub_scan->add_option("--mpcmdrun", sopts.mpcmdrun_path,
                       "Override MpCmdRun.exe auto-discovery")
        ->check(CLI::ExistingFile);
    sub_scan->add_option("--temp-dir", sopts.temp_dir,
                       "Override scan temp directory");
    sub_scan->add_option("--timeout-ms", sopts.timeout_ms,
                       "Per-scan timeout in milliseconds (default 60000)")
        ->check(CLI::Range(1000, 600'000));
    sub_scan->add_flag("-v,--verbose", sopts.verbosity, "Repeatable (-v, -vv, -vvv)");
    sub_scan->add_flag("-q,--quiet",   sopts.quiet,     "Suppress stderr log sink");
    sub_scan->add_option("--log-file", sopts.log_file,  "Write full log to this file");
    sub_scan_out = sub_scan;
}

}  // namespace

ParsedOr<ParseResult> parse(int argc, const char* const* argv) {
    CLI::App app{"morphkatz"};
    Options        opts;
    CompareOptions copts;
    ScanOptions    sopts;
    bool           show_version = false;
    CLI::App*      sub_compare  = nullptr;
    CLI::App*      sub_scan     = nullptr;

    install(app, opts, copts, sopts, sub_compare, sub_scan, show_version);

    try {
        app.parse(argc, argv);
    } catch (const CLI::CallForHelp&) {
        ParseResult pr;
        pr.action    = Action::ShowHelp;
        pr.help_text = app.help();
        return pr;
    } catch (const CLI::CallForAllHelp&) {
        ParseResult pr;
        pr.action    = Action::ShowHelp;
        pr.help_text = app.help();
        return pr;
    } catch (const CLI::CallForVersion&) {
        ParseResult pr;
        pr.action = Action::ShowVersion;
        return pr;
    } catch (const CLI::ParseError& e) {
        // CLI11's app.exit() already formats and writes the message to
        // stderr. Leave `what` empty so main() doesn't double-print it.
        return ParseError{ "", app.exit(e) };
    }

    if (show_version) {
        ParseResult pr;
        pr.action = Action::ShowVersion;
        return pr;
    }

    if (sub_compare && sub_compare->parsed()) {
        ParseResult pr;
        pr.action  = Action::Compare;
        pr.compare = std::move(copts);
        return pr;
    }

    if (sub_scan && sub_scan->parsed()) {
        ParseResult pr;
        pr.action = Action::Scan;
        pr.scan   = std::move(sopts);
        return pr;
    }

    // morph (default) mode: `input` is mandatory when no subcommand ran.
    if (opts.input.empty()) {
        // Zero args at all? Return the sentinel so main() can show the
        // friendly first-run banner instead of a bare error message.
        if (argc <= 1) {
            ParseResult pr;
            pr.action = Action::ShowBanner;
            return pr;
        }
        return ParseError{
            "missing required argument: input "
            "(provide a PE file, or use the 'compare' subcommand). "
            "Run 'morphkatz --help' for options.",
            1
        };
    }

    // Default output keeps the original extension so Windows still
    // recognizes it: foo.exe -> foo.patched.exe (not foo.exe.patched).
    if (opts.output.empty() && !opts.in_place) {
        auto stem = opts.input;
        const auto ext = opts.input.extension();  // ".exe", ".dll", or ""
        stem.replace_extension();                 // strip
        stem += ".patched";
        stem += ext;                              // reapply
        opts.output = stem;
    }
    if (opts.in_place) {
        opts.output = opts.input;
    }

    // If the user didn't override --rules and didn't supply a default
    // path up-front (tests do this with MORPHKATZ_RULES_DIR), try to
    // auto-discover the shipped pack next to the executable.
    if (opts.default_rules_dir.empty()) {
        opts.default_rules_dir = resolve_default_rules_dir();
    }

    ParseResult pr;
    pr.action  = Action::Run;
    pr.options = std::move(opts);
    return pr;
}

ParsedOr<ParseResult> parse(int argc, wchar_t** argv) {
    std::vector<std::string>  utf8_storage;
    std::vector<const char*>  utf8_argv;
    utf8_storage.reserve(static_cast<size_t>(argc));
    utf8_argv.reserve(static_cast<size_t>(argc) + 1);
    for (int i = 0; i < argc; ++i) {
        utf8_storage.emplace_back(to_utf8(argv[i] ? argv[i] : L""));
        utf8_argv.push_back(utf8_storage.back().c_str());
    }
    utf8_argv.push_back(nullptr);
    return parse(argc, utf8_argv.data());
}

}

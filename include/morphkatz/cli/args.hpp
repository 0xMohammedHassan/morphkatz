#pragma once

#include "morphkatz/common/error.hpp"

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace morphkatz::cli {

enum class Profile  : unsigned { Safe, Normal, Aggressive };
enum class Verify   : unsigned { None, Redisasm, Unicorn };
enum class Action   : unsigned { Run, ShowVersion, ShowHelp, ShowBanner, Compare, Scan };

// Behavior of the .rdata/.data atom-mutation pass.
//   Off        - default; pass is a no-op even if `--target` finds atoms.
//   Plan       - dry-run discovery: emit the atom list (JSON to stderr or
//                to --report when set) and exit before any mutation. Use
//                this to validate atom selection on a new sample.
//   EncodeOnly - discover atoms and XOR-encode them in place on disk, but
//                do NOT append a decoder section and do NOT redirect the
//                entry point. The output passes static AV scans by
//                construction (no runtime decoder shape to fingerprint)
//                but will NOT execute correctly. Intended use case is
//                detection-engineering coverage testing where the
//                artifact is never run; see docs/data-morph.md.
//   On         - full pass: discover atoms, encode them on disk, append
//                the decoder section, install the runtime decode hook.
enum class DataMorphMode : unsigned { Off, Plan, EncodeOnly, On };

// Where the runtime decoder lives in the morphed PE.
//   Auto      - prefer TLS callback when feasible, fall back to EP-thunk.
//   EpThunk   - patch AddressOfEntryPoint; runs after existing TLS callbacks.
//   TlsCallback - install as the first TLS callback; always runs first.
enum class DecoderPlacement : unsigned { Auto, EpThunk, TlsCallback };

struct Options {
    std::filesystem::path input;
    std::filesystem::path output;
    bool backup           = true;
    bool in_place         = false;

    Profile profile       = Profile::Normal;
    std::optional<std::filesystem::path> yara_target;
    std::vector<std::filesystem::path>   extra_rule_paths;
    std::filesystem::path default_rules_dir;     // auto-resolved from exe dir

    // When true (the default) and `--target-defender` flags a known
    // family (e.g. Mimikatz), the orchestrator auto-loads a bundled
    // YARA hint pack from `<rules>/yara/x64/<family>.yar` if the user
    // didn't already pass one via `--target`. `--no-auto-yara` disables
    // this path entirely.
    bool auto_yara       = true;

    std::optional<uint64_t> seed;
    int  mutation_budget  = -1;                  // -1 = unlimited
    int  variants         = 1;                   // batch N deterministic morphs

    Verify verify         = Verify::Redisasm;
    int    verify_timeout_ms = 5000;
    bool   rollback_on_verify_failure = true;

    bool fix_checksum     = true;
    bool strip_signature  = false;
    std::optional<int64_t> reproducible_timestamp;
    std::string            rich_header_mode = "preserve";   // preserve|strip|randomize

    std::optional<std::filesystem::path> report_path;
    bool dry_run          = false;
    bool stats            = false;

    // Optional Defender feedback loop. When set, the orchestrator builds
    // a `scan::DefenderTarget` from this reference path before mutating
    // the input, blends its per-VA priorities into the rule matcher,
    // and post-scans the output to populate the report's defender block.
    std::optional<std::filesystem::path> defender_target;

    // Atom-mutation pass (`.rdata`/`.data` morphing). See DataMorphMode.
    // The Plan variant is read-only and exits before finalize().
    DataMorphMode    data_morph        = DataMorphMode::Off;
    // True only when the user passed `--data-morph` explicitly. The
    // `--target-defender` orchestrator flips this to `On` automatically
    // when bisect anchors land in `.rdata`/`.data`, but only if the
    // user didn't pin a value themselves. See `data_pass()` in
    // `engine/orchestrator.cpp`.
    bool             data_morph_explicit = false;
    DecoderPlacement decoder_placement = DecoderPlacement::Auto;
    uint32_t         data_morph_min_len = 4;
    uint32_t         data_morph_max_len = 4096;

    int  verbosity        = 0;
    bool quiet            = false;
    std::filesystem::path log_file;
};

struct CompareOptions {
    std::vector<std::filesystem::path> inputs;
    std::optional<std::filesystem::path> report_path;  // .json or .html
    int  verbosity = 0;
    bool quiet     = false;
    std::filesystem::path log_file;
};

// Options for the `morphkatz scan` subcommand. Mirrors `CompareOptions`
// for the standard verbosity / report knobs and adds the Tier-1 scanner
// configuration. Kept separate from `Options` so the two parsers don't
// drift in subtle ways.
struct ScanOptions {
    std::filesystem::path input;
    std::optional<std::filesystem::path> report_path;     // .json or .html

    bool        bisect              = false;
    std::string bisect_mode         = "single";          // single|all (v1 only single)
    // PE-aware scope for the bisect's mask. `sections` (default) keeps
    // the buffer parseable on every iteration by only masking inside
    // section payloads minus parsed data-directory windows. `raw`
    // disables PE-awareness and falls back to legacy slice-and-scan,
    // which can give false-clean verdicts on truncated PEs.
    std::string bisect_scope        = "sections";        // sections|sections-all|code|data|raw
    std::string engine              = "cli";             // cli|amsi (v1 only cli)

    bool        strict_preconditions = true;
    std::optional<std::filesystem::path> mpcmdrun_path;
    std::optional<std::filesystem::path> temp_dir;
    int         timeout_ms          = 60'000;

    int  verbosity = 0;
    bool quiet     = false;
    std::filesystem::path log_file;
};

struct ParseError {
    std::string what;
    int         exit_code = 1;
};

struct ParseResult {
    Action          action = Action::Run;
    Options         options;
    CompareOptions  compare;
    ScanOptions     scan;
    std::string     help_text;
};

// Result type: success carries ParseResult, failure carries ParseError with
// a non-zero exit code (1 for bad args, 0 for --help/--version handled early).
template <typename T>
class ParsedOr {
public:
    ParsedOr(T value) : ok_{true}, value_{std::move(value)} {}
    ParsedOr(ParseError err) : ok_{false}, error_{std::move(err)} {}

    [[nodiscard]] bool ok() const noexcept { return ok_; }
    [[nodiscard]] explicit operator bool() const noexcept { return ok_; }
    T& operator*() { return value_; }
    const T& operator*() const { return value_; }
    T* operator->() { return &value_; }
    const T* operator->() const { return &value_; }

    const ParseError& error() const { return error_; }

private:
    bool       ok_;
    T          value_{};
    ParseError error_{};
};

// Windows-only wide entrypoint parser. Converts UTF-16 argv to UTF-8 at the boundary.
ParsedOr<ParseResult> parse(int argc, wchar_t** argv);

// Overload for ASCII/test use.
ParsedOr<ParseResult> parse(int argc, const char* const* argv);

}

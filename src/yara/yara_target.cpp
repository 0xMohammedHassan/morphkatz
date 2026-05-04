#include "morphkatz/yara/yara_target.hpp"

#include "morphkatz/common/logging.hpp"

#if MORPHKATZ_WITH_YARA
#  include <yara.h>
#endif

#include <algorithm>
#include <cstdio>
#include <utility>

namespace morphkatz::yara_target {

#if MORPHKATZ_WITH_YARA

namespace {

// Process-scoped YARA init/finalize guard. yr_initialize() is idempotent
// (it uses an internal refcount), but pairing one init with one finalize
// at process lifetime is simpler than threading the refcount through the
// PriorityMap move/destruction graph and stays correct even on exceptional
// load() paths.
class YaraContext {
public:
    static YaraContext& instance() {
        static YaraContext ctx;
        return ctx;
    }
    [[nodiscard]] bool ok() const noexcept { return ok_; }

private:
    YaraContext() {
        ok_ = (yr_initialize() == ERROR_SUCCESS);
    }
    ~YaraContext() {
        if (ok_) yr_finalize();
    }
    YaraContext(const YaraContext&)            = delete;
    YaraContext& operator=(const YaraContext&) = delete;
    bool ok_ = false;
};

}  // namespace

// Compiled YR_RULES handle kept alive for the life of the PriorityMap. The
// process-wide YaraContext above handles yr_initialize/yr_finalize; this
// struct is a pure RAII wrapper around the rules handle.
struct PriorityMap::Compiled {
    YR_RULES* rules = nullptr;

    Compiled() = default;
    Compiled(Compiled&& other) noexcept : rules(other.rules) { other.rules = nullptr; }
    Compiled& operator=(Compiled&& other) noexcept {
        if (this != &other) {
            if (rules) yr_rules_destroy(rules);
            rules = other.rules;
            other.rules = nullptr;
        }
        return *this;
    }
    ~Compiled() {
        if (rules) yr_rules_destroy(rules);
    }
    Compiled(const Compiled&) = delete;
    Compiled& operator=(const Compiled&) = delete;
};

#else

struct PriorityMap::Compiled {};

#endif

PriorityMap::PriorityMap(std::vector<Atom> atoms,
                         size_t rule_count,
                         std::unique_ptr<Compiled> compiled)
    : atoms_(std::move(atoms)),
      rule_count_(rule_count),
      compiled_(std::move(compiled)) {}

PriorityMap::PriorityMap(std::vector<Atom> atoms, size_t rule_count)
    : atoms_(std::move(atoms)),
      rule_count_(rule_count),
      compiled_(nullptr) {}

PriorityMap::~PriorityMap() = default;
PriorityMap::PriorityMap(PriorityMap&&) noexcept = default;
PriorityMap& PriorityMap::operator=(PriorityMap&&) noexcept = default;

double PriorityMap::boost_for(uint64_t /*va*/,
                              std::span<const uint8_t> old_bytes,
                              std::span<const uint8_t> new_bytes) const noexcept {
    // A candidate rewrite "breaks" an atom iff the original slot contains the
    // atom byte sequence and the replacement does not. Both sides are at
    // most ~15 bytes and the atom pool is small, so the linear scan is cheap.
    if (atoms_.empty()) return 0.0;
    double boost = 0.0;
    auto contains = [](std::span<const uint8_t> hay,
                       std::span<const uint8_t> needle) noexcept -> bool {
        if (needle.empty() || hay.size() < needle.size()) return false;
        const auto n = hay.size() - needle.size();
        for (size_t i = 0; i <= n; ++i) {
            if (std::equal(needle.begin(), needle.end(), hay.begin() + i)) return true;
        }
        return false;
    };
    for (const auto& a : atoms_) {
        if (contains(old_bytes, a.bytes) && !contains(new_bytes, a.bytes)) {
            boost = std::max(boost, a.weight);
        }
    }
    return boost;
}

#if MORPHKATZ_WITH_YARA

namespace {

void yr_compiler_error_cb(int /*level*/, const char* file, int line,
                          const YR_RULE* /*rule*/, const char* msg, void* /*user*/) {
    MK_WARN("yara compile: {}:{}: {}", file ? file : "?", line, msg ? msg : "");
}

void collect_atoms(YR_RULES* rules,
                   std::vector<PriorityMap::Atom>& out,
                   size_t& rule_count) {
    YR_RULE* rule;
    yr_rules_foreach(rules, rule) {
        ++rule_count;
        YR_STRING* str;
        yr_rule_strings_foreach(rule, str) {
            if (!str->string || str->length == 0) continue;
            // YARA stores each pattern's literal prefix in `string`. For hex
            // strings with wildcards this is the fixed anchor; for text
            // strings it is the raw UTF-8. Cap at 16 bytes — YARA's own
            // upper bound for Aho-Corasick atoms.
            const auto len = std::min<uint32_t>(static_cast<uint32_t>(str->length), 16u);
            PriorityMap::Atom a;
            a.bytes.assign(str->string, str->string + len);
            a.rule_name = rule->identifier ? rule->identifier : "";
            a.weight    = 1.0;
            out.push_back(std::move(a));
        }
    }
}

struct ScanCtx {
    std::vector<std::string> hits;
};

int yr_scan_cb(YR_SCAN_CONTEXT* /*ctx*/,
               int message,
               void* message_data,
               void* user_data) {
    auto* sc = static_cast<ScanCtx*>(user_data);
    if (message == CALLBACK_MSG_RULE_MATCHING) {
        const auto* rule = static_cast<const YR_RULE*>(message_data);
        if (rule && rule->identifier) sc->hits.emplace_back(rule->identifier);
    }
    return CALLBACK_CONTINUE;
}

struct OffsetCtx {
    const uint8_t*                            data    = nullptr;
    size_t                                    size    = 0;
    std::vector<PriorityMap::MatchHit>* out    = nullptr;
};

// Scan callback that records per-string match offsets via YARA's
// CALLBACK_MSG_RULE_MATCHING + iter_string_matches API. We deliberately
// skip rules that don't have any concrete byte matches (e.g. pure
// `condition: ...` rules that only reference filesize) - they're not
// useful for an atom-mutation pipeline.
int yr_scan_offsets_cb(YR_SCAN_CONTEXT* ctx,
                       int message,
                       void* message_data,
                       void* user_data) {
    auto* oc = static_cast<OffsetCtx*>(user_data);
    if (message != CALLBACK_MSG_RULE_MATCHING) return CALLBACK_CONTINUE;

    const auto* rule = static_cast<const YR_RULE*>(message_data);
    if (!rule || !rule->identifier || !ctx) return CALLBACK_CONTINUE;
    const std::string rule_name = rule->identifier;

    YR_STRING* str = nullptr;
    yr_rule_strings_foreach(rule, str) {
        if (!str) continue;
        YR_MATCH* m = nullptr;
        yr_string_matches_foreach(ctx, str, m) {
            if (!m) continue;
            const auto off = static_cast<size_t>(m->offset);
            const auto len = static_cast<size_t>(m->match_length);
            if (len == 0 || off > oc->size) continue;
            const auto end = off + len;
            if (end > oc->size) continue;

            PriorityMap::MatchHit hit;
            hit.rule_name = rule_name;
            hit.offset    = off;
            hit.length    = len;
            hit.bytes.assign(oc->data + off, oc->data + end);
            oc->out->push_back(std::move(hit));
        }
    }
    return CALLBACK_CONTINUE;
}

}  // namespace

std::vector<std::string> PriorityMap::scan(std::span<const uint8_t> data) const {
    if (!compiled_ || !compiled_->rules) return {};
    ScanCtx sc;
    const int rc = yr_rules_scan_mem(compiled_->rules,
                                     const_cast<uint8_t*>(data.data()),
                                     data.size(),
                                     /*flags=*/0,
                                     yr_scan_cb,
                                     &sc,
                                     /*timeout=*/0);
    if (rc != ERROR_SUCCESS) {
        MK_WARN("yr_rules_scan_mem failed: {}", rc);
    }
    return sc.hits;
}

std::vector<PriorityMap::MatchHit>
PriorityMap::scan_with_offsets(std::span<const uint8_t> data) const {
    if (!compiled_ || !compiled_->rules) return {};
    std::vector<MatchHit> out;
    OffsetCtx oc{};
    oc.data = data.data();
    oc.size = data.size();
    oc.out  = &out;
    const int rc = yr_rules_scan_mem(compiled_->rules,
                                     const_cast<uint8_t*>(data.data()),
                                     data.size(),
                                     /*flags=*/0,
                                     yr_scan_offsets_cb,
                                     &oc,
                                     /*timeout=*/0);
    if (rc != ERROR_SUCCESS) {
        MK_WARN("yr_rules_scan_mem (offsets) failed: {}", rc);
    }
    return out;
}

Result<std::unique_ptr<PriorityMap>> load(const std::filesystem::path& yar_file) {
    if (!YaraContext::instance().ok()) {
        return Error::make(ErrorKind::RuleLoad, "yr_initialize failed");
    }

    YR_COMPILER* comp = nullptr;
    if (yr_compiler_create(&comp) != ERROR_SUCCESS) {
        return Error::make(ErrorKind::RuleLoad, "yr_compiler_create failed");
    }
    yr_compiler_set_callback(comp, yr_compiler_error_cb, nullptr);

    FILE* f = nullptr;
#if defined(_WIN32)
    _wfopen_s(&f, yar_file.wstring().c_str(), L"rb");
#else
    f = std::fopen(yar_file.string().c_str(), "rb");
#endif
    if (!f) {
        yr_compiler_destroy(comp);
        return Error::make(ErrorKind::Io, "cannot open yara rules", yar_file.string());
    }

    const int errs = yr_compiler_add_file(comp, f, nullptr, yar_file.string().c_str());
    std::fclose(f);
    if (errs > 0) {
        yr_compiler_destroy(comp);
        return Error::make(ErrorKind::RuleLoad, "yara rule compile reported errors");
    }

    YR_RULES* rules = nullptr;
    if (yr_compiler_get_rules(comp, &rules) != ERROR_SUCCESS) {
        yr_compiler_destroy(comp);
        return Error::make(ErrorKind::RuleLoad, "yr_compiler_get_rules failed");
    }
    yr_compiler_destroy(comp);

    auto compiled = std::make_unique<PriorityMap::Compiled>();
    compiled->rules = rules;

    std::vector<PriorityMap::Atom> atoms;
    size_t rule_count = 0;
    collect_atoms(rules, atoms, rule_count);

    MK_DEBUG("YARA: compiled {} rules, {} atoms", rule_count, atoms.size());
    return std::make_unique<PriorityMap>(std::move(atoms), rule_count, std::move(compiled));
}

#else

std::vector<std::string> PriorityMap::scan(std::span<const uint8_t> /*data*/) const {
    return {};
}

std::vector<PriorityMap::MatchHit>
PriorityMap::scan_with_offsets(std::span<const uint8_t> /*data*/) const {
    return {};
}

Result<std::unique_ptr<PriorityMap>> load(const std::filesystem::path& /*yar_file*/) {
    return Error::make(ErrorKind::NotSupported,
        "build was compiled without MORPHKATZ_WITH_YARA");
}

#endif

}

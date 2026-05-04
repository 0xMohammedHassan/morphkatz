#pragma once

#include "morphkatz/cli/args.hpp"
#include "morphkatz/common/error.hpp"
#include "morphkatz/rules/rule.hpp"

#include <filesystem>
#include <memory>
#include <vector>

namespace morphkatz::rules {

struct LoaderOptions {
    cli::Profile profile = cli::Profile::Normal;
    std::filesystem::path default_rules_dir;
    std::vector<std::filesystem::path> extra_paths;
};

class RulePack {
public:
    explicit RulePack(std::vector<Rule> rules, std::vector<std::string> packs);
    [[nodiscard]] const std::vector<Rule>& rules() const noexcept { return rules_; }
    [[nodiscard]] size_t rule_count() const noexcept { return rules_.size(); }
    [[nodiscard]] size_t pack_count() const noexcept { return packs_.size(); }
    [[nodiscard]] const std::vector<std::string>& pack_names() const noexcept { return packs_; }

private:
    std::vector<Rule>         rules_;
    std::vector<std::string>  packs_;
};

// Load every YAML rule pack under `default_rules_dir` plus any extras.
// The profile controls which tags are activated (safe/normal/aggressive).
Result<std::unique_ptr<RulePack>> load_all(const LoaderOptions& opts);

// Expose the single-file loader for unit tests.
Result<std::vector<Rule>> load_file(const std::filesystem::path& yaml_path);

}

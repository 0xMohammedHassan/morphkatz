#pragma once

#include "morphkatz/rules/rule_matcher.hpp"

#include <vector>

namespace morphkatz::disasm { struct BasicBlock; }

namespace morphkatz::engine {

class Rng;

// Polymorph picks which candidates to apply out of the matcher's output.
// Strategy: group by source VA, take a weighted-reservoir pick per VA,
// respecting --mutation-budget. Because all draws go through the seeded
// xoshiro256** RNG, results are fully reproducible for a given --seed.
class Polymorph {
public:
    explicit Polymorph(Rng& rng);

    // Returns the subset of `candidates` chosen for application.
    [[nodiscard]] std::vector<rules::Candidate> select(
        const disasm::BasicBlock& block,
        std::vector<rules::Candidate> candidates,
        int mutation_budget);

private:
    Rng& rng_;
};

}

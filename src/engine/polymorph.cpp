#include "morphkatz/engine/polymorph.hpp"

#include "morphkatz/disasm/cfg.hpp"
#include "morphkatz/engine/rng.hpp"

#include <algorithm>
#include <unordered_map>
#include <vector>

namespace morphkatz::engine {

Polymorph::Polymorph(Rng& rng) : rng_(rng) {}

std::vector<rules::Candidate> Polymorph::select(
    const disasm::BasicBlock& /*block*/,
    std::vector<rules::Candidate> candidates,
    int mutation_budget) {
    // Group candidates by source VA so we pick at most one rewrite per
    // instruction; this guarantees we don't double-encode the same slot.
    std::unordered_map<uint64_t, std::vector<size_t>> by_va;
    by_va.reserve(candidates.size());
    for (size_t i = 0; i < candidates.size(); ++i) {
        by_va[candidates[i].source.va].push_back(i);
    }

    std::vector<rules::Candidate> chosen;
    chosen.reserve(by_va.size());

    // Deterministic iteration order: sort the VAs ascending.
    std::vector<uint64_t> vas;
    vas.reserve(by_va.size());
    for (const auto& [va, _] : by_va) vas.push_back(va);
    std::sort(vas.begin(), vas.end());

    for (uint64_t va : vas) {
        const auto& idxs = by_va[va];
        std::vector<double> weights;
        weights.reserve(idxs.size());
        for (auto i : idxs) {
            weights.push_back(candidates[i].weight * (1.0 + candidates[i].priority_boost));
        }
        const auto pick = rng_.weighted_pick(weights);
        if (pick < 0) continue;
        chosen.push_back(std::move(candidates[idxs[static_cast<size_t>(pick)]]));
    }

    if (mutation_budget >= 0 && chosen.size() > static_cast<size_t>(mutation_budget)) {
        // Partial Fisher-Yates: only shuffle the last `budget` slots.
        // For each tail index i from N-1 down to N-budget, swap chosen[i]
        // with chosen[rng.range(i)] (inclusive; see Rng::range). The
        // invariant of the classical Fisher-Yates algorithm guarantees
        // the resulting subset is a uniform random `budget`-sample of
        // the input, and the work is O(budget) instead of O(N).
        const auto budget = static_cast<size_t>(mutation_budget);
        const auto n      = chosen.size();
        const auto tail_begin = n - budget;
        for (size_t i = n - 1; i >= tail_begin && i > 0; --i) {
            const auto j = rng_.range(static_cast<uint64_t>(i));
            std::swap(chosen[i], chosen[static_cast<size_t>(j)]);
            if (i == tail_begin) break;
        }
        // Move the sampled tail to the front and truncate.
        std::move(chosen.begin() + static_cast<std::ptrdiff_t>(tail_begin),
                  chosen.end(),
                  chosen.begin());
        chosen.resize(budget);
    }
    return chosen;
}

}

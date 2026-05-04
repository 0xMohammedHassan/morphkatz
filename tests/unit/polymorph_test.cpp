#include "morphkatz/disasm/cfg.hpp"
#include "morphkatz/engine/polymorph.hpp"
#include "morphkatz/engine/rng.hpp"
#include "morphkatz/rules/rule_matcher.hpp"

#include <catch2/catch_test_macros.hpp>

TEST_CASE("Polymorph picks at most one candidate per source VA", "[engine][polymorph]") {
    morphkatz::engine::Rng rng(uint64_t{0});
    morphkatz::engine::Polymorph poly(rng);

    std::vector<morphkatz::rules::Candidate> cands;
    cands.resize(4);
    for (int i = 0; i < 4; ++i) {
        cands[i].source.va = 0x1000;   // same VA - must collapse to 1 chosen
        cands[i].weight    = 1.0;
        cands[i].source.length = 3;
    }

    morphkatz::disasm::BasicBlock bb;
    auto chosen = poly.select(bb, std::move(cands), /*mutation_budget=*/-1);
    REQUIRE(chosen.size() == 1);
}

TEST_CASE("Polymorph respects --mutation-budget", "[engine][polymorph]") {
    morphkatz::engine::Rng rng(uint64_t{1});
    morphkatz::engine::Polymorph poly(rng);

    std::vector<morphkatz::rules::Candidate> cands;
    for (int i = 0; i < 10; ++i) {
        morphkatz::rules::Candidate c;
        c.source.va = 0x1000 + static_cast<uint64_t>(i) * 4;
        c.weight    = 1.0;
        cands.push_back(c);
    }
    morphkatz::disasm::BasicBlock bb;
    auto chosen = poly.select(bb, std::move(cands), /*mutation_budget=*/3);
    REQUIRE(chosen.size() == 3);
}

TEST_CASE("Polymorph is deterministic under a fixed seed", "[engine][polymorph]") {
    auto run = []() {
        morphkatz::engine::Rng rng(uint64_t{999});
        morphkatz::engine::Polymorph poly(rng);
        std::vector<morphkatz::rules::Candidate> cands;
        for (int i = 0; i < 6; ++i) {
            morphkatz::rules::Candidate c;
            c.source.va = 0x1000 + static_cast<uint64_t>(i) * 4;
            c.weight    = 1.0 + i;
            cands.push_back(c);
        }
        morphkatz::disasm::BasicBlock bb;
        return poly.select(bb, std::move(cands), -1).size();
    };
    REQUIRE(run() == run());
}

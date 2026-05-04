# MorphKatz architecture

This document explains the moving parts of the C++/Win32 port so contributors
can pick a module and make changes with confidence. The design principles
are, in order of priority:

1. **Semantic preservation.** Every rewrite must be observationally identical
   for the flags, registers and memory reads/writes that downstream code
   actually depends on.
2. **Reproducibility.** A run given the same input, rule-pack and `--seed`
   must produce byte-identical output on every machine.
3. **Extensibility.** New mutation ideas land as YAML rules, not C++ patches.

## Build targets at a glance

The CMake project produces **two** real artefacts; everything else in
the generated `MorphKatz.sln` is CMake scaffolding:

| Target           | Type                     | Contents                                                                                                                                                       |
|------------------|--------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `morphkatz_core` | Static library (`.lib`)  | Every `.cpp` under `src/` **except** `main.cpp`: PE loader, CFG, IR, flag liveness, rule engine, polymorph, patcher, encoder, orchestrator, batch, binary diff, compare, YARA targeting, report, metrics, CLI parser. |
| `morphkatz`      | Executable (`.exe`)      | One translation unit (`src/main.cpp`) that wires up logging, parses argv, and dispatches to `Orchestrator::run` / `engine::run_variants` / `engine::run_compare`. Links `morphkatz::core`.  |

Why the split?

* **Tests link the core lib directly.** `morphkatz_tests` drives engine
  internals without paying the `CreateProcess` tax or re-parsing argv.
* **Embedders can consume `morphkatz::core`** from an IDA plugin,
  CI job, or EDR pipeline without shelling out to the CLI.
* **Incremental builds.** Changing `main.cpp` recompiles one TU;
  the 20+ core TUs stay cached.

`ALL_BUILD`, `ZERO_CHECK`, `INSTALL`, and `RUN_TESTS` are the standard
CMake helper projects (build-everything / auto-reconfigure on CMake
edits / `cmake --install` / `ctest` driver, respectively).

## Module map

```
include/morphkatz/
  analysis/       flag-liveness dataflow + metrics + binary_diff
  cli/            CLI11-driven option surface, startup banner
  common/         Error, Result<T>, wide-string helpers, logging, version
  disasm/         Zydis decode helpers + recursive-descent CFG
  engine/         RNG, PadPolicy, Polymorph, Patcher, Orchestrator, batch, compare
  format/         LIEF-backed PE image wrapper + compat gates (.NET, 32-bit)
  ir/             structured Instruction, Operand, FlagsEffect
  report/         JSON + HTML diff report with metrics
  rules/          YAML loader, compiled predicates, RuleMatcher
  verify/         re-disasm check, optional Unicorn emulation
  yara/           libyara loader + pre/post scan
```

## End-to-end flow

```
 load_image  ->  build CFG  ->  compute flag liveness
                                         |
                                         v
   YAML rule packs -> RuleMatcher (flags gate, register class gate)
                                         |
                                         v
               Polymorph (weighted pick per source VA)
                                         |
                                         v
            Patcher (direct + Aho-Corasick raw byte patches)
                                         |
                                         v
            Verifier (re-disasm, optional Unicorn)
                                         |
                                         v
              PE hygiene (checksum, timestamp, Rich hdr)
                                         |
                                         v
                   save()  +  write_report()
```

## Key design choices vs the Python reference

| Concern                    | Python reference                      | C++/Win32 port                                     |
|----------------------------|---------------------------------------|----------------------------------------------------|
| Disassembly                | Capstone linear sweep                 | Zydis recursive descent with jump-table recovery   |
| Encoding                   | Keystone, string-parsed operands      | Zydis `ZydisEncoderEncodeInstruction`, typed IR    |
| Instruction semantics      | string matching on mnemonics          | `ir::Instruction` + `ir::FlagsEffect` from Zydis   |
| Flag correctness           | implicit                              | explicit `analysis::FlagLiveness` dataflow         |
| Padding                    | `b'\x90'*n` / `b'\x87\xff'*n`         | 9-form multi-byte NOP rotation (Intel SDM)          |
| Randomness                 | `random` module, unseeded by default  | `xoshiro256**` seeded from `--seed` or BCrypt      |
| YARA feedback loop         | none                                  | pre/post scan with rule-breaking weight boosts     |
| Post-patch verification    | none                                  | re-disasm + optional Unicorn basic-block emulation |
| PE hygiene                 | optional checksum                     | checksum + Authenticode strip + Rich header scrub  |
| Extensibility              | edit the `.py`                         | drop a YAML file into `rules/`                      |

## Rule grammar at a glance

```yaml
- id: x64.zero.xor_to_sub
  match:
    mnemonic: XOR
    operand_count: 2
    constraints:
      - { op: 0, kind: register, class: gpr }
      - { same_register: [0, 1] }
  rewrite:
    mnemonic: SUB
    operands: [ { copy_from: 0 }, { copy_from: 0 } ]
  flags_effect: equivalent
  size_delta: 0
  weight: 0.8
```

Rules can also carry a raw-byte `raw_from` / `raw_to` pair for signatures
that don't round-trip through the IR (`rules/x64/targeted/*.yaml`). These
bypass the flag gate by contract — author-audited only.

## Memory & threading model

Everything in v1.0 runs on the calling thread; the per-block pipeline is
linear. The rule-matching, flag-liveness, and polymorph-selection stages
are per-block and embarrassingly parallel, so a `std::jthread` pool over
the CFG is on the v1.1 roadmap. Reproducibility under multi-threading
will require per-thread `xoshiro256**` streams seeded from the master
RNG.

Ownership uses PIMPL where the plan prescribes it:
`Orchestrator::Impl` (`src/engine/orchestrator.cpp`) owns the CFG, rule
pack, live-flags map and report; `Patcher::Impl`
(`src/engine/patcher.cpp`) owns the Aho-Corasick automaton and the
queued direct-offset patches; `PriorityMap::Compiled`
(`src/yara/yara_target.cpp`) owns the `YR_RULES*`. No globals, no
singletons, no mutable statics. YARA's process-scoped
`yr_initialize` / `yr_finalize` counter is the single exception and is
balanced per `PriorityMap` life-cycle.

# MorphKatz Roadmap

This is a public, best-effort roadmap. Dates are aspirational; scope is
firm until a milestone closes, then the next one opens.

## v1.0 — "Public launch"

**Status:** 🟢 done, in review.

- x64-only, Windows-first.
- CFG-aware recursive-descent disassembly with jump-table recovery.
- Per-basic-block `FlagLiveness` dataflow (AF/CF/OF/PF/SF/ZF).
- 20+ hand-audited YAML rules: equivalence-preserving rewrites + targeted
  raw-byte patches for Donut, CobaltStrike, Adaptix, Mimikatz.
- Aho-Corasick multi-pattern scanner for raw-byte rules.
- Deterministic `xoshiro256**` RNG, Intel SDM multi-byte NOP rotation.
- Optional Unicorn-based basic-block semantic verification.
- Optional YARA atom-priority targeting (`--target rules.yar`).
- JSON + HTML diff reports with YARA pre/post scan.
- PE hygiene: `CheckSumMappedFile` fix, Authenticode strip,
  reproducible timestamp, Rich-header scrub (`preserve|strip|randomize`).
- One-click Visual Studio 2022 experience
  (`Open-in-VS.cmd`, `.vs/launch.vs.json`).
- CMake presets for x64 release / debug / ASan.
- CI: GitHub Actions matrix with Catch2 tests, ASan job, fuzz-smoke job.
- libFuzzer harness over the decoder + rule matcher.
- Chocolatey + Scoop manifests.
- AGPL-3.0 open-source licence.

## v1.1 — "Auto-Discover (preview)"

**Target:** ~8 weeks after v1.0.

The headline feature of v1.1 is **Auto-Discover**: MorphKatz will read your
YARA rules and mine the rule conditions for new byte patterns it can
target, without you writing a single YAML rule.

### Auto-Discover

Today, the targeted rules live in `rules/x64/targeted/*.yaml`. Each pack
was written by a human who read the YARA rules, picked byte patterns out of
the `strings:` section and hand-expressed them as `raw_from` / `raw_to`
pairs. That scales badly: for a customer with 10 000 internal YARA rules,
no one is writing 10 000 YAML packs.

v1.1 adds `--auto-discover <rules.yar>`, which:

1. Compiles the YARA rules via `libyara`'s public compiler API.
2. Walks the rule AST and extracts every `{ hex hex hex }` sub-pattern and
   every ASCII string of length ≥ 6 that appears in a rule condition.
3. Scans the target PE for each atom and, for each hit, determines
   whether a *semantically-safe* rewrite is available in the current rule
   pack that would break the atom.
4. If yes, queues the rewrite. If no, records the atom as "uncovered" in
   the diff report so the operator knows their YARA pack has a gap.
5. Ships a new `--auto-discover-export <patches.yaml>` mode that writes
   the discovered rewrites out as a fresh rule pack for review.

The point is *not* to replace hand-written rules; it is to give the hand-
written rules a head-start on coverage for the long tail of YARA signatures
that exist only inside a single SOC's rule library.

### Other v1.1 work

- **Google Benchmark integration.** The `MORPHKATZ_BUILD_BENCH=ON` option
  currently stubs; v1.1 fills in the harness with baseline numbers for
  decode, rule-match, encode, full-run on 1 MB / 10 MB / 100 MB binaries.
- **Parallel basic-block rewriting.** v1.0 is deliberately single-threaded
  for reproducibility. v1.1 adds a work-queue-parallel mode
  (`--jobs N`, default = 1) with a per-block seed derived from the master
  seed so reproducibility is preserved.
- **Improved Rich-header handling.** v1.0 supports `preserve|strip|
  randomize`. v1.1 adds `--rich mimic:<target.exe>` to copy the Rich
  header from a named donor binary, useful for red-team engagements.
- **ARM64 prototype.** Recursive-descent disassembly for AArch64 via
  Capstone, initial equivalence-rule pack. ARM64 will remain **Pro**-tier
  only for v1.x.

## v1.2 — "Pipelines"

**Target:** H2 of the v1.0 release year.

- `morphkatz diff` sub-command: takes two PEs, shows a side-by-side
  instruction-level diff annotated with which MorphKatz rule would produce
  each divergence.
- `morphkatz bench` sub-command: runs the `--auto-discover` pipeline and
  a matrix of rule packs against a YARA pack, prints an MTTR-style
  summary (mean-time-to-evade per rule).
- YAML schema: conditional rules (`when: os_version > 10.0.22000`, etc.)
  to let contributors scope targeted rewrites to specific Windows builds.
- Optional Ghidra plugin for visualising the CFG MorphKatz actually saw,
  including basic-block flag liveness.

## v2.0 — "Formal"

**Target:** undecided, probably H1 of the year after v1.0.

- Replace the `flags_effect:` trust-based claim in YAML with an **SMT-
  backed formal verifier**. Each rule ships an SMT-LIB proof of
  equivalence that `morphkatz --verify=smt` checks at load time. A rule
  without a proof is only loaded under `--unsafe-rules`.
- Full x86 (32-bit) support via the same IR and engine.
- Windows ARM64 tier-1 support.

## Format support gates

MorphKatz v1.0 refuses to operate on PE binaries it cannot safely morph.
Calls to `PeImage::from_bytes` return `ErrorKind::NotSupported` for the
two cases below; the deferred work is tracked here.

### Multi-arch <a id="multi-arch"></a>

The v1.0 pipeline is hard-coded to x86-64: Zydis is instantiated in
`LONG_64` mode, rule packs encode x64 opcodes, and the CFG walker
assumes 64-bit `rip`-relative addressing. 32-bit x86 (`IMAGE_FILE_MACHINE_I386`,
`0x014C`), ARM64 (`0xAA64`), and all other machine types are rejected
up-front.

v1.1 adds a 32-bit Zydis mode switch plus an x86 rule pack. ARM64
prototype tracks under the v1.1 "ARM64 prototype" bullet above.
v2.0 targets full x86 and ARM64 tier-1 support.

### .NET / managed PE <a id="dotnet"></a>

A managed PE has a populated `IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR`
(data directory 14). Its `.text` section holds the CLI header, metadata
tables, and IL bytecode rather than x86 instructions. Disassembling it
with Zydis produces noise and morphing it would corrupt the CLR
assembly. v1.0 refuses these binaries.

v1.x line: no support — .NET rewriting requires an IL-level engine
(think `ILRewriter` / Mono.Cecil), not a byte-level x86 patcher. A
separate "MorphKatz.Managed" tool is under consideration for v2.x; it
will share the rule-pack and reporting surface but have an independent
assembly/disassembly engine.

## Things that will *not* happen

- **Linux ELF / macOS Mach-O port.** MorphKatz is Win32-first. PE is not a
  concealed placeholder for "any binary format" — the engine assumes
  Windows-specific structures like the Rich header, Authenticode, and
  the Windows loader. Other platforms are a different project.
- **Live-memory in-process rewriting.** MorphKatz is a file-level tool;
  it does not run inside another process' address space. This is a hard
  scope boundary.
- **Rules targeting specific commercial EDR vendors' internal signatures.**
  See [`RESPONSIBLE_USE.md`](../RESPONSIBLE_USE.md).

If you'd like to help land something on this roadmap sooner, open
an issue or a draft PR — see [`CONTRIBUTING.md`](../CONTRIBUTING.md).

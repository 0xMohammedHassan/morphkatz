# Benchmarks

> **v1.0 status:** MorphKatz ships the evaluation *harness* but does not
> yet ship measured numbers. The throughput and YARA-breakage tables that
> used to live here were written before the harness was built and have
> been removed; they are replaced by the measurement plan below. Real
> numbers land once the corpus-backed benchmark pipeline (see
> [`evasion_bench.md`](evasion_bench.md)) runs end-to-end.

## Harness layout

Everything under `scripts/bench/` is the reproducible pipeline. See
[`evasion_bench.md`](evasion_bench.md) for the long-form provenance,
legal, and sandboxing notes; this section is the operator's cheat sheet.

```pwsh
# 1. Fetch 20 samples from MalwareBazaar (requires free Auth-Key).
./scripts/bench/fetch_corpus.ps1 `
    -OutDir D:\mk-bench\corpus `
    -Tag exe -Count 20

# 2. Fetch a pinned YARA rule pack + yara64.exe.
./scripts/bench/fetch_yara_pack.ps1 -OutDir D:\mk-bench\yara

# 3. Run MorphKatz over every sample at each profile.
foreach ($p in 'safe','normal','aggressive') {
    ./scripts/bench/eval.ps1 `
        -CorpusDir D:\mk-bench\corpus `
        -YaraDir   D:\mk-bench\yara `
        -OutDir    D:\mk-bench\runs\$p `
        -Profile   $p `
        -Seed      1
}

# 4. Aggregate and splice the table back into this file.
python scripts/bench/aggregate.py `
    --results D:\mk-bench\runs\normal\results.jsonl `
    --out-json D:\mk-bench\benchmarks.summary.json `
    --replace-in-file docs/benchmarks.md
```

The harness is destructive by design — `eval.ps1` overwrites
`results.jsonl` for a given profile on each run. Commit a copy of the
summary JSON alongside the Markdown table if you want history.

## Measurement plan

Numbers we publish, and the script that produces each:

| Metric                              | Source script                    | Units                 |
|-------------------------------------|----------------------------------|-----------------------|
| Wall time + MB/s per sample         | `scripts/bench/eval.ps1`         | ms, MB/s              |
| YARA pre/post hit counts per rule   | `scripts/bench/eval.ps1`         | count, count          |
| Rule-breakage % per profile         | `scripts/bench/aggregate.py`     | %                     |
| Bytes-changed % per profile         | `DiffReport.metrics`             | %                     |
| Entropy delta per section           | `DiffReport.metrics`             | Shannon bits/byte     |
| SHA-256 + RichHash pre/post         | `DiffReport.metrics`             | hex string            |

Profiles measured: `safe`, `normal`, `aggressive` (the three
`--mutation-budget` presets in the CLI).

Corpus: 20+ SHA-256-addressed samples fetched from MalwareBazaar — see
[`evasion_bench.md`](evasion_bench.md) for provenance, legal, and
reproducibility notes.

Environment recorded alongside each run (by `eval.ps1`): CPU model,
RAM, Windows build, MorphKatz `--version` string, YARA version, and
the pinned rule-pack commit SHA.

## Published numbers

The table below is rewritten in place by `aggregate.py --replace-in-file`.
Until someone runs the pipeline end-to-end, it stays empty on purpose —
see `evasion_bench.md` for why shipping invented numbers is worse than
shipping none.

<!-- BENCH_TABLE_BEGIN -->

_No measured runs yet. Populate with `aggregate.py --replace-in-file`
after running the pipeline above._

<!-- BENCH_TABLE_END -->

## Running the built-in reproducer (wall-clock only)

The harness above is the only thing that produces the comparison table.
For a one-file wall-clock sanity check (no YARA, no corpus), the
following `Measure-Command` block is enough:

```pwsh
cmake --preset vs2022-x64-release
cmake --build --preset vs2022-x64-release --target morphkatz
Measure-Command {
  .\build\vs2022-x64\Release\morphkatz.exe `
    sample.exe --output patched.exe --seed 1
}
```

## Google Benchmark harness

The `MORPHKATZ_BUILD_BENCH` option in `CMakeLists.txt` is still a stub —
it skips with a warning if `bench/CMakeLists.txt` is absent. Filled-in
per-stage micro-benchmarks (decode, rule-match, encode) are v1.1 work,
tracked in [`roadmap.md`](roadmap.md#v11--auto-discover-preview).

## Verification overhead (qualitative)

`--verify=redisasm` re-decodes every patched basic block and is cheap;
`--verify=unicorn` emulates each block under a timeout. Concrete
overhead numbers will be captured by the harness above.


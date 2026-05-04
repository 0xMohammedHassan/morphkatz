# Evasion benchmark — provenance, reproducibility, legal

The MorphKatz evasion benchmark measures how often the rewriter
breaks public YARA signatures on a pinned corpus of real-world
samples. This document is the ground truth for *how* that measurement
is produced; the numbers themselves live in
[`benchmarks.md`](benchmarks.md).

## Pipeline

```
fetch_corpus.ps1      fetch_yara_pack.ps1
        │                      │
        ▼                      ▼
  <corpus>/samples/*.bin   <yara>/pack.yar + yara64.exe
        │                      │
        └──────► eval.ps1 ◄────┘
                    │
                    ▼
            results.jsonl
                    │
                    ▼
            aggregate.py
                    │
                    ▼
     benchmarks.summary.json + table.md
```

## Corpus: MalwareBazaar

Source: [https://mb-api.abuse.ch](https://mb-api.abuse.ch)

`scripts/bench/fetch_corpus.ps1` queries the public MalwareBazaar API
with a configurable tag list (default: `exe`) and writes every
fetched sample *plus* a `corpus.manifest.json` capturing:

* `sha256_hash` (primary key)
* `file_name` as uploaded
* `file_type`, `signature`, `tags`, `first_seen`
* UTC timestamp of the fetch

Access requires a free Auth-Key from
[auth.abuse.ch](https://auth.abuse.ch). Per the service terms, samples
must not be redistributed; our manifest is the only thing that gets
committed. Anyone reproducing the benchmark fetches their own samples
addressed by the manifest's SHA-256 list.

### Sandboxing

Live malware. `fetch_corpus.ps1` refuses to write to the system drive
by default. Run the whole pipeline inside an isolated Hyper-V VM with:

* Defender real-time scanning **on** (alerts go to the host share).
* No outbound network except the MalwareBazaar endpoint (allow-list).
* Snapshot before every `eval.ps1` run; revert after.

## YARA rule pack

Source: abuse.ch
[YARAify-rules](https://github.com/abuse-ch/YARAify-rules) (pinned by
commit SHA in `yara.pack.manifest.json`).

`fetch_yara_pack.ps1` downloads a zipped snapshot, compiles each
`.yar` file in isolation with `yara64.exe` (skipping the ones that
fail the compile step so a single bad rule doesn't nuke the pack),
and concatenates the survivors into `pack.yar`. Every concatenation
prepends a comment with the rule's source path for audit.

The scanner itself is `yara64.exe` from a pinned
[VirusTotal YARA release](https://github.com/VirusTotal/yara/releases),
downloaded by the same script. Shipping the exact scanner binary is
the only way to keep pre/post hit counts reproducible across machines.

## Measurement loop (`eval.ps1`)

For each sample the harness records **one JSON Lines row** with:

| Field                  | Meaning                                         |
|------------------------|-------------------------------------------------|
| `sha256_before`        | input SHA-256 (also filename key)              |
| `profile`              | `safe` \| `normal` \| `aggressive`             |
| `seed`                 | morphkatz `--seed`                             |
| `pre_hits`             | YARA rule names that match the input           |
| `post_hits`            | YARA rule names that match the morphed output  |
| `broken_rules`         | `pre_hits \ post_hits`                         |
| `gained_rules`         | `post_hits \ pre_hits` (should be empty)       |
| `wall_ms`              | `morphkatz.exe` wall clock                     |
| `exit_code`            | morphkatz rc (0 = ok; non-zero rows dropped)   |
| `bytes_changed_pct`    | from DiffReport.metrics                        |
| `entropy_before/after` | from DiffReport.metrics                        |
| `sha256_after`         | post-morph hash                                |

`env.<profile>.json` captures OS caption + build, CPU model, RAM,
morphkatz version, YARA version, and the seed / profile actually used
so two people running the same numbers can detect drift.

## Aggregation (`aggregate.py`)

`results.jsonl` → per-profile rollup:

* `breakage_median/mean/p95` — distribution of
  `(pre - post) / pre * 100` percentages across samples.
* `bytes_changed_median/p95_pct` — from the DiffReport metrics.
* `entropy_delta_median/p95` — `after - before`, rounded to 3 dp.
* `wall_ms_median/p95`, `throughput_mb_s`.

The Markdown table between `<!-- BENCH_TABLE_BEGIN -->` and
`<!-- BENCH_TABLE_END -->` in `benchmarks.md` is overwritten in-place
by `aggregate.py --replace-in-file`. Run it with `--out-json` first to
inspect the rollup before touching the public doc.

## Non-goals

* We don't measure dynamic/behavioral detection — only static YARA.
  Any claim about "evading AV" on the strength of this harness is
  overreach; the number measures YARA signature breakage, nothing
  more.
* The corpus isn't balanced across families. The tag filter
  (`-Tag CobaltStrike,mimikatz,...`) is how you control breadth; the
  manifest records the exact query so the bias is visible.
* Pre/post YARA hits are compared by *rule name only*. A mutation
  that shifts a hit from one variant rule to another of the same
  family counts as "gained a rule". Rename-only rulesets will
  therefore look artificially noisy; that's a property of the data,
  not the tool.

## Legal

MalwareBazaar samples are shared under the abuse.ch terms of use
(non-redistribution, research-only). YARAify rules are Apache-2.0.
Running this harness on anything but samples you legally possess is
your responsibility. MorphKatz itself is AGPL-3.0; see
[`LICENSE`](../LICENSE).

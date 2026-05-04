#!/usr/bin/env python3
"""Aggregate MorphKatz evasion-benchmark JSONL results.

Consumes the results.jsonl emitted by eval.ps1 and produces:

  * ``benchmarks.summary.json`` - machine-readable rollup per profile.
  * ``benchmarks.table.md`` - a GitHub-flavored Markdown fragment ready
    to paste into ``docs/benchmarks.md`` (or piped to
    ``--replace-in-file``).

Metrics aggregated per (profile) group:

  * N samples completed, N failed, total wall time.
  * YARA breakage: median/mean/p95 of ``(pre - post) / pre * 100``.
  * Bytes changed: median/mean/p95 from the per-sample DiffReport.
  * Entropy delta: median/p95 of ``after - before``.
  * Throughput: MB/s = total input bytes / total wall time.

The script intentionally avoids numpy/pandas so it runs in a clean
Python 3.9+ environment without extra wheels.
"""

from __future__ import annotations

import argparse
import io
import json
import math
import pathlib
import statistics
import sys
from collections import defaultdict
from typing import Any, Iterable

# Force stdout/stderr to UTF-8 so the harness runs in a non-UTF codepage
# shell (Arabic-Windows cp1256, Japanese cp932, etc.) without crashing
# on non-ASCII table glyphs.
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except (AttributeError, io.UnsupportedOperation):
        pass


def load_jsonl(path: pathlib.Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as exc:
                print(
                    f"{path}:{lineno}: skipping malformed JSON line ({exc})",
                    file=sys.stderr,
                )
    return rows


def quantile(values: Iterable[float], q: float) -> float:
    data = sorted(v for v in values if v is not None and not math.isnan(v))
    if not data:
        return 0.0
    if len(data) == 1:
        return float(data[0])
    pos = q * (len(data) - 1)
    lo = math.floor(pos)
    hi = math.ceil(pos)
    if lo == hi:
        return float(data[lo])
    frac = pos - lo
    return float(data[lo] + (data[hi] - data[lo]) * frac)


def mean(values: Iterable[float]) -> float:
    data = [v for v in values if v is not None and not math.isnan(v)]
    return float(statistics.fmean(data)) if data else 0.0


def median(values: Iterable[float]) -> float:
    data = [v for v in values if v is not None and not math.isnan(v)]
    return float(statistics.median(data)) if data else 0.0


def breakage_pct(row: dict[str, Any]) -> float:
    pre = row.get("pre_hits") or []
    post = row.get("post_hits") or []
    if not pre:
        return 0.0
    broken = sum(1 for r in pre if r not in post)
    return 100.0 * broken / len(pre)


def aggregate(rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for r in rows:
        groups[r.get("profile", "unknown")].append(r)

    out: dict[str, dict[str, Any]] = {}
    for profile, items in groups.items():
        ok = [r for r in items if r.get("exit_code") == 0]
        failed = [r for r in items if r.get("exit_code") != 0]
        breakage = [breakage_pct(r) for r in ok if r.get("pre_hits")]
        bytes_changed_pct = [
            r.get("bytes_changed_pct") for r in ok if r.get("bytes_changed_pct") is not None
        ]
        entropy_delta = [
            (r["entropy_after"] - r["entropy_before"])
            for r in ok
            if r.get("entropy_before") is not None and r.get("entropy_after") is not None
        ]
        wall_ms = [r.get("wall_ms", 0.0) for r in ok]
        total_bytes = sum(r.get("size_bytes", 0) for r in ok)
        total_sec = sum(wall_ms) / 1000.0

        out[profile] = {
            "samples_total":     len(items),
            "samples_ok":        len(ok),
            "samples_failed":    len(failed),
            "breakage_median":   median(breakage),
            "breakage_mean":     mean(breakage),
            "breakage_p95":      quantile(breakage, 0.95),
            "bytes_changed_median_pct": median(bytes_changed_pct),
            "bytes_changed_p95_pct":    quantile(bytes_changed_pct, 0.95),
            "entropy_delta_median":  median(entropy_delta),
            "entropy_delta_p95":     quantile(entropy_delta, 0.95),
            "wall_ms_median":        median(wall_ms),
            "wall_ms_p95":           quantile(wall_ms, 0.95),
            "throughput_mb_s":       (total_bytes / 1_000_000.0 / total_sec) if total_sec > 0 else 0.0,
        }
    return out


def render_markdown(summary: dict[str, dict[str, Any]]) -> str:
    profile_order = ["safe", "normal", "aggressive"]
    profiles = [p for p in profile_order if p in summary] + \
               [p for p in summary if p not in profile_order]

    lines: list[str] = []
    lines.append("<!-- auto-generated by scripts/bench/aggregate.py -->")
    lines.append("")
    lines.append("| profile | N  | breakage median % | breakage p95 % | "
                 "bytes changed median % | entropy delta median | MB/s |")
    lines.append("|---------|----|-------------------|---------------|"
                 "-----------------------|----------------------|------|")
    for p in profiles:
        s = summary[p]
        lines.append(
            f"| `{p}` | {s['samples_ok']} | "
            f"{s['breakage_median']:.1f} | {s['breakage_p95']:.1f} | "
            f"{s['bytes_changed_median_pct']:.2f} | "
            f"{s['entropy_delta_median']:+.3f} | "
            f"{s['throughput_mb_s']:.2f} |"
        )
    lines.append("")
    return "\n".join(lines)


def replace_block(md_path: pathlib.Path, fragment: str,
                  begin: str = "<!-- BENCH_TABLE_BEGIN -->",
                  end:   str = "<!-- BENCH_TABLE_END -->") -> None:
    """Replace the block between `begin` and `end` markers in-place.

    If the markers are absent the function is a no-op (and prints a
    hint to stderr) so repeated runs are idempotent.
    """
    original = md_path.read_text(encoding="utf-8")
    i = original.find(begin)
    j = original.find(end)
    if i < 0 or j < 0 or j < i:
        print(
            f"{md_path}: markers '{begin}' / '{end}' not found; "
            "leaving file untouched.",
            file=sys.stderr,
        )
        return
    new = original[: i + len(begin)] + "\n\n" + fragment + "\n" + original[j:]
    md_path.write_text(new, encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--results", required=True, type=pathlib.Path,
                    help="Path to results.jsonl emitted by eval.ps1")
    ap.add_argument("--out-json", required=False, type=pathlib.Path,
                    help="Write aggregated summary JSON here")
    ap.add_argument("--out-md", required=False, type=pathlib.Path,
                    help="Write aggregated Markdown table here")
    ap.add_argument("--replace-in-file", required=False, type=pathlib.Path,
                    help="Splice the table into this Markdown file between "
                         "BENCH_TABLE_BEGIN / BENCH_TABLE_END markers")
    args = ap.parse_args()

    rows = load_jsonl(args.results)
    if not rows:
        print(f"no usable rows in {args.results}", file=sys.stderr)
        return 2

    summary = aggregate(rows)

    if args.out_json:
        args.out_json.parent.mkdir(parents=True, exist_ok=True)
        args.out_json.write_text(json.dumps(summary, indent=2), encoding="utf-8")
        print(f"wrote {args.out_json}")

    md = render_markdown(summary)
    if args.out_md:
        args.out_md.parent.mkdir(parents=True, exist_ok=True)
        args.out_md.write_text(md, encoding="utf-8")
        print(f"wrote {args.out_md}")
    else:
        print(md)

    if args.replace_in_file:
        replace_block(args.replace_in_file, md)
        print(f"patched {args.replace_in_file}")

    return 0


if __name__ == "__main__":
    sys.exit(main())

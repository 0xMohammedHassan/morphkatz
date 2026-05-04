"""Standalone smoke test for aggregate.py.

Run with: ``python scripts/bench/test_aggregate.py``. No pytest
dependency — the bench harness should work in a clean Python 3.9+
environment on the same VM that runs eval.ps1.
"""

from __future__ import annotations

import json
import pathlib
import subprocess
import sys
import tempfile

HERE = pathlib.Path(__file__).parent.resolve()
AGGREGATE = HERE / "aggregate.py"


def _fixture() -> list[dict]:
    # Three samples, two profiles. breakage for "normal":
    #   sample1: 2 pre, 1 post  -> 50%
    #   sample2: 4 pre, 0 post  -> 100%
    # breakage for "safe":
    #   sample3: 5 pre, 4 post  -> 20%
    return [
        {"sha256_before": "a", "profile": "normal", "seed": 1, "size_bytes": 1024,
         "pre_hits": ["r1", "r2"], "post_hits": ["r2"],
         "exit_code": 0, "wall_ms": 50,
         "bytes_changed": 3, "bytes_changed_pct": 0.3,
         "entropy_before": 6.0, "entropy_after": 6.2,
         "sha256_after": "aa"},
        {"sha256_before": "b", "profile": "normal", "seed": 1, "size_bytes": 2048,
         "pre_hits": ["r1", "r2", "r3", "r4"], "post_hits": [],
         "exit_code": 0, "wall_ms": 150,
         "bytes_changed": 20, "bytes_changed_pct": 1.0,
         "entropy_before": 6.1, "entropy_after": 6.4,
         "sha256_after": "bb"},
        {"sha256_before": "c", "profile": "safe", "seed": 1, "size_bytes": 512,
         "pre_hits": ["r1", "r2", "r3", "r4", "r5"],
         "post_hits": ["r1", "r2", "r3", "r4"],
         "exit_code": 0, "wall_ms": 25,
         "bytes_changed": 1, "bytes_changed_pct": 0.2,
         "entropy_before": 5.9, "entropy_after": 5.95,
         "sha256_after": "cc"},
        # one failure, should be excluded from ok-metrics
        {"sha256_before": "d", "profile": "normal", "seed": 1, "size_bytes": 1024,
         "pre_hits": [], "post_hits": [], "exit_code": 99, "wall_ms": 0},
    ]


def run_case() -> None:
    with tempfile.TemporaryDirectory() as td:
        tdp = pathlib.Path(td)
        results = tdp / "results.jsonl"
        with results.open("w", encoding="utf-8") as f:
            for row in _fixture():
                f.write(json.dumps(row) + "\n")

        out_json = tdp / "summary.json"
        out_md   = tdp / "table.md"
        rc = subprocess.run(
            [sys.executable, str(AGGREGATE),
             "--results", str(results),
             "--out-json", str(out_json),
             "--out-md",   str(out_md)],
            check=True, capture_output=True, text=True,
        )
        assert out_json.exists(), "aggregator did not write summary JSON"
        assert out_md.exists(),   "aggregator did not write markdown"

        summary = json.loads(out_json.read_text(encoding="utf-8"))
        assert "normal" in summary and "safe" in summary, \
            f"missing profile group: {list(summary)}"

        n = summary["normal"]
        assert n["samples_ok"]     == 2
        assert n["samples_failed"] == 1
        # Breakage median: (50 + 100) / 2 = 75; median is mean of two
        assert abs(n["breakage_median"] - 75.0) < 1e-6, n
        assert abs(n["breakage_mean"]   - 75.0) < 1e-6, n

        s = summary["safe"]
        assert s["samples_ok"] == 1
        assert abs(s["breakage_median"] - 20.0) < 1e-6, s

        md = out_md.read_text(encoding="utf-8")
        assert "`normal`" in md and "`safe`" in md, md

        # Replace-in-file path exercises the marker-splicing branch.
        md_target = tdp / "target.md"
        md_target.write_text(
            "pre\n<!-- BENCH_TABLE_BEGIN -->\nold\n<!-- BENCH_TABLE_END -->\npost\n",
            encoding="utf-8",
        )
        subprocess.run(
            [sys.executable, str(AGGREGATE),
             "--results", str(results),
             "--replace-in-file", str(md_target)],
            check=True, capture_output=True, text=True,
        )
        patched = md_target.read_text(encoding="utf-8")
        assert patched.startswith("pre\n") and patched.endswith("post\n")
        assert "old" not in patched
        assert "|" in patched, "no markdown table spliced in"


if __name__ == "__main__":
    run_case()
    print("ok")

# MorphKatz YARA hint packs

This tree ships **YARA rule files** that the MorphKatz rule matcher
loads to prioritise candidate rewrites. They are *not* malware
detection rules — they are **hints** that say "if you see these byte
patterns in the input, prefer rewrites that touch them."

```
rules/yara/
  x64/
    mimikatz.yar
```

## When are these loaded?

Two paths:

1. **Explicit**: pass `--target rules/yara/x64/mimikatz.yar` (or any
   `.yar` file). This always takes precedence.
2. **Automatic**: when `--target-defender <ref.exe>` is used and
   Defender flags the reference with a known family name (e.g.
   `HackTool:Win32/Mimikatz!pz`), MorphKatz loads
   `<rules>/yara/x64/<family>.yar` if it exists. Pass
   `--no-auto-yara` to disable.

The loader keeps the user-supplied `--target` if both apply; the
auto-load path is silent when no family matches.

## How are these used?

The `yara_target::PriorityMap` walks each rule's strings, captures
their byte atoms (capped at 16 bytes per atom), and exposes a
`boost_for(va, old_bytes, new_bytes)` function. The rule matcher
folds the result into the candidate rewrite's priority as
`weight * (1 + boost)`, so a candidate that **breaks** an atom (the
atom is present in `old_bytes` but not in the proposed `new_bytes`)
gets pushed up the polymorphic selector's order.

## Authoring guidelines

* **License**: AGPL-3.0-or-later, matching the project. Do not
  copy-paste rules from third-party packs (yara-rules/rules,
  signature-base, etc.) — link to them in user docs instead.
* **Confidence**: keep low-confidence atoms here. High-confidence
  detection is the user's job via `--target`.
* **Public-only**: every string and hex pattern must already be
  documented in public reverse-engineering material. We don't ship
  novel signatures.
* **Granularity**: prefer 4–16 byte hex atoms (matches YARA's
  Aho-Corasick atom bound) so they actually feed the matcher's
  boost lookup.
* **Filename convention**: `rules/yara/x64/<family>.yar` where
  `<family>` is the lowercase Defender family name without
  category / platform prefix (e.g. `mimikatz`, not
  `hacktool_win32_mimikatz`).
* **Rule naming**: `MorphKatz_<Family>_<Aspect>` so rule names can
  be told apart from third-party packs in mixed-load scenarios.
* **Meta block**: include `author`, `license`, `description`,
  `target` (the Defender threat name pattern this hints for), and
  `confidence` (string explanation).

## Adding a new family

1. Drop `<family>.yar` in `rules/yara/x64/`.
2. Extend `match_family_yara()` in
   [`src/engine/orchestrator.cpp`](../../src/engine/orchestrator.cpp)
   to map the Defender threat substring to your basename.
3. Add a `yara_target::load` smoke test in
   [`tests/unit/yara_target_test.cpp`](../../tests/unit/yara_target_test.cpp)
   asserting rule and atom counts.
4. Update the user-facing list in
   [`docs/scan.md`](../../docs/scan.md) and the README quick start.

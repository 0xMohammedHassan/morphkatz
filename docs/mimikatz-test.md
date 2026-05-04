# mimikatz end-to-end validation walkthrough

This walkthrough demonstrates the canonical "morph + Defender feedback"
loop against an upstream mimikatz release. It is the worked example
the README's "what does this actually do?" section refers to.

> [!CAUTION]
> mimikatz is a credential-dumping tool. Microsoft Defender flags it
> as `Trojan:Win32/Mimikatz` (and several adjacent families). Run this
> walkthrough only on machines you own (or have explicit written
> authorization for), and only inside an isolated VM / lab network.
> The MorphKatz repo never bundles mimikatz; you fetch it yourself
> via the opt-in script.

## Prerequisites

* Windows 10 22H2 or Windows 11 (Defender platform 4.18+).
* An elevated PowerShell session.
* MorphKatz built and on `PATH` (or run from `build\vs2022-x64\Debug`).
* About 200 MB free disk for the mimikatz release zip + extract.

## 1. Take a Defender snapshot, fetch mimikatz

```pwsh
cd C:\path\to\morphkatz
.\scripts\bench\fetch_mimikatz.ps1 -Confirm -OutputDir .\mimikatz-bench
```

The script:

1. Snapshots `Get-MpPreference` to `mimikatz-bench\mp-prefs.snapshot.json`.
2. Disables MAPS reporting and sample submission (precondition gate).
3. Adds `mimikatz-bench` to Defender exclusions so RTP doesn't yank
   the binary mid-scan.
4. Downloads `mimikatz_trunk.zip` from the upstream
   [gentilkiwi/mimikatz](https://github.com/gentilkiwi/mimikatz)
   release page and verifies the pinned SHA-256 (when supplied via
   `-ExpectedZipSha256`).
5. Extracts to `.\mimikatz-bench\extracted\`.

You'll get a final banner that lists the suggested commands for the
next steps.

## 2. Pre-scan the unmutated binary

```pwsh
$mimi = ".\mimikatz-bench\extracted\x64\mimikatz.exe"
morphkatz scan $mimi --bisect --bisect-mode all --report scan-pre.json
```

The default bisect scope is `sections` (PE-aware). The scanner sees
the full file every iteration with bytes outside the candidate
window masked **only inside section payloads minus parsed
data-directory windows** — headers and imports stay verbatim, so
the parser cannot bail with a false-clean verdict and produce
misleading "anchor at 0x0" results. See
[`docs/scan.md`](scan.md#pe-aware-bisection---bisect-scope) for the
full scope catalogue.

Expected output (Defender 4.18+ on a current-signatures host):

```text
scan: mimikatz.exe -> INFECTED
  threat=HackTool:Win32/Mimikatz!pz                       severity=
  bisect (all): scope=sections status=done anchors=N scans=M elapsed=...ms
    [1] status=found offset=0x... len=... section=.text  frags=1
    [2] status=found offset=0x... len=... section=.rdata frags=1
    [3] status=found offset=0x... len=... section=...    frags=1
```

`scan-pre.json` contains the engine version, the verdict, the active
bisect scope (`scope`, `scope_bytes`), and the multi-anchor
bisection result (one entry per byte window with offset, length,
hex dump, fragments, and PE section attribution).

If every L/R scan still flags after a `sections` run (i.e. all peels
return `midpoint_span`), the signature lives inside a parsed
data-directory record (e.g. an import name). Retry with
`--bisect-scope sections-all` to also let the bisect mask directory
content. If `--bisect-mode single` returns `status=midpoint_span`,
that's the single-anchor algorithm signalling "more than one anchor
straddles the midpoint" — re-run with `--bisect-mode all` to
enumerate them.

## 3. Morph the binary with Defender as the target

```pwsh
morphkatz $mimi `
    --target-defender $mimi `
    --seed 42 `
    --report run.html
```

What happens:

* The orchestrator pre-scans `mimikatz.exe` and runs **multi-anchor**
  bisection — one entry per byte window Defender keys on.
* If the threat name contains `Mimikatz` and you didn't pass
  `--target`, the bundled YARA hint pack at
  `rules/yara/x64/mimikatz.yar` is auto-loaded so the rule matcher
  can boost candidate rewrites that match Mimikatz code atoms.
  Pass `--no-auto-yara` to disable.
* The polymorphic engine prefers rewrites whose target VA falls
  inside a Defender-confirmed anchor window or a YARA atom.
* After the rewrite + verify + finalize pipeline writes
  `mimikatz.patched.exe`, the orchestrator re-scans it and records
  the diff.
* `run.html` contains the standard MorphKatz diff report plus a
  **Defender** block listing engine version, every anchor, and
  broken / persisted / introduced detections.

You can iterate seeds (`--seed 1, 2, 3, ...`) until you find one that
breaks all anchors. Use `--variants 8` to fan out a deterministic
batch in a single command.

## 4. Post-scan to confirm

```pwsh
morphkatz scan ".\mimikatz-bench\extracted\x64\mimikatz.patched.exe" `
    --report scan-post.json
```

A successful run shows `scan: mimikatz.patched.exe -> CLEAN` for all
the families that the morph round was able to break. Any remaining
`!ml` detections will persist (they are intentionally not part of
the bisection algorithm; see `docs/scan.md`).

## 5. Compare reports

```pwsh
morphkatz compare $mimi ".\mimikatz-bench\extracted\x64\mimikatz.patched.exe" `
    --report compare.html
```

Useful columns to look at:

* `aligned_hamming_pct` — percentage of bytes that differ.
* `histogram_cosine` — closeness of the byte-frequency distribution.
* `alphabet_jaccard` — set similarity of distinct byte values.

A typical morph run produces ~5-10% Hamming difference, >0.99
histogram cosine (similar distribution), and 1.0 Jaccard (no new
byte values introduced).

## 6. Restore the host

When you're done:

```pwsh
.\scripts\bench\fetch_mimikatz.ps1 -Restore -OutputDir .\mimikatz-bench
```

This:

* Removes the Defender exclusion on `mimikatz-bench`.
* Restores `MAPSReporting`, `SubmitSamplesConsent`, and (if previously
  set) `DisableRealtimeMonitoring` from the snapshot.
* Leaves the extracted mimikatz binaries on disk - delete them
  yourself with `Remove-Item -Recurse -Force .\mimikatz-bench` if
  you no longer need them.

## What this proves (and what it doesn't)

The walkthrough demonstrates that:

* MorphKatz can integrate with the deployed antivirus engine on the
  host without cloud or kernel access.
* Multi-anchor bisection enumerates every byte window Defender keys
  on for the input, including signatures (like
  `HackTool:Win32/Mimikatz!pz`) that single-anchor bisect can only
  describe as `midpoint_span`.
* The orchestrator can turn those anchors plus an auto-loaded YARA
  hint pack into prioritized rewrites and re-scan the output.

The walkthrough does **not** claim:

* That MorphKatz is a complete bypass tool. Mimikatz `!pz` carries
  signature weight in PE strings, exports, and structures that the
  v0.1 / v0.2 OSS rule packs do not yet morph (string-table morphing
  and PE structure morphing are explicit roadmap items).
* That ML detections, behaviour rules, and EDR telemetry are
  affected by byte-level mutation — they are not.
* That the result will run undetected on every Defender install -
  signatures roll forward and a binary that's clean today may flag
  again tomorrow.

For the underlying research that informs this design, see the project's
internal research notes.

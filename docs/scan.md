# `morphkatz scan` — Defender feedback for byte-level mutation

`morphkatz scan` runs Microsoft Defender against a single file using the
shipped Tier-1 backend (`MpCmdRun.exe`) and optionally bisects to find
the smallest detected byte window. It is the OSS-tier counterpart to
the existing `--target` flag (which uses YARA rules) and lets the
mutation engine learn anchors directly from the deployed antivirus
engine on the host.

This page documents the standalone subcommand. For the orchestrator
integration via `--target-defender`, see the "Defender as a target"
section near the bottom.

## Why "Tier-1"?

The internal research plan lays out
five scanner integration tiers in order of fidelity / risk:

| Tier | Backend                          | Status    |
|------|----------------------------------|-----------|
| 1    | `MpCmdRun.exe` (process spawn)   | shipped   |
| 2    | AMSI (in-process COM)            | planned   |
| 3    | `MpClient.dll` direct calls      | research  |
| 4    | MAPS cloud signature submission  | research  |
| 5    | `mpengine.dll` direct disasm     | research  |

MorphKatz currently ships Tier-1 only. Higher tiers either require
licensing review (Tier-3, Tier-5), require the cloud (Tier-4), or
expose the user to engine-version brittleness (Tier-2). Tier-2 is
slated for a future release once the in-process surface stabilises;
Tiers 3-5 are documented but stay out of scope for now.

## Preconditions

The scanner refuses to run unless these registry values are set
(strict mode, default on):

* `HKLM\Software\Microsoft\Windows Defender\Spynet\SpynetReporting` = `0`
* `HKLM\Software\Microsoft\Windows Defender\Spynet\SubmitSamplesConsent` = `2`

This prevents your scan corpus from being uploaded to Microsoft's
cloud reputation service. The validator prints the exact
`Set-MpPreference` invocation needed when a precondition fails so
nobody has to go googling.

To override the gate explicitly:

```pwsh
morphkatz scan payload.bin --no-strict-preconditions
```

You will see a warning block in the JSON / HTML report and a stderr
line so the relaxation is visible at audit time.

## CLI surface

```text
morphkatz scan <input> [options]

  --bisect                       Halve-and-rescan to find the offending
                                 byte window(s).
  --bisect-mode {single|all}     `single` (default) returns one anchor;
                                 `all` peels found anchors from a working
                                 copy and re-scans until clean (or budget
                                 exhausts), surfacing the full anchor list.
  --bisect-scope {sections|sections-all|code|data|raw}
                                 PE-aware mask scope (default sections).
                                 See "PE-aware bisection" below.
  --engine        {cli|amsi}     Tier-1 only in v1; AMSI is reserved.
  --report        <out.json|out.html>
                                 Structured report (extension switches).
  --strict-preconditions         Default ON. Hard-fails when MAPS or
                                 SubmitSamples aren't off.
  --no-strict-preconditions      Disable the gate; emits a warning.
  --mpcmdrun      <path>         Override discovery (Defender platform
                                 dir / Program Files / PATH).
  --temp-dir      <path>         Override scan temp directory.
  --timeout-ms    <N>            Per-scan timeout (default 60000).
  -v, -vv, -vvv                  Verbosity.
  -q, --quiet                    Suppress stderr log sink.
  --log-file      <path>         Persistent log.
```

## Examples

### EICAR canary

```pwsh
echo 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > eicar.com
morphkatz scan eicar.com --report eicar.json
```

If RTP is on, you may need to add the working directory to Defender
exclusions first. The scanner will still surface the verdict, but a
quarantined input shows up as a clean scan with a sanitized stdout.

### Bisect a known sample

```pwsh
morphkatz scan path\to\flagged.exe --bisect --report bisect.html
```

The HTML report contains the offending offset, length, hex dump, and
section name (when the input is a PE). Output is roughly:

```text
scan: flagged.exe -> INFECTED
  threat=Trojan:Win32/Mimikatz                            severity=Severe
  bisect: status=found offset=0x9f10 len=128 section=.text scans=18 elapsed=8410ms
```

### Multi-anchor bisect (recover every byte window)

When the single-anchor bisect comes back with `status=midpoint_span`
the signature isn't a contiguous run — there are multiple independent
anchors that all flag the buffer. Use `--bisect-mode all` to peel them
off one at a time:

```pwsh
morphkatz scan path\to\flagged.exe `
    --bisect --bisect-mode all `
    --report multi-bisect.json
```

The peel-and-rescan algorithm:

1. Run a single-anchor bisection on the input.
2. Mask the found window in a working copy (zero-fill, layout
   preserved so PE offsets stay valid).
3. Re-scan; if clean, return `status=done`. Otherwise loop.
4. Stop on either `max_anchors` (default 8), `total_max_scans`
   (default 256), or an `*!ml` detection on a subsequent peel.

Output is roughly:

```text
scan: flagged.exe -> INFECTED
  threat=HackTool:Win32/Mimikatz!pz                       severity=
  bisect (all): status=done anchors=4 scans=58 elapsed=2104ms
    [1] status=found  offset=0x18a0 len=64  section=.text
    [2] status=found  offset=0xd400 len=32  section=.rdata
    [3] status=found  offset=0xe240 len=128 section=.text
    [4] status=found  offset=0x12a00 len=16 section=.data
```

The JSON shape changes from a single `bisect: {...}` to
`bisect: { mode: "all", status: ..., anchors: [...] }`. The HTML
report renders an anchor table.

## PE-aware bisection (`--bisect-scope`)

Without this option, the bisect would localise by *truncating* the
input — sending `input.subspan(lo, mid)` etc. to the scanner. That
breaks PE parsing: a truncated buffer fails the PE header walk,
Defender reports CLEAN, and the bisect mistakenly concludes the
signature isn't in that half. Real-world result: every anchor lands
near offset 0 (the parser-bail boundary), regardless of where the
signature actually lives.

`--bisect-scope` fixes this. Instead of truncating, the bisect always
hands Defender the **full** file, with bytes outside the candidate
window masked **only inside the scope** (zero-fill). Headers, the
section table, and (in default `sections` scope) parsed
data-directory regions are preserved verbatim every iteration, so
the scanner always sees a structurally valid PE.

Available scopes:

| Scope          | What's eligible to be masked                                                  |
|----------------|-------------------------------------------------------------------------------|
| `sections`     | Section raw data **minus** parsed data-directory windows (default; safest)    |
| `sections-all` | All section raw data (incl. imports / exports / etc.)                         |
| `code`         | Sections with `IMAGE_SCN_MEM_EXECUTE` or `IMAGE_SCN_CNT_CODE` only            |
| `data`         | Sections with `IMAGE_SCN_CNT_INITIALIZED_DATA` and no execute                 |
| `raw`          | Empty list — falls back to legacy slice-and-scan (can give false-cleans)      |

Pick a scope by where you suspect the signature lives:

* If you don't know yet, leave `sections` (default).
* If `sections` returns `midpoint_span` *and* the threat name suggests
  the anchor is in an import name or other directory record, retry with
  `sections-all`.
* `code` / `data` are useful for narrowing the search in known cases
  (e.g. instruction-byte signatures vs. string atoms).
* `raw` reproduces legacy v1.0 behaviour and is left in for parity
  reporting on non-PE inputs (raw shellcode / payloads). On a real PE
  it can lie to you; pick a PE-aware scope unless you need legacy
  shape.

The JSON `bisect` block gains two fields:

```json
"bisect": {
  "scope":       "sections",
  "scope_bytes": 1042816,
  "status":      "found",
  "offset":      62208,
  "length":      48,
  "section":     ".rdata",
  "fragments":   [{"file_offset": 62208, "length": 48}],
  ...
}
```

`scope_bytes` is the total number of bytes in the active scope (the
"virtual" coordinate space the bisect actually operates in). When the
final anchor straddles a gap between two scan ranges (e.g. between
two adjacent sections that aren't contiguous on disk), `fragments`
lists the per-fragment file ranges; the common single-fragment case
collapses to one entry that matches `offset` / `length`.

### Override discovery

```pwsh
morphkatz scan suspect.bin `
  --mpcmdrun 'C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.24080.4\MpCmdRun.exe' `
  --bisect --report suspect.json
```

## Defender as a target during morph

The orchestrator can use the scanner during a normal `morphkatz` run
via `--target-defender <reference.exe>`:

```pwsh
morphkatz payload.exe `
    --target-defender payload.exe `
    --seed 42 --report run.html
```

What happens:

1. The orchestrator builds a Tier-1 scanner and a `DefenderTarget`
   from `<reference.exe>`.
2. The target performs an initial scan + multi-anchor bisect (peel-
   and-rescan); it learns the byte windows Defender keys on.
3. If the threat name matches a known family (e.g. `Mimikatz`) and
   the user hasn't passed `--target`, a bundled YARA hint pack from
   `rules/yara/x64/<family>.yar` is auto-loaded so the rule matcher
   can boost candidate rewrites that touch family-specific bytes.
   Pass `--no-auto-yara` to disable.
4. The rule matcher's per-VA priority sums the YARA boost (if any)
   with the Defender anchor boost. Confirmed Defender anchors get a
   stronger weight than YARA atoms because they represent a *real*
   deployed signature.
5. After the morph + finalize pipeline writes the output, the target
   re-scans the saved file and computes broken / persisted /
   introduced detections.
6. A `defender:` block is added to the JSON / HTML report containing
   the engine label, version, full anchor list, and verdict diff.

`<reference.exe>` is usually the same file you're morphing, but the
two are decoupled so you can also bisect a *known-bad* sample and
mutate a different but related sample (useful for family-wide
research).

## Data-section morphing escalation

When a `--target-defender` run isolates anchors that land in `.rdata`
or `.data` and the user hasn't pinned `--data-morph`, the orchestrator
auto-escalates to `--data-morph on` for that run. This is the only
way to break body-content signatures (e.g. `HackTool:Win64/Mimikatz.D`,
`HackTool:Win32/AmDisable!MTB`) whose anchor bytes live outside the
executable section that the instruction-level rewriter touches.

See [`docs/data-morph.md`](data-morph.md) for the full surface.

## Out of scope (v1)

* Tier-2 / 3 / 4 / 5 backends — same plan, separate revisions.
* PE structure morphing (timestamp scrub, debug dir, section-name
  normalization). Required to flip persisted -> broken on family
  signatures whose anchors live in PE headers (e.g. `Mimikatz!pz`);
  data-section morphing already handles `.rdata`/`.data` anchors via
  `--data-morph` (see [`docs/data-morph.md`](data-morph.md)).
* Toggling Defender preferences from inside `morphkatz.exe`. The
  scanner only validates and reports; mutation of `Set-MpPreference`
  state lives in
  [`scripts/bench/fetch_mimikatz.ps1`](../scripts/bench/fetch_mimikatz.ps1)
  for the manual workflow.
* URL-input scanning. Local files only.

## Reading a scan report

`scan-report.json` example:

```json
{
  "tool": "morphkatz",
  "mode": "scan",
  "engine": {
    "label":       "MpCmdRun-Tier1",
    "exe_version": "1.1.24080.4",
    "vdm_version": "1.413.2226.0"
  },
  "preconditions": {
    "defender_present": true,
    "spynet_reporting": 0,
    "submit_samples":   2,
    "rtp_off":          0,
    "strict":           true
  },
  "input": { "path": "...", "size": 1310720, "sha256": "..." },
  "verdict": {
    "infected":    true,
    "threats":     [ {"name":"Trojan:Win32/Mimikatz","severity":"Severe","is_ml":false,"is_pua":false} ],
    "engine":      "1.1.24080.4",
    "vdm":         "1.413.2226.0",
    "elapsed_ms":  482,
    "raw_exit_code": 2
  },
  "bisect": {
    "status":      "found",
    "offset":      9520,
    "length":      192,
    "section":     ".text",
    "section_kind":"code",
    "scan_count":  18,
    "elapsed_ms":  8410,
    "hex":         "48 8b 05 ... 41 ff e0",
    "midpoint_span_warning": false
  }
}
```

The HTML variant renders the same fields as a styled, printable
report — useful for sharing with internal blue-team / detection
engineering folks.

## Troubleshooting

| Symptom                                   | Likely cause                                     | Fix                                                   |
|-------------------------------------------|--------------------------------------------------|-------------------------------------------------------|
| `MpCmdRun.exe not found`                  | Defender uninstalled / on Server core            | Pass `--mpcmdrun <path>`.                             |
| Verdict is `clean` for known-bad input    | RTP scrubbed the file before scan                | Add the temp dir to Defender exclusions.              |
| `Defender pre-condition gate failed`      | MAPS / sample submission still on                | Run the printed `Set-MpPreference` commands.          |
| Bisection stops at `midpoint_span`        | Signature straddles the half boundary            | Re-run with `--bisect-mode all` to peel every anchor. |
| Anchors all cluster around offset 0       | Legacy slice-and-scan parser-bail false-cleans   | Use a PE-aware `--bisect-scope` (default `sections`). |
| Every L/R scan still flags after `sections`| Signature is in a data directory (e.g. imports) | Retry with `--bisect-scope sections-all`.            |
| `[ML]` flag in stdout / report            | Threat is `*!ml`; engine refuses to bisect       | Expected. ML detections aren't byte-pattern based.    |
| `cannot write scan temp file`             | Workspace not writable / out of disk             | Pass `--temp-dir <path>`.                             |

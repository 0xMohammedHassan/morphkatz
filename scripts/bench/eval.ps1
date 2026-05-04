#Requires -Version 5.1
<#
.SYNOPSIS
    Run MorphKatz against a pre-fetched corpus and record YARA
    pre/post hit counts for the evasion benchmark.

.DESCRIPTION
    For each sample under <CorpusDir>/samples/*.bin:

      1. Scan original with yara64.exe against <YaraDir>/pack.yar;
         capture hit rule names.
      2. Run morphkatz.exe against the sample with the requested
         profile + seed, writing the morphed output and diff report
         under <OutDir>/<profile>/<sha>.morphed + <sha>.json.
      3. Scan the morphed output the same way; capture hit rule names.
      4. Append one JSON line to <OutDir>/results.jsonl with
         per-sample bookkeeping (pre hits, post hits, broken rules,
         wall_ms, bytes_changed, sha256_before/after, exit_code).

    The resulting JSON Lines file is what `aggregate.py` consumes.

    Sandbox guidance: run inside a network-isolated Windows VM with
    Defender real-time protection ENABLED but quarantine quarantined
    alerts sent to a host-only share. Never run on a production host.

.PARAMETER CorpusDir
    Directory produced by fetch_corpus.ps1 (expects `samples/*.bin`).

.PARAMETER YaraDir
    Directory produced by fetch_yara_pack.ps1 (expects `yara64.exe`
    and `pack.yar`).

.PARAMETER MorphKatzExe
    Path to built morphkatz.exe (Release). Default: probe
    `build/vs2022-x64/Release/morphkatz.exe` and
    `build/vs2022-x64-release/Release/morphkatz.exe`.

.PARAMETER OutDir
    Destination for morphed outputs, per-sample reports, and
    results.jsonl.

.PARAMETER Profile
    MorphKatz profile (`safe`, `normal`, `aggressive`). Run the
    script three times (one per profile) to populate all rows of the
    benchmark table.

.PARAMETER Seed
    RNG seed forwarded to morphkatz. Fixed across the whole run so
    results are reproducible for a given (corpus, rule-pack, seed,
    profile) tuple.

.PARAMETER Limit
    Skip after N samples; useful when iterating on the harness. 0 = all.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $CorpusDir,
    [Parameter(Mandatory)] [string] $YaraDir,
    [string] $MorphKatzExe,
    [Parameter(Mandatory)] [string] $OutDir,
    [ValidateSet('safe','normal','aggressive')] [string] $Profile = 'normal',
    [uint64] $Seed = 1,
    [int]    $Limit = 0
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Log([string]$msg, [ConsoleColor]$color = 'White') {
    $ts = Get-Date -Format 'HH:mm:ss'
    Write-Host "[$ts] $msg" -ForegroundColor $color
}

# --- 1. Resolve binaries ---------------------------------------------------
if (-not $MorphKatzExe) {
    $candidates = @(
        'build/vs2022-x64/Release/morphkatz.exe',
        'build/vs2022-x64-release/Release/morphkatz.exe'
    )
    foreach ($c in $candidates) {
        if (Test-Path $c) { $MorphKatzExe = (Resolve-Path $c).Path; break }
    }
    if (-not $MorphKatzExe) {
        throw "MorphKatz binary not found; pass -MorphKatzExe."
    }
}
if (-not (Test-Path $MorphKatzExe)) { throw "Missing: $MorphKatzExe" }

$yaraExe = Join-Path $YaraDir 'yara64.exe'
$yaraPack = Join-Path $YaraDir 'pack.yar'
if (-not (Test-Path $yaraExe))  { throw "Missing: $yaraExe (run fetch_yara_pack.ps1 first)" }
if (-not (Test-Path $yaraPack)) { throw "Missing: $yaraPack (run fetch_yara_pack.ps1 first)" }

$samples = Get-ChildItem (Join-Path $CorpusDir 'samples') -Filter '*.bin' -File
if ($samples.Count -eq 0) { throw "No *.bin samples under $CorpusDir\samples" }
if ($Limit -gt 0) { $samples = $samples | Select-Object -First $Limit }

$profDir = Join-Path $OutDir $Profile
New-Item -ItemType Directory -Force -Path $profDir | Out-Null
$resultsFile = Join-Path $OutDir 'results.jsonl'
if (-not (Test-Path $resultsFile)) { New-Item -ItemType File $resultsFile | Out-Null }

# --- 2. Helper: scan a file with yara; return rule-name array -------------
function Invoke-YaraScan([string]$target) {
    # `-L` prints rule names only, one per line. We don't parse meta yet.
    $raw = & $yaraExe -L $yaraPack $target 2>$null
    if ($LASTEXITCODE -ne 0) { return @() }
    # yara `-L` prints `rule_name filename` per match; extract rule names.
    $hits = @()
    foreach ($line in $raw) {
        $rule = ($line -split '\s+', 2)[0]
        if ($rule) { $hits += $rule }
    }
    return ($hits | Select-Object -Unique)
}

# --- 3. Main loop ----------------------------------------------------------
$env_info = @{
    os_caption     = (Get-CimInstance Win32_OperatingSystem).Caption
    os_build       = [Environment]::OSVersion.Version.ToString()
    cpu            = (Get-CimInstance Win32_Processor).Name
    ram_gb         = [math]::Round(((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB), 1)
    morphkatz_exe  = $MorphKatzExe
    morphkatz_version = (& $MorphKatzExe --version 2>$null | Select-Object -First 1)
    yara_version   = (& $yaraExe --version 2>$null)
    pack           = $yaraPack
    profile        = $Profile
    seed           = $Seed
    started_at     = (Get-Date).ToUniversalTime().ToString('o')
}
$env_info | ConvertTo-Json -Depth 3 |
    Set-Content (Join-Path $OutDir "env.$Profile.json") -Encoding UTF8

Log "Evaluating $($samples.Count) sample(s) at profile=$Profile seed=$Seed" Cyan
$completed = 0
foreach ($s in $samples) {
    $sha       = [IO.Path]::GetFileNameWithoutExtension($s.Name)
    $origPath  = $s.FullName
    $outPath   = Join-Path $profDir "$sha.morphed"
    $reportPath = Join-Path $profDir "$sha.json"

    $row = [ordered]@{
        sha256_before = $sha
        profile       = $Profile
        seed          = $Seed
        size_bytes    = $s.Length
    }

    # Pre-scan.
    $pre = Invoke-YaraScan $origPath
    $row.pre_hits = $pre

    # Run morphkatz.
    $sw = [Diagnostics.Stopwatch]::StartNew()
    try {
        & $MorphKatzExe $origPath `
            --profile $Profile `
            --seed $Seed `
            --output $outPath `
            --report $reportPath `
            --no-backup `
            --quiet *> $null
        $rc = $LASTEXITCODE
    } catch {
        $rc = 99
    }
    $sw.Stop()
    $row.exit_code  = $rc
    $row.wall_ms    = [math]::Round($sw.Elapsed.TotalMilliseconds, 1)

    if ($rc -eq 0 -and (Test-Path $outPath)) {
        $post = Invoke-YaraScan $outPath
        $row.post_hits     = $post
        $row.broken_rules  = @($pre | Where-Object { $post -notcontains $_ })
        $row.gained_rules  = @($post | Where-Object { $pre  -notcontains $_ })

        $row.sha256_after  = (Get-FileHash $outPath -Algorithm SHA256).Hash.ToLower()

        # Pull metrics out of the per-sample DiffReport if present.
        if (Test-Path $reportPath) {
            $j = Get-Content $reportPath -Raw | ConvertFrom-Json
            if ($j.metrics) {
                $row.bytes_changed     = $j.metrics.bytes_changed
                $row.bytes_changed_pct = $j.metrics.bytes_changed_pct
                $row.entropy_before    = $j.metrics.entropy_before
                $row.entropy_after     = $j.metrics.entropy_after
            }
        }
    } else {
        $row.post_hits    = @()
        $row.broken_rules = @()
        $row.error        = "morphkatz failed (rc=$rc)"
    }

    ($row | ConvertTo-Json -Compress -Depth 6) |
        Add-Content -Path $resultsFile -Encoding UTF8

    $completed++
    Log ("  [{0}/{1}] {2} : pre={3}, post={4}, broken={5}, wall={6}ms" -f `
         $completed, $samples.Count, $sha.Substring(0,12),
         $pre.Count, ($row.post_hits).Count, ($row.broken_rules).Count, $row.wall_ms)
}

Log "Wrote $resultsFile ($completed row(s))" Green
Log "Run aggregate.py next to produce benchmarks.md fragments." Green

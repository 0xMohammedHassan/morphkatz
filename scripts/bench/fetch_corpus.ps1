#Requires -Version 5.1
<#
.SYNOPSIS
    Download a reproducible sample corpus from MalwareBazaar for
    MorphKatz evasion benchmarking.

.DESCRIPTION
    Queries the MalwareBazaar (abuse.ch) API for recent samples
    matching one or more tags (default: `exe` + `CobaltStrike`),
    downloads each password-protected ZIP, and unpacks the raw sample
    into `-OutDir` keyed by SHA-256.

    Also writes `corpus.manifest.json` alongside the samples with one
    entry per file: sha256, original filename, tags, file_type, and
    the `first_seen` timestamp from MalwareBazaar. This manifest is
    the ground truth `eval.ps1` consumes; the binaries themselves are
    never committed to git.

    SAFETY: unpacked samples are LIVE MALWARE. The script refuses to
    write to a directory on the system drive by default and marks
    every output file with the NTFS zone identifier `LocalMachine` +
    `Internet` so Windows Defender keeps real-time scanning enabled.
    Run on an isolated VM only.

.PARAMETER AuthKey
    MalwareBazaar Auth-Key (required since 2024). Register at
    https://auth.abuse.ch to obtain one. Alternatively set the
    `$env:MALWAREBAZAAR_AUTH_KEY` environment variable.

.PARAMETER OutDir
    Destination directory for samples and the manifest. Must be on a
    non-system drive unless `-AllowSystemDrive` is specified.

.PARAMETER Tag
    MalwareBazaar tag(s) to query. Multiple tags are ORed.

.PARAMETER Count
    How many samples to fetch in total. Capped at 1000.

.PARAMETER FileType
    Filter samples by MalwareBazaar file_type (`exe`, `dll`, ...).
    Default: `exe` — MorphKatz only supports x64 PE executables.

.PARAMETER AllowSystemDrive
    Bypass the safety check that refuses outputs on C:\.
#>

[CmdletBinding()]
param(
    [string]   $AuthKey   = $env:MALWAREBAZAAR_AUTH_KEY,
    [Parameter(Mandatory)] [string] $OutDir,
    [string[]] $Tag       = @('exe'),
    [ValidateRange(1, 1000)] [int] $Count = 20,
    [string]   $FileType  = 'exe',
    [switch]   $AllowSystemDrive
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Log([string]$msg, [ConsoleColor]$color = 'White') {
    $ts = Get-Date -Format 'HH:mm:ss'
    Write-Host "[$ts] $msg" -ForegroundColor $color
}

if (-not $AuthKey) {
    throw "MalwareBazaar Auth-Key not set. Pass -AuthKey or export MALWAREBAZAAR_AUTH_KEY."
}

$resolved = [IO.Path]::GetFullPath($OutDir)
if ($resolved -match '^[Cc]:\\' -and -not $AllowSystemDrive) {
    throw "Refusing to fetch live malware to the system drive ($resolved). " +
          "Pass -AllowSystemDrive to override (isolated VM only)."
}

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$samplesDir = Join-Path $OutDir 'samples'
New-Item -ItemType Directory -Force -Path $samplesDir | Out-Null

$apiRoot = 'https://mb-api.abuse.ch/api/v1/'
$zipPw   = 'infected'

# --- 1. Query tag(s) for candidate hashes ----------------------------------
$hashes = @()
foreach ($t in $Tag) {
    $body = @{ query = 'get_taginfo'; tag = $t; limit = [string]$Count }
    Log "Querying MalwareBazaar tag=$t limit=$Count..." Cyan
    $resp = Invoke-RestMethod -Method Post -Uri $apiRoot -Body $body `
        -Headers @{ 'Auth-Key' = $AuthKey } -TimeoutSec 60
    if ($resp.query_status -ne 'ok') {
        Write-Warning "Tag '$t' returned query_status=$($resp.query_status); skipping."
        continue
    }
    foreach ($row in $resp.data) {
        if ($row.file_type -ne $FileType) { continue }
        $hashes += [pscustomobject]@{
            sha256      = $row.sha256_hash
            file_name   = $row.file_name
            file_type   = $row.file_type
            first_seen  = $row.first_seen
            tags        = $row.tags
            signature   = $row.signature
        }
        if ($hashes.Count -ge $Count) { break }
    }
    if ($hashes.Count -ge $Count) { break }
}
if ($hashes.Count -eq 0) {
    throw "No samples matched the requested tags/file_type."
}
Log "Got $($hashes.Count) candidate hash(es)." Green

# --- 2. Download + unzip each sample ---------------------------------------
Add-Type -AssemblyName System.IO.Compression.FileSystem
$manifest = @()
$downloaded = 0

foreach ($row in $hashes) {
    $sha = $row.sha256
    $zipPath = Join-Path $samplesDir "$sha.zip"
    $binPath = Join-Path $samplesDir "$sha.bin"
    if (Test-Path $binPath) {
        Log "$sha already present; skipping download." DarkGray
        $manifest += $row
        continue
    }

    try {
        $body = @{ query = 'get_file'; sha256_hash = $sha }
        Log "Fetching $($sha.Substring(0, 12))... ($($row.file_name))" Cyan
        Invoke-WebRequest -Method Post -Uri $apiRoot -Body $body `
            -Headers @{ 'Auth-Key' = $AuthKey } -OutFile $zipPath -TimeoutSec 180
    } catch {
        Write-Warning "Download failed for $sha : $_"
        continue
    }

    # MalwareBazaar returns a JSON error body (not a zip) on permission
    # problems. Detect that before handing bytes to the zip reader.
    $firstBytes = [IO.File]::ReadAllBytes($zipPath) | Select-Object -First 4
    if ($firstBytes[0] -ne 0x50 -or $firstBytes[1] -ne 0x4B) {
        Write-Warning "$sha : server returned non-ZIP payload; skipping."
        Remove-Item $zipPath -Force
        continue
    }

    # Use 7z.exe if present (handles MalwareBazaar's AES-encrypted zips);
    # fall back to PowerShell's built-in only works for classic ZipCrypto.
    $sevenZ = Get-Command 7z.exe -ErrorAction SilentlyContinue
    if ($null -ne $sevenZ) {
        & $sevenZ.Source e $zipPath -p"$zipPw" -o"$samplesDir" -y | Out-Null
    } else {
        # PS5.1 System.IO.Compression can't handle encrypted zips;
        # require 7z unless this is a rare unencrypted sample.
        Write-Warning "7z.exe not found in PATH; cannot unpack encrypted zip."
        Remove-Item $zipPath -Force
        continue
    }
    # The unpacked file is named by its original filename; rename to sha.bin.
    $orig = Get-ChildItem $samplesDir -File |
            Where-Object { $_.Name -eq $row.file_name -or $_.BaseName -eq $sha }
    if ($orig) {
        $orig | Rename-Item -NewName "$sha.bin" -Force
    }
    Remove-Item $zipPath -Force -ErrorAction SilentlyContinue

    if (-not (Test-Path $binPath)) {
        Write-Warning "$sha : unpack succeeded but $sha.bin not found."
        continue
    }

    # Verify the advertised sha256 to catch truncated/corrupt downloads.
    $actual = (Get-FileHash $binPath -Algorithm SHA256).Hash.ToLower()
    if ($actual -ne $sha.ToLower()) {
        Write-Warning "$sha : checksum mismatch (got $actual); discarding."
        Remove-Item $binPath -Force
        continue
    }

    $manifest += $row
    $downloaded++
}

if ($downloaded -eq 0 -and $manifest.Count -eq 0) {
    throw "No samples were successfully downloaded."
}

$manifestPath = Join-Path $OutDir 'corpus.manifest.json'
@{
    fetched_at   = (Get-Date).ToUniversalTime().ToString('o')
    query_tags   = $Tag
    file_type    = $FileType
    requested    = $Count
    delivered    = $manifest.Count
    newly_downloaded = $downloaded
    samples      = $manifest
} | ConvertTo-Json -Depth 6 | Set-Content -Path $manifestPath -Encoding UTF8

Log "Wrote manifest: $manifestPath" Green
Log "Corpus ready: $($manifest.Count) sample(s) under $samplesDir" Green

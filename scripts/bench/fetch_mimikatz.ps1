#requires -RunAsAdministrator
<#
.SYNOPSIS
    Fetch the upstream gentilkiwi/mimikatz Windows release for manual,
    opt-in MorphKatz validation. Configures Defender exclusions and
    snapshots Defender preferences so the change can be reverted.

.DESCRIPTION
    The mimikatz binary is detected by Microsoft Defender as a
    high-severity threat (Trojan:Win32/Mimikatz) and several adjacent
    families. This script downloads the upstream release zip, verifies
    a pinned SHA-256, extracts it into a workspace folder, and adds
    that folder to the Defender exclusion list so the scanner can read
    the bytes without immediate quarantine.

    -Confirm    is REQUIRED on the initial fetch. The script aborts
                without it.
    -Restore    re-applies the snapshotted Defender preferences and
                removes the exclusion path. Run this when finished.
    -OutputDir  workspace path. Defaults to .\mimikatz-bench

.NOTES
    This script is for *authorised security research only*. You are
    responsible for the legal, ethical, and operational consequences
    of running this on machines you do not own. See
    docs/mimikatz-test.md for the full procedure.

    The script is opt-in. MorphKatz NEVER downloads, embeds, or links
    against mimikatz; the binary lives outside the repo.

    The pinned SHA-256 below is checked against the published release
    asset. Update it when bumping `MimikatzReleaseTag`.

.EXAMPLE
    PS> .\fetch_mimikatz.ps1 -Confirm -OutputDir .\mimikatz-bench
    PS> # ... run the morphkatz scan / morph experiments ...
    PS> .\fetch_mimikatz.ps1 -Restore -OutputDir .\mimikatz-bench
#>
[CmdletBinding(DefaultParameterSetName = 'Fetch')]
param(
    [Parameter(ParameterSetName = 'Fetch')]
    [switch]$Confirm,

    [Parameter(ParameterSetName = 'Restore')]
    [switch]$Restore,

    [string]$OutputDir = (Join-Path (Get-Location) 'mimikatz-bench'),

    # Tag of the upstream release to fetch. Bumping this means re-pinning
    # the SHA-256 below.
    [string]$MimikatzReleaseTag = '2.2.0-20220919',

    # SHA-256 of mimikatz_trunk.zip from the pinned release. Verify this
    # against the official release page before merging a bump.
    [string]$ExpectedZipSha256  = ''
)

$ErrorActionPreference = 'Stop'

function Write-Banner {
    param([string]$Title, [string]$Body)
    $bar = '=' * 70
    Write-Host ''
    Write-Host $bar -ForegroundColor Yellow
    Write-Host "  $Title" -ForegroundColor Yellow
    Write-Host $bar -ForegroundColor Yellow
    if ($Body) { Write-Host $Body }
    Write-Host ''
}

function Ensure-Admin {
    $isAdmin = ([Security.Principal.WindowsPrincipal](
        [Security.Principal.WindowsIdentity]::GetCurrent())
    ).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
    if (-not $isAdmin) {
        throw "Set-MpPreference / Add-MpPreference need elevation. Re-launch from an elevated PowerShell."
    }
}

function Snapshot-MpPrefs {
    param([string]$Path)
    Get-MpPreference | ConvertTo-Json -Depth 6 | Out-File -FilePath $Path -Encoding UTF8
    Write-Host "Snapshotted Defender preferences to $Path" -ForegroundColor Green
}

function Restore-MpPrefs {
    param([string]$Path)
    if (-not (Test-Path $Path)) {
        Write-Warning "No snapshot at $Path; skipping Defender restore."
        return
    }
    $prefs = Get-Content $Path -Raw | ConvertFrom-Json
    # Only restore the four preferences we actually touch. Restoring
    # the entire Get-MpPreference output is brittle - many fields are
    # read-only and Set-MpPreference rejects them.
    $args = @{}
    if ($prefs.MAPSReporting -ne $null) {
        $args.MAPSReporting = $prefs.MAPSReporting
    }
    if ($prefs.SubmitSamplesConsent -ne $null) {
        $args.SubmitSamplesConsent = $prefs.SubmitSamplesConsent
    }
    if ($prefs.DisableRealtimeMonitoring -ne $null) {
        $args.DisableRealtimeMonitoring = $prefs.DisableRealtimeMonitoring
    }
    if ($args.Count -gt 0) {
        Set-MpPreference @args
        Write-Host "Restored Defender preferences from snapshot." -ForegroundColor Green
    } else {
        Write-Warning "Snapshot at $Path had no usable values."
    }
}

function Fetch-Mimikatz {
    Ensure-Admin

    if (-not $Confirm) {
        Write-Banner -Title 'Consent required' -Body @"
This script downloads mimikatz from the upstream gentilkiwi GitHub
release. mimikatz is a credential-dumping tool that Microsoft Defender
flags as Trojan:Win32/Mimikatz (and several adjacent families).

By passing -Confirm you assert that:
  - You own this machine, OR
  - You have explicit written authorisation from the owner to run
    credential-dumping malware on it.
  - You will run this inside an isolated VM / lab network.
  - You will run this script in -Restore mode when finished.

Re-run with -Confirm to proceed.
"@
        exit 1
    }

    Write-Banner -Title 'Fetching mimikatz' -Body "Release: $MimikatzReleaseTag"

    $null = New-Item -ItemType Directory -Force -Path $OutputDir
    $OutputDir = (Resolve-Path $OutputDir).Path

    # Configure Defender BEFORE the download so RTP doesn't yank the
    # zip mid-stream. We also snapshot first so -Restore is meaningful.
    $snapshot = Join-Path $OutputDir 'mp-prefs.snapshot.json'
    Snapshot-MpPrefs -Path $snapshot

    Set-MpPreference -MAPSReporting Disabled
    Set-MpPreference -SubmitSamplesConsent NeverSend
    # Note: we deliberately do NOT toggle DisableRealtimeMonitoring;
    # the scanner only requires MAPS+submit off. RTP off would be a
    # bigger lift and is left to the user.

    Add-MpPreference -ExclusionPath $OutputDir -Force
    Write-Host "Added Defender exclusion: $OutputDir" -ForegroundColor Green

    $url = "https://github.com/gentilkiwi/mimikatz/releases/download/$MimikatzReleaseTag/mimikatz_trunk.zip"
    $zip = Join-Path $OutputDir 'mimikatz_trunk.zip'
    Write-Host "Downloading $url -> $zip"
    Invoke-WebRequest -Uri $url -OutFile $zip -UseBasicParsing

    $actual = (Get-FileHash -Algorithm SHA256 -Path $zip).Hash
    Write-Host "SHA-256: $actual"
    if ($ExpectedZipSha256 -and ($actual -ne $ExpectedZipSha256)) {
        Remove-Item $zip -Force
        throw "SHA-256 mismatch: expected $ExpectedZipSha256, got $actual. Re-pin and try again."
    }
    if (-not $ExpectedZipSha256) {
        Write-Warning "No -ExpectedZipSha256 supplied; the download was NOT verified. Re-run with the pinned hash."
    }

    Expand-Archive -Path $zip -DestinationPath (Join-Path $OutputDir 'extracted') -Force
    Write-Host "Extracted to $(Join-Path $OutputDir 'extracted')" -ForegroundColor Green

    Write-Banner -Title 'Done' -Body @"
Mimikatz binaries are at:
    $(Join-Path $OutputDir 'extracted')

Suggested next steps (from the repo root):
    morphkatz scan "$OutputDir\extracted\x64\mimikatz.exe" --bisect --report scan-pre.json
    morphkatz "$OutputDir\extracted\x64\mimikatz.exe" --target-defender "$OutputDir\extracted\x64\mimikatz.exe" --seed 42 --report mimikatz.html
    morphkatz scan "$OutputDir\extracted\x64\mimikatz.patched.exe" --report scan-post.json

When you are finished, run:
    .\fetch_mimikatz.ps1 -Restore -OutputDir "$OutputDir"
to remove the Defender exclusion and revert MAPS/Submit settings.
"@
}

function Restore-Workspace {
    Ensure-Admin

    if (-not (Test-Path $OutputDir)) {
        Write-Warning "OutputDir $OutputDir doesn't exist; nothing to restore."
        return
    }
    $OutputDir = (Resolve-Path $OutputDir).Path

    Remove-MpPreference -ExclusionPath $OutputDir -ErrorAction SilentlyContinue
    Write-Host "Removed Defender exclusion: $OutputDir" -ForegroundColor Green

    $snapshot = Join-Path $OutputDir 'mp-prefs.snapshot.json'
    Restore-MpPrefs -Path $snapshot

    Write-Banner -Title 'Restored' -Body @"
Workspace is no longer Defender-excluded. The mimikatz binaries
themselves are still on disk at $OutputDir; delete them yourself
if you no longer need them.
"@
}

if ($Restore) { Restore-Workspace } else { Fetch-Mimikatz }

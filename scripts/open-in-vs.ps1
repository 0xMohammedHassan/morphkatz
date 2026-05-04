#requires -Version 5.1
<#
.SYNOPSIS
    Configure the MorphKatz CMake project with the Visual Studio 17 2022
    generator and open the resulting MorphKatz.sln in the IDE.

.DESCRIPTION
    Hand-maintaining .sln/.vcxproj files alongside CMakeLists.txt is a
    losing battle (every target, source file, include dir, and vcpkg
    linkage would have to be mirrored twice). Instead, the project ships
    a Visual Studio CMake preset; this script runs the preset and
    launches the IDE on the generated solution so contributors get the
    classic "double-click the .sln" experience.

.PARAMETER Preset
    CMake configure preset. Must be one of the VS generator presets from
    CMakePresets.json. Defaults to "vs2022-x64".

.PARAMETER Fresh
    Pass --fresh to CMake so the cache is rebuilt from scratch.

.PARAMETER NoOpen
    Configure only; do not launch devenv. Useful for CI smoke checks.

.EXAMPLE
    PS> .\scripts\open-in-vs.ps1
    Configures build\vs2022-x64\ and opens MorphKatz.sln in Visual Studio.

.EXAMPLE
    PS> .\scripts\open-in-vs.ps1 -Preset vs2022-x64-asan -Fresh
    Regenerates the ASan solution from a clean cache.
#>

[CmdletBinding()]
param(
    [ValidateSet("vs2022-x64", "vs2022-x64-asan")]
    [string]$Preset = "vs2022-x64",

    [switch]$Fresh,
    [switch]$NoOpen
)

$ErrorActionPreference = "Stop"
$script:RepoRoot = Split-Path -Parent $PSScriptRoot

function Fail($msg) {
    Write-Host "error: $msg" -ForegroundColor Red
    exit 1
}

function Require-Cmd($name) {
    if (-not (Get-Command $name -ErrorAction SilentlyContinue)) {
        Fail "'$name' is not on PATH. Install it and retry."
    }
}

Push-Location $script:RepoRoot
try {
    Write-Host "== MorphKatz: Open in Visual Studio ==" -ForegroundColor Cyan
    Write-Host "repo:   $script:RepoRoot"
    Write-Host "preset: $Preset"

    Require-Cmd "cmake"

    if (-not $env:VCPKG_ROOT) {
        Fail @"
VCPKG_ROOT environment variable is not set.

MorphKatz's dependencies (Zydis, LIEF, YARA, Unicorn, ...) are resolved
through vcpkg in manifest mode. Install vcpkg, then set the env var
persistently:

    git clone https://github.com/microsoft/vcpkg  C:\src\vcpkg
    C:\src\vcpkg\bootstrap-vcpkg.bat
    [Environment]::SetEnvironmentVariable('VCPKG_ROOT', 'C:\src\vcpkg', 'User')

Then open a new PowerShell and re-run this script.
"@
    }

    if (-not (Test-Path "$env:VCPKG_ROOT\scripts\buildsystems\vcpkg.cmake")) {
        Fail "VCPKG_ROOT is '$env:VCPKG_ROOT' but vcpkg.cmake is missing. Did bootstrap-vcpkg complete?"
    }

    $configureArgs = @("--preset", $Preset)
    if ($Fresh) { $configureArgs += "--fresh" }

    Write-Host ""
    Write-Host "[1/2] cmake $($configureArgs -join ' ')" -ForegroundColor Yellow
    cmake @configureArgs
    if ($LASTEXITCODE -ne 0) { Fail "CMake configure failed with exit code $LASTEXITCODE." }

    $sln = Join-Path $script:RepoRoot "build\$Preset\MorphKatz.sln"
    if (-not (Test-Path $sln)) {
        Fail "Expected solution not found: $sln`n(CMake may have changed output layout; check build/$Preset/ by hand.)"
    }

    Write-Host ""
    Write-Host "[2/2] solution: $sln" -ForegroundColor Yellow

    if ($NoOpen) {
        Write-Host "  -NoOpen set; skipping devenv launch."
        exit 0
    }

    # Prefer the classic devenv.exe via vswhere so we match the toolset used
    # at configure time. Falls back to Start-Process (Windows file association)
    # if vswhere is unavailable.
    $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    $devenv  = $null
    if (Test-Path $vswhere) {
        $devenv = & $vswhere -latest -prerelease `
            -requires Microsoft.Component.MSBuild `
            -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
            -property productPath 2>$null
    }

    if ($devenv -and (Test-Path $devenv)) {
        Write-Host "  launching: $devenv" -ForegroundColor Green
        Start-Process -FilePath $devenv -ArgumentList "`"$sln`""
    } else {
        Write-Host "  launching via file association" -ForegroundColor Green
        Start-Process -FilePath $sln
    }
}
finally {
    Pop-Location
}

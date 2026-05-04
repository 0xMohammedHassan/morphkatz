#Requires -Version 5.1
<#
.SYNOPSIS
    One-shot cold build pipeline for MorphKatz on Windows.

.DESCRIPTION
    Runs a full, cold-cache build of MorphKatz end-to-end: vcpkg dependency
    resolution, CMake configure, Release build, ctest, and a final smoke
    invocation of morphkatz.exe --version.

    Designed to run unattended (the cold vcpkg build is 45-75 minutes on a
    fresh VCPKG_ROOT because LIEF, Unicorn, and YARA all compile from source).

    Invoked once by the assistant during first-run verification; not part of
    the daily developer flow.

.PARAMETER Preset
    CMake configure preset. Defaults to vs2022-x64.

.PARAMETER BuildPreset
    CMake build preset. Defaults to vs2022-x64-release.

.PARAMETER TestPreset
    CTest preset. Defaults to vs2022-x64-release.

.PARAMETER CMake
    Full path to cmake.exe (probed if omitted).
#>

[CmdletBinding()]
param(
    [string] $Preset      = 'vs2022-x64',
    [string] $BuildPreset = 'vs2022-x64-release',
    [string] $TestPreset  = 'vs2022-x64-release',
    [string] $CMake
)

$ErrorActionPreference = 'Stop'

function Log([string]$msg, [ConsoleColor]$color = 'White') {
    $ts = Get-Date -Format 'HH:mm:ss'
    Write-Host "[$ts] $msg" -ForegroundColor $color
}

function Step([string]$name, [scriptblock]$block) {
    Log "=== BEGIN $name ===" Cyan
    $sw = [Diagnostics.Stopwatch]::StartNew()
    try {
        & $block
        $sw.Stop()
        Log "=== END   $name  ($([math]::Round($sw.Elapsed.TotalSeconds,1))s) ===" Green
    } catch {
        $sw.Stop()
        Log "=== FAIL  $name  ($([math]::Round($sw.Elapsed.TotalSeconds,1))s): $_ ===" Red
        throw
    }
}

# --- 1. locate cmake ----------------------------------------------------
if (-not $CMake) {
    $candidates = @(
        "$env:ProgramFiles\CMake\bin\cmake.exe",
        "${env:ProgramFiles(x86)}\CMake\bin\cmake.exe"
    )
    $CMake = $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
    if (-not $CMake) { throw "cmake.exe not found on standard install paths" }
}
$CTest = Join-Path (Split-Path $CMake) 'ctest.exe'

Log "cmake: $CMake"
Log "ctest: $CTest"
Log "vcpkg: $env:VCPKG_ROOT"
Log "host : $env:COMPUTERNAME  ($env:NUMBER_OF_PROCESSORS logical CPUs)"
Log ""

# --- 2. sanity-check VCPKG_ROOT -----------------------------------------
if (-not $env:VCPKG_ROOT) { throw "VCPKG_ROOT is not set" }
if (-not (Test-Path "$env:VCPKG_ROOT\vcpkg.exe")) {
    throw "vcpkg.exe not found under VCPKG_ROOT ($env:VCPKG_ROOT). Run bootstrap-vcpkg.bat first."
}

# --- 3. build pipeline --------------------------------------------------
$srcDir = Split-Path -Parent $PSScriptRoot
Log "source dir: $srcDir"
Set-Location $srcDir

Step "CMake configure (preset: $Preset)" {
    & $CMake --preset $Preset
    if ($LASTEXITCODE -ne 0) { throw "cmake configure exited with $LASTEXITCODE" }
}

Step "CMake build (preset: $BuildPreset, parallel)" {
    & $CMake --build --preset $BuildPreset --parallel
    if ($LASTEXITCODE -ne 0) { throw "cmake build exited with $LASTEXITCODE" }
}

Step "CTest (preset: $TestPreset)" {
    & $CTest --preset $TestPreset
    if ($LASTEXITCODE -ne 0) { throw "ctest exited with $LASTEXITCODE" }
}

# --- 4. smoke invocation of the built exe -------------------------------
$exe = Get-ChildItem -Path "$srcDir\build\$Preset" -Recurse -Filter morphkatz.exe -ErrorAction SilentlyContinue |
       Where-Object { $_.FullName -notmatch '\\_deps\\' } |
       Select-Object -First 1 -ExpandProperty FullName
if (-not $exe) { throw "morphkatz.exe not found under build\$Preset" }

Step "morphkatz.exe smoke (--version, --help)" {
    Log "exe: $exe"
    & $exe --version
    if ($LASTEXITCODE -ne 0) { throw "--version exited with $LASTEXITCODE" }
    Write-Host ""
    & $exe --help | Select-Object -First 40
}

Log ""
Log "====================================" Green
Log " ALL GREEN - MorphKatz builds clean." Green
Log "====================================" Green
Log "Binary: $exe"

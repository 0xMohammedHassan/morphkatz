@echo off
REM ---------------------------------------------------------------------------
REM  MorphKatz - one-click "Open in Visual Studio" entry point.
REM
REM  Double-click this file (or run it from cmd/PowerShell) to:
REM    1. Ensure VCPKG_ROOT is set.
REM    2. Configure the CMake project with the Visual Studio 17 2022 generator.
REM    3. Open the generated MorphKatz.sln in the IDE.
REM
REM  Any extra CLI args are forwarded to scripts\open-in-vs.ps1. Examples:
REM    Open-in-VS.cmd                 (defaults: preset=vs2022-x64)
REM    Open-in-VS.cmd -Preset vs2022-x64-asan
REM    Open-in-VS.cmd -Fresh          (nuke the CMake cache first)
REM    Open-in-VS.cmd -NoOpen         (configure only; useful for CI)
REM ---------------------------------------------------------------------------

setlocal
set "SCRIPT_DIR=%~dp0"

powershell.exe -NoProfile -ExecutionPolicy Bypass ^
    -File "%SCRIPT_DIR%scripts\open-in-vs.ps1" %*
set "EXITCODE=%ERRORLEVEL%"

if not "%EXITCODE%"=="0" (
    echo.
    echo Open-in-VS.cmd exited with code %EXITCODE%.
    echo See the error message above for details.
    pause
)
exit /b %EXITCODE%

@echo off
REM Builds amsi_patch_demo.cpp into amsi_patch_demo.exe using MSVC.
REM Defender will quarantine the OUTPUT during/after link unless RTP is
REM paused or the output dir is excluded. We write the .exe to %TEMP%
REM first to avoid spurious deletion in the workspace.

setlocal
set "VCVARS=C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
if not exist "%VCVARS%" (
  echo [build] vcvars64.bat not found at: %VCVARS%
  exit /b 1
)

call "%VCVARS%" >nul
if errorlevel 1 (
  echo [build] vcvars64.bat failed
  exit /b 1
)

set "SRC=%~dp0amsi_patch_demo.cpp"
set "OUT=%~1"
if "%OUT%"=="" set "OUT=%~dp0amsi_patch_demo.exe"

REM /Os: optimize for size  -> small .text we can fully bisect
REM /GS-: skip stack cookies -> smaller .text, easier to read
REM /MT: static CRT          -> self-contained .exe (no UCRT side-deps)
REM /O1: optimize for size & speed compromise
REM /EHsc: standard C++ exception model
REM We DON'T strip anything; we want the textbook patterns visible.
cl.exe /nologo /std:c++17 /EHsc /O1 /Os /GS- /MT ^
  /Fo:"%TEMP%\amsi_patch_demo.obj" ^
  /Fe:"%OUT%" ^
  "%SRC%" ^
  /link /SUBSYSTEM:CONSOLE /NODEFAULTLIB:libcmtd.lib advapi32.lib kernel32.lib user32.lib

if errorlevel 1 (
  echo [build] cl.exe failed
  exit /b 1
)

echo [build] OK = %OUT%
endlocal

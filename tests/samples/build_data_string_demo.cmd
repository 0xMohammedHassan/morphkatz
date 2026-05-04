@echo off
REM build_data_string_demo.cmd -- compile data_string_demo.exe with cl.exe.
REM
REM Usage: from a Visual Studio "x64 Native Tools Command Prompt":
REM   cd tests\samples
REM   build_data_string_demo.cmd [out_dir]
REM
REM out_dir defaults to the current directory.

setlocal
set OUT_DIR=%~1
if "%OUT_DIR%"=="" set OUT_DIR=%~dp0

set OUT_EXE=%OUT_DIR%\data_string_demo.exe

where cl.exe >nul 2>&1
if errorlevel 1 (
    echo [build_data_string_demo] cl.exe not found in PATH; run from an
    echo                          x64 Native Tools Command Prompt.
    exit /b 1
)

cl /nologo /MD /Os /EHsc ^
    /Fe"%OUT_EXE%" ^
    "%~dp0data_string_demo.cpp" ^
    /link /SUBSYSTEM:CONSOLE
if errorlevel 1 (
    echo [build_data_string_demo] cl.exe failed
    exit /b 1
)
echo [build_data_string_demo] -^> %OUT_EXE%
endlocal

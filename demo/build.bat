@echo off
REM ═══════════════════════════════════════════════════════════════════
REM  FerrIL Demo — Build Script
REM  Compiles DemoPayload.dll and DemoTarget.exe using csc.exe from
REM  .NET Framework 4.x installed on the system.
REM ═══════════════════════════════════════════════════════════════════

setlocal enabledelayedexpansion

set OUTDIR=%~dp0build
set CSC=

REM Find csc.exe — prefer 4.x framework
for %%v in (v4.0.30319 v3.5) do (
    if exist "%WINDIR%\Microsoft.NET\Framework\%%v\csc.exe" (
        set CSC=%WINDIR%\Microsoft.NET\Framework\%%v\csc.exe
        goto :found_csc
    )
)

echo ERROR: Cannot find .NET Framework csc.exe
echo Install .NET Framework 4.x Developer Pack or SDK
exit /b 1

:found_csc
echo Using compiler: %CSC%
echo Output dir:     %OUTDIR%
echo.

if not exist "%OUTDIR%" mkdir "%OUTDIR%"

REM ── Step 1: Build DemoPayload.dll (cert pinning + crypto + Stage2) ──
echo [1/2] Building DemoPayload.dll...
"%CSC%" /nologo /target:library /optimize ^
    /out:"%OUTDIR%\DemoPayload.dll" ^
    "%~dp0DemoPayload\Stage2.cs"

if errorlevel 1 (
    echo FAILED: DemoPayload.dll
    exit /b 1
)
echo      OK: %OUTDIR%\DemoPayload.dll

REM ── Step 2: Build DemoTarget.exe (loader, x86) ─────────────────────
echo [2/2] Building DemoTarget.exe (x86)...
"%CSC%" /nologo /target:exe /optimize /platform:x86 ^
    /out:"%OUTDIR%\DemoTarget.exe" ^
    "%~dp0DemoTarget\Program.cs" ^
    "%~dp0DemoTarget\AssemblyLoader.cs" ^
    "%~dp0DemoTarget\EmbeddedPayload.cs"

if errorlevel 1 (
    echo FAILED: DemoTarget.exe
    exit /b 1
)
echo      OK: %OUTDIR%\DemoTarget.exe

echo.
echo Build successful!

endlocal

@echo off
rem Shared helper for the build scripts: resolves the IDA SDK and IDA install from the
rem environment, and reports a usable error instead of silently configuring against whatever
rem CMake had cached from a previous run.
rem
rem Override any of these before calling:
rem   IDASDK  - IDA SDK root (the directory holding include/ and lib/, or its parent holding src/)
rem   IDASDK_SRC - the SDK src/ directory, if it does not follow from IDASDK
rem   IDADIR  - IDA installation directory the plugin DLL is deployed into ("" to skip deploy)
rem   TREX_SDK_HINT - comma-separated extra locations to probe when IDASDK is not set
rem
rem After `call scripts\buildenv.bat` the caller can use:
rem   %IDASDK_SRC%   SDK src/ dir (has include/ and lib/)
rem   %IDADIR%       IDA install dir, possibly empty
setlocal

rem Normalize IDASDK to the directory that actually contains include/hexrays.hpp: callers may
rem hand us either the SDK root or the root's src/ subdirectory.
if defined IDASDK call :normalize_sdk "%IDASDK%"
if not defined IDASDK_SRC set "IDASDK_SRC=%IDASDK%"

if not defined IDASDK_SRC goto :nosdk
if not exist "%IDASDK_SRC%\include\hexrays.hpp" goto :nosdk

rem IDA_INSTALL_DIR defaults to IDADIR; an explicitly empty IDASDK-only build is still fine.
if not defined IDADIR set "IDADIR=%IDA_INSTALL_DIR%"
endlocal & (
  set "IDASDK_SRC=%IDASDK_SRC%"
  set "IDADIR=%IDADIR%"
  exit /b 0
)

:nosdk
echo ERROR: no IDA SDK found. Set IDASDK to an ida-sdk checkout, e.g.
echo    set IDASDK=E:\dev\ida-sdk-9.4\ida-sdk-9.4.0-sdk.1\src
echo.
echo The SDK tag must match the IDA you run: init_hexrays_plugin() compares a compile-time
echo HEXRAYS_API_MAGIC against the running IDA, so a mismatched pair yields a plugin that
echo refuses to load with "no decompiler available" even though the decompiler is installed.
endlocal & exit /b 1

:normalize_sdk
rem %~1 is the raw IDASDK value. Accept <root> (has include\hexrays.hpp) or <root>\src.
setlocal
set "P=%~1"
if exist "%~1\include\hexrays.hpp" (
  endlocal & set "IDASDK=%~1" & set "IDASDK_SRC=%~1" & exit /b 0
)
if exist "%~1\src\include\hexrays.hpp" (
  endlocal & set "IDASDK=%~1" & set "IDASDK_SRC=%~1\src" & exit /b 0
)
endlocal & set "IDASDK=%~1" & set "IDASDK_SRC=%~1" & exit /b 0

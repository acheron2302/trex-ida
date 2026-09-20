@echo off
rem Syntax-check one translation unit with the Intel compiler (the required configuration),
rem without touching the project build.
rem usage: scripts\check.bat <file.cpp>   (one at a time: /Fo needs a single TU)
setlocal
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" >nul || exit /b 1
call "D:\Intel\oneAPI\setvars.bat" >nul || exit /b 1
if not exist "%TEMP%\trexchk" mkdir "%TEMP%\trexchk" >nul 2>&1
set SDK=E:\tools\plugins\ida plug\ida-sdk\src\include
icx-cl /nologo /c /std:c++20 /EHsc /W3 /Wno-unknown-pragmas ^
  /D__NT__ /D__IDP__ /D__EA64__=1 /D_CRT_SECURE_NO_WARNINGS ^
  /I"%~dp0..\include" /I"%SDK%" /I"%~dp0..\src" /I"%~dp0..\src\frontends\ida" /I"%~dp0..\src\plugin" /I"%~dp0..\tests" ^
  /Fo"%TEMP%\trexchk\\" %*
echo CHECK_EXIT=%ERRORLEVEL%
endlocal

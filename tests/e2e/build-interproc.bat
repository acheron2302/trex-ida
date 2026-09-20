@echo off
setlocal
rem Build the inter-procedural propagation fixture, unoptimized so the calls survive inlining.
rem No debug information: IDA must see names (from the export table) but no types.
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" >nul || exit /b 1
cd /d "%~dp0"
cl /nologo /Od /GS- /Fe:interproc.exe interproc.c || exit /b 1
del /q interproc.pdb interproc.obj interproc.lib interproc.exp 2>nul
echo built %~dp0interproc.exe
endlocal

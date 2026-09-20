@echo off
setlocal
rem Build the end-to-end fixture with no debug information (IDA must see no types).
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" >nul || exit /b 1
cd /d "%~dp0"
cl /nologo /O2 /GS- /Fe:fixture.exe fixture.c || exit /b 1
del /q fixture.pdb 2>nul
rem also drop the import lib and object: only the exe is needed
del /q fixture.obj fixture.lib 2>nul
echo built %~dp0fixture.exe
endlocal

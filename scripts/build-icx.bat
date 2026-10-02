@echo off
setlocal
rem Build trexida with the Intel oneAPI DPC++/C++ compiler (icx-cl, MSVC ABI).
rem IDASDK / IDADIR select the SDK and IDA locations (see scripts\buildenv.bat); IDEVARS points at
rem oneAPI's setvars.bat when it is not on the default path. No machine-specific path is baked in.
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" >nul || exit /b 1
if not defined IDEVARS if exist "D:\Intel\oneAPI\setvars.bat" set "IDEVARS=D:\Intel\oneAPI\setvars.bat"
if defined IDEVARS call "%IDEVARS%" >nul || exit /b 1
call "%~dp0buildenv.bat" || exit /b 1
echo trexida: SDK    = %IDASDK_SRC%
echo trexida: IDADIR = %IDADIR%
cmake -S "%~dp0.." -B "%~dp0..\build-icx" -G Ninja ^
  -DCMAKE_CXX_COMPILER=icx-cl -DCMAKE_BUILD_TYPE=Release ^
  -DIDA_SDK_DIR="%IDASDK_SRC%" -DIDA_SDK_SRC_DIR="%IDASDK_SRC%" ^
  -DIDA_INSTALL_DIR="%IDADIR%" || exit /b 1
cmake --build "%~dp0..\build-icx" || exit /b 1
endlocal

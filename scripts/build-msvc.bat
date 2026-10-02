@echo off
setlocal
rem Reference build with MSVC (used to isolate port bugs from compiler bugs).
rem Configure the SDK and IDA locations with the IDASDK / IDADIR environment variables; see
rem scripts\buildenv.bat. No machine-specific path is baked in here.
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" >nul || exit /b 1
call "%~dp0buildenv.bat" || exit /b 1
echo trexida: SDK    = %IDASDK_SRC%
echo trexida: IDADIR = %IDADIR%
cmake -S "%~dp0.." -B "%~dp0..\build-msvc" -G Ninja ^
  -DCMAKE_C_COMPILER=cl -DCMAKE_CXX_COMPILER=cl -DCMAKE_BUILD_TYPE=Release ^
  -DIDA_SDK_DIR="%IDASDK_SRC%" -DIDA_SDK_SRC_DIR="%IDASDK_SRC%" ^
  -DIDA_INSTALL_DIR="%IDADIR%" || exit /b 1
cmake --build "%~dp0..\build-msvc" || exit /b 1
endlocal

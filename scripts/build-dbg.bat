@echo off
rem Configure a RelWithDebInfo build (for debugging trex_unit_tests under cdb).
setlocal
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" >nul || exit /b 1
call "D:\Intel\oneAPI\setvars.bat" >nul || exit /b 1
cmake -S "%~dp0.." -B "%~dp0..\build-dbg" -G Ninja ^
  -DCMAKE_CXX_COMPILER=icx-cl -DCMAKE_BUILD_TYPE=RelWithDebInfo ^
  -DIDA_SDK_DIR="E:\tools\plugins\ida plug\ida-sdk\src" ^
  -DIDA_INSTALL_DIR="" || exit /b 1
cmake --build "%~dp0..\build-dbg" --target trex_unit_tests || exit /b 1
endlocal

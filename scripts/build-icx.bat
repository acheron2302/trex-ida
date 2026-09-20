@echo off
setlocal
rem Build trexida with the Intel oneAPI DPC++/C++ compiler (icx-cl, MSVC ABI).
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" >nul || exit /b 1
call "D:\Intel\oneAPI\setvars.bat" >nul || exit /b 1
cmake -S "%~dp0.." -B "%~dp0..\build-icx" -G Ninja ^
  -DCMAKE_CXX_COMPILER=icx-cl -DCMAKE_BUILD_TYPE=Release ^
  -DIDA_SDK_DIR="E:\tools\plugins\ida plug\ida-sdk\src" ^
  -DIDA_INSTALL_DIR="D:\tools\IDA 9.4" || exit /b 1
cmake --build "%~dp0..\build-icx" || exit /b 1
endlocal

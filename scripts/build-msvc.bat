@echo off
setlocal
rem Reference build with MSVC (used to isolate port bugs from compiler bugs).
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat" >nul || exit /b 1
cmake -S "%~dp0.." -B "%~dp0..\build-msvc" -G Ninja ^
  -DCMAKE_C_COMPILER=cl -DCMAKE_CXX_COMPILER=cl -DCMAKE_BUILD_TYPE=Release ^
  -DIDA_SDK_DIR="E:\tools\plugins\ida plug\ida-sdk\src" ^
  -DIDA_INSTALL_DIR="D:\tools\IDA 9.4" || exit /b 1
cmake --build "%~dp0..\build-msvc" || exit /b 1
endlocal

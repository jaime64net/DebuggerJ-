@echo off
REM Build con VS18 + Ninja dentro del entorno MSVC (invocado desde WSL via cmd.exe)
setlocal
set "VS=C:\Program Files\Microsoft Visual Studio\18\Community"
set "CMAKE=%VS%\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"
set "NINJA=%VS%\Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja\ninja.exe"

call "%VS%\VC\Auxiliary\Build\vcvars64.bat" || (echo vcvars FAILED & exit /b 1)

cd /d "C:\Discos\Proyectos\NEXCODE\DebuggerJ++"

"%CMAKE%" -S . -B build-ninja -G Ninja ^
  -DCMAKE_BUILD_TYPE=Release ^
  -DCMAKE_MAKE_PROGRAM="%NINJA%" ^
  -DCMAKE_C_COMPILER=cl -DCMAKE_CXX_COMPILER=cl
if errorlevel 1 (echo CONFIGURE FAILED & exit /b 1)

"%CMAKE%" --build build-ninja
if errorlevel 1 (echo BUILD FAILED & exit /b 1)

echo BUILD OK
endlocal

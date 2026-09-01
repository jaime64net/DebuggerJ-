@echo off
REM ==== Build de DebuggerJ++ (Windows / MSVC) ====
REM Requisitos: Visual Studio 2019/2022 con "Desktop development with C++",
REM             CMake 3.20+ y Git (para que FetchContent baje Zydis/ImGui/json).
REM Ejecutar desde un "x64 Native Tools Command Prompt for VS" o con VS en el PATH.

setlocal
cd /d "%~dp0"

if not exist build mkdir build
cmake -S . -B build -G "Visual Studio 17 2022" -A x64
if errorlevel 1 (
    echo.
    echo Fallo la configuracion de CMake. Prueba con -G "Visual Studio 16 2019" si usas VS2019.
    exit /b 1
)

cmake --build build --config Release
if errorlevel 1 (
    echo Fallo la compilacion.
    exit /b 1
)

echo.
echo ======================================================
echo  Listo:  build\Release\DebuggerJ++.exe
echo  Ejecutalo COMO ADMINISTRADOR para depurar procesos.
echo ======================================================
endlocal

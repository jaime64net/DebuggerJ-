cmake_minimum_required(VERSION 3.20)
project(DebuggerJpp LANGUAGES CXX RC)

# DebuggerJ++  -  Debugger / disassembler para analisis de malware (x86 / x64)
# Solo compila en Windows con MSVC: usa la Windows Debug API, DbgHelp, D3D11 y WinHTTP.

if(NOT WIN32)
    message(FATAL_ERROR "DebuggerJ++ solo compila en Windows (usa la Windows Debug API). Abre el proyecto en Visual Studio / MSVC.")
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(MSVC)
    add_compile_options(/W4 /permissive- /Zc:__cplusplus /utf-8 /MP)
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS NOMINMAX WIN32_LEAN_AND_MEAN UNICODE _UNICODE)
endif()

include(FetchContent)

# ---- Zydis (desensamblador x86/x64) ----
set(ZYDIS_BUILD_TOOLS   OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
FetchContent_Declare(zydis
    GIT_REPOSITORY https://github.com/zyantific/zydis.git
    GIT_TAG        v4.1.0
    GIT_SHALLOW    TRUE)
FetchContent_MakeAvailable(zydis)

# ---- nlohmann/json (para la API de Claude) ----
FetchContent_Declare(json
    GIT_REPOSITORY https://github.com/nlohmann/json.git
    GIT_TAG        v3.11.3
    GIT_SHALLOW    TRUE)
FetchContent_MakeAvailable(json)

# ---- Keystone (ensamblador x86/x64) : binario precompilado oficial ----
# (Keystone 0.9.2 no compila con CMake 4.x; usamos el .lib/.dll/headers precompilados.)
set(KEYSTONE_DIR ${CMAKE_SOURCE_DIR}/tools/keystone-win64/keystone-0.9.2-win64)

# ---- Dear ImGui (GUI) + backends Win32/DX11 ----
# Rama 'docking': habilita Docking (anclar ventanas) y Multi-Viewport (sacar ventanas
# a otros monitores). Necesario para el DockSpace del main y la ventana Contenedor.
FetchContent_Declare(imgui
    GIT_REPOSITORY https://github.com/ocornut/imgui.git
    GIT_TAG        docking
    GIT_SHALLOW    TRUE)
FetchContent_MakeAvailable(imgui)

add_library(imgui STATIC
    ${imgui_SOURCE_DIR}/imgui.cpp
    ${imgui_SOURCE_DIR}/imgui_draw.cpp
    ${imgui_SOURCE_DIR}/imgui_tables.cpp
    ${imgui_SOURCE_DIR}/imgui_widgets.cpp
    ${imgui_SOURCE_DIR}/imgui_demo.cpp
    ${imgui_SOURCE_DIR}/backends/imgui_impl_win32.cpp
    ${imgui_SOURCE_DIR}/backends/imgui_impl_dx11.cpp)
target_include_directories(imgui PUBLIC
    ${imgui_SOURCE_DIR}
    ${imgui_SOURCE_DIR}/backends)
target_link_libraries(imgui PUBLIC d3d11 dxgi d3dcompiler)

# ---- Ejecutable principal ----
file(GLOB_RECURSE APP_SOURCES CONFIGURE_DEPENDS
    ${CMAKE_SOURCE_DIR}/src/*.cpp
    ${CMAKE_SOURCE_DIR}/src/*.h)

# Recurso de icono (.rc -> icono del exe/ventana). Aseguramos que rc.exe encuentre
# el .ico anadiendo assets/ como include de recursos.
set(CMAKE_RC_FLAGS "${CMAKE_RC_FLAGS} /I \"${CMAKE_SOURCE_DIR}/assets\"")
add_executable(DebuggerJpp WIN32 ${APP_SOURCES} ${CMAKE_SOURCE_DIR}/assets/DebuggerJ++.rc)
target_include_directories(DebuggerJpp PRIVATE ${CMAKE_SOURCE_DIR}/src ${KEYSTONE_DIR}/include)
target_link_libraries(DebuggerJpp PRIVATE
    imgui
    Zydis
    ${KEYSTONE_DIR}/keystone_imp.lib
    nlohmann_json::nlohmann_json
    dbghelp     # simbolos
    winhttp     # cliente Claude API
    comdlg32    # dialogo abrir archivo
    psapi       # GetMappedFileName / modulos
    ws2_32      # servidor de control MCP
    iphlpapi    # conexiones TCP del proceso (panel System)
    bcrypt      # token criptografico de sesion MCP
    ntdll)

set_target_properties(DebuggerJpp PROPERTIES OUTPUT_NAME "DebuggerJ++")

# Copiar firmas de packers junto al binario
add_custom_command(TARGET DebuggerJpp POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_directory
        ${CMAKE_SOURCE_DIR}/signatures
        $<TARGET_FILE_DIR:DebuggerJpp>/signatures)

# Manifiestos de plugins declarativos disponibles junto al ejecutable.
add_custom_command(TARGET DebuggerJpp POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_directory
        ${CMAKE_SOURCE_DIR}/plugins
        $<TARGET_FILE_DIR:DebuggerJpp>/plugins)

add_custom_command(TARGET DebuggerJpp POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_directory
        ${CMAKE_SOURCE_DIR}/sdk
        $<TARGET_FILE_DIR:DebuggerJpp>/sdk)

# Skills de IA (seed) junto al binario
add_custom_command(TARGET DebuggerJpp POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_directory
        ${CMAKE_SOURCE_DIR}/skills
        $<TARGET_FILE_DIR:DebuggerJpp>/skills)

# keystone.dll junto al binario
add_custom_command(TARGET DebuggerJpp POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        ${KEYSTONE_DIR}/keystone.dll
        $<TARGET_FILE_DIR:DebuggerJpp>/keystone.dll)

# Artifacts: scripts Python de investigacion + index.md (browser Tools -> Artifacts)
if(EXISTS ${CMAKE_SOURCE_DIR}/artefacts)
    add_custom_command(TARGET DebuggerJpp POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_directory
            ${CMAKE_SOURCE_DIR}/artefacts
            $<TARGET_FILE_DIR:DebuggerJpp>/artefacts)
endif()

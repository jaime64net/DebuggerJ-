// DebuggerJ++ - punto de entrada. Crea la ventana Win32 + dispositivo D3D11
// e inicia el bucle de ImGui que dibuja la App.

#include <windows.h>
#include <d3d11.h>
#include <tchar.h>
#include <cstdlib>
#include <crtdbg.h>
#include <memory>

#include "imgui.h"
#include "imgui_impl_win32.h"
#include "imgui_impl_dx11.h"

#include "gui/App.h"

static ID3D11Device*           g_pd3dDevice = nullptr;
static ID3D11DeviceContext*    g_pd3dDeviceContext = nullptr;
static IDXGISwapChain*         g_pSwapChain = nullptr;
static ID3D11RenderTargetView* g_mainRTV = nullptr;

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND, UINT, WPARAM, LPARAM);

static void CreateRenderTarget() {
    ID3D11Texture2D* pBack = nullptr;
    g_pSwapChain->GetBuffer(0, IID_PPV_ARGS(&pBack));
    if (pBack) { g_pd3dDevice->CreateRenderTargetView(pBack, nullptr, &g_mainRTV); pBack->Release(); }
}
static void CleanupRenderTarget() { if (g_mainRTV) { g_mainRTV->Release(); g_mainRTV = nullptr; } }

static bool CreateDeviceD3D(HWND hWnd) {
    DXGI_SWAP_CHAIN_DESC sd{};
    sd.BufferCount = 2;
    sd.BufferDesc.Width = 0; sd.BufferDesc.Height = 0;
    sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.BufferDesc.RefreshRate.Numerator = 60; sd.BufferDesc.RefreshRate.Denominator = 1;
    sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.OutputWindow = hWnd; sd.SampleDesc.Count = 1; sd.Windowed = TRUE;
    sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

    UINT flags = 0;
    D3D_FEATURE_LEVEL fl; const D3D_FEATURE_LEVEL levels[] = { D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0 };
    if (D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, flags, levels, 2,
            D3D11_SDK_VERSION, &sd, &g_pSwapChain, &g_pd3dDevice, &fl, &g_pd3dDeviceContext) != S_OK)
        return false;
    CreateRenderTarget();
    return true;
}
static void CleanupDeviceD3D() {
    CleanupRenderTarget();
    if (g_pSwapChain) { g_pSwapChain->Release(); g_pSwapChain = nullptr; }
    if (g_pd3dDeviceContext) { g_pd3dDeviceContext->Release(); g_pd3dDeviceContext = nullptr; }
    if (g_pd3dDevice) { g_pd3dDevice->Release(); g_pd3dDevice = nullptr; }
}

static LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam)) return true;
    switch (msg) {
    case WM_SIZE:
        if (g_pd3dDevice != nullptr && wParam != SIZE_MINIMIZED) {
            CleanupRenderTarget();
            g_pSwapChain->ResizeBuffers(0, (UINT)LOWORD(lParam), (UINT)HIWORD(lParam), DXGI_FORMAT_UNKNOWN, 0);
            CreateRenderTarget();
        }
        return 0;
    case WM_DESTROY: PostQuitMessage(0); return 0;
    }
    return DefWindowProcW(hWnd, msg, wParam, lParam);
}

// Handler de parametro invalido del CRT: por defecto ucrtbase llama __fastfail
// (0xC0000409) y aborta el proceso ante un parametro invalido (p.ej. algun printf/
// conversion sensible al locale/timing). Con un handler propio la ejecucion continua
// en vez de abortar, evitando el crash intermitente de arranque.
static void crtInvalidParam(const wchar_t*, const wchar_t*, const wchar_t*, unsigned int, uintptr_t) {}

int APIENTRY wWinMain(HINSTANCE hInst, HINSTANCE, LPWSTR, int) {
    _set_invalid_parameter_handler(crtInvalidParam);
#ifdef _DEBUG
    _CrtSetReportMode(_CRT_ASSERT, 0);
#endif
    WNDCLASSEXW wc = { sizeof(wc), CS_CLASSDC, WndProc, 0, 0, hInst, nullptr, nullptr, nullptr, nullptr,
                       L"DebuggerJpp", nullptr };
    RegisterClassExW(&wc);
    HWND hwnd = CreateWindowW(wc.lpszClassName, L"DebuggerJ++  -  analisis de malware (x86/x64)",
                              WS_OVERLAPPEDWINDOW, 60, 40, 1500, 950,
                              nullptr, nullptr, wc.hInstance, nullptr);

    if (!CreateDeviceD3D(hwnd)) { CleanupDeviceD3D(); UnregisterClassW(wc.lpszClassName, wc.hInstance); return 1; }

    // M10: modo headless. --headless oculta la ventana (el MCP y el motor siguen
    // corriendo) para automatizacion/batch dirigido por MCP.
    bool headless = std::wstring(GetCommandLineW()).find(L"--headless") != std::wstring::npos;
    ShowWindow(hwnd, headless ? SW_HIDE : SW_SHOWDEFAULT);
    UpdateWindow(hwnd);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
    io.ConfigFlags |= ImGuiConfigFlags_DockingEnable;    // anclar ventanas dentro del main/contenedor
    // Multi-viewport ON por defecto: necesario para que el platform interface se inicialice
    // y las ventanas (p.ej. el Contenedor) puedan SALIR del main a otros monitores. Si en
    // alguna GPU/driver la interfaz parpadea, se apaga en caliente (Window -> Multi-monitor)
    // o se arranca con --no-viewports.
    if (std::wstring(GetCommandLineW()).find(L"--no-viewports") == std::wstring::npos) {
        io.ConfigFlags |= ImGuiConfigFlags_ViewportsEnable;
        io.ConfigViewportsNoAutoMerge = false;
    }
    ImGui::StyleColorsDark();
    if (io.ConfigFlags & ImGuiConfigFlags_ViewportsEnable) {
        ImGuiStyle& style = ImGui::GetStyle();
        style.WindowRounding = 0.0f;
        style.Colors[ImGuiCol_WindowBg].w = 1.0f;
    }
    ImGui_ImplWin32_Init(hwnd);
    ImGui_ImplDX11_Init(g_pd3dDevice, g_pd3dDeviceContext);

    // Construccion defensiva: si algun load del constructor lanza, se reintenta una vez
    // (una excepcion no capturada aqui llamaria std::terminate -> abort).
    std::unique_ptr<dbg::App> appPtr;
    for (int attempt = 0; attempt < 3 && !appPtr; ++attempt) {
        try { appPtr = std::make_unique<dbg::App>(); }
        catch (...) { appPtr.reset(); }
    }
    if (!appPtr) { CleanupDeviceD3D(); UnregisterClassW(wc.lpszClassName, wc.hInstance); return 1; }
    dbg::App& app = *appPtr;

    // Arranque opcional del MCP por linea de comandos: --mcp [--bindall] [--port=NNNN]
    // Se DIFIERE al segundo frame: arrancar el hilo de red concurrentemente con la
    // inicializacion de D3D/ImGui provocaba un crash intermitente en el arranque.
    bool wantMcp = false; int mcpPort = 8377; bool mcpBindAll = false;
    {
        std::wstring cl = GetCommandLineW();
        if (cl.find(L"--mcp") != std::wstring::npos) {
            wantMcp = true;
            mcpBindAll = cl.find(L"--bindall") != std::wstring::npos;
            auto p = cl.find(L"--port=");
            if (p != std::wstring::npos) mcpPort = _wtoi(cl.c_str() + p + 7);
            if (cl.find(L"--noauth") != std::wstring::npos) app.cliSetNoAuth(true);
            auto ap = cl.find(L"--access=");
            if (ap != std::wstring::npos) app.cliSetAccess(_wtoi(cl.c_str() + ap + 9));
        }
    }
    int frameCount = 0;

    bool done = false;
    while (!done) {
        MSG msg;
        while (PeekMessage(&msg, nullptr, 0U, 0U, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
            if (msg.message == WM_QUIT) done = true;
        }
        if (done) break;

        ImGui_ImplDX11_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();

        try {
            app.render();
            // Arranque diferido del MCP: tras un par de frames, ya inicializado todo.
            if (wantMcp && ++frameCount == 2) { app.cliStartMcp(mcpPort, mcpBindAll); wantMcp = false; }
        } catch (...) {
            // Una excepcion dentro de un panel no debe tumbar la app; se ignora este frame.
        }

        ImGui::Render();
        const float clear[4] = { 0.09f, 0.09f, 0.11f, 1.0f };
        g_pd3dDeviceContext->OMSetRenderTargets(1, &g_mainRTV, nullptr);
        g_pd3dDeviceContext->ClearRenderTargetView(g_mainRTV, clear);
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());

        // Multi-viewport: dibuja y presenta las ventanas que salieron a otros monitores.
        if (io.ConfigFlags & ImGuiConfigFlags_ViewportsEnable) {
            ImGui::UpdatePlatformWindows();
            ImGui::RenderPlatformWindowsDefault();
        }

        g_pSwapChain->Present(1, 0);
    }

    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();
    CleanupDeviceD3D();
    DestroyWindow(hwnd);
    UnregisterClassW(wc.lpszClassName, wc.hInstance);
    return 0;
}

// DebuggerJ++ - punto de entrada. Crea la ventana principal Win32 + D3D11 y, aparte, una
// segunda ventana NATIVA "Contenedor" con su propio contexto ImGui y swapchain (para llevar
// paneles a otro monitor sin el parpadeo del multi-viewport de ImGui).

#include <windows.h>
#include <d3d11.h>
#include <dxgi.h>
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

// Ventana Contenedor (segunda ventana nativa)
static HWND                    g_contHwnd = nullptr;
static IDXGISwapChain*         g_contSwap = nullptr;
static ID3D11RenderTargetView* g_contRTV = nullptr;
static ImGuiContext*           g_mainCtx = nullptr;
static ImGuiContext*           g_contCtx = nullptr;
static dbg::App*               g_app = nullptr;

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND, UINT, WPARAM, LPARAM);

static void CreateMainRTV() {
    ID3D11Texture2D* pBack = nullptr;
    g_pSwapChain->GetBuffer(0, IID_PPV_ARGS(&pBack));
    if (pBack) { g_pd3dDevice->CreateRenderTargetView(pBack, nullptr, &g_mainRTV); pBack->Release(); }
}
static void CleanupMainRTV() { if (g_mainRTV) { g_mainRTV->Release(); g_mainRTV = nullptr; } }
static void CreateContRTV() {
    if (!g_contSwap) return;
    ID3D11Texture2D* pBack = nullptr;
    g_contSwap->GetBuffer(0, IID_PPV_ARGS(&pBack));
    if (pBack) { g_pd3dDevice->CreateRenderTargetView(pBack, nullptr, &g_contRTV); pBack->Release(); }
}
static void CleanupContRTV() { if (g_contRTV) { g_contRTV->Release(); g_contRTV = nullptr; } }

static bool CreateDeviceD3D(HWND hWnd) {
    DXGI_SWAP_CHAIN_DESC sd{};
    sd.BufferCount = 2;
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
    CreateMainRTV();
    return true;
}

// Crea el swapchain de la ventana Contenedor sobre el mismo dispositivo D3D.
static bool CreateContSwapchain(HWND hWnd) {
    IDXGIDevice* dxgiDev = nullptr; IDXGIAdapter* adapter = nullptr; IDXGIFactory* factory = nullptr;
    if (FAILED(g_pd3dDevice->QueryInterface(IID_PPV_ARGS(&dxgiDev)))) return false;
    dxgiDev->GetAdapter(&adapter);
    if (adapter) adapter->GetParent(IID_PPV_ARGS(&factory));
    bool ok = false;
    if (factory) {
        DXGI_SWAP_CHAIN_DESC sd{};
        sd.BufferCount = 2;
        sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
        sd.BufferDesc.RefreshRate.Numerator = 60; sd.BufferDesc.RefreshRate.Denominator = 1;
        sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
        sd.OutputWindow = hWnd; sd.SampleDesc.Count = 1; sd.Windowed = TRUE;
        sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;
        ok = SUCCEEDED(factory->CreateSwapChain(g_pd3dDevice, &sd, &g_contSwap));
        if (ok) CreateContRTV();
    }
    if (factory) factory->Release();
    if (adapter) adapter->Release();
    if (dxgiDev) dxgiDev->Release();
    return ok;
}

static void CleanupDeviceD3D() {
    CleanupContRTV(); if (g_contSwap) { g_contSwap->Release(); g_contSwap = nullptr; }
    CleanupMainRTV();
    if (g_pSwapChain) { g_pSwapChain->Release(); g_pSwapChain = nullptr; }
    if (g_pd3dDeviceContext) { g_pd3dDeviceContext->Release(); g_pd3dDeviceContext = nullptr; }
    if (g_pd3dDevice) { g_pd3dDevice->Release(); g_pd3dDevice = nullptr; }
}

// WndProc compartido: rutea cada mensaje al contexto ImGui de su ventana.
static LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    const bool isCont = (g_contHwnd && hWnd == g_contHwnd);
    ImGuiContext* ctx = isCont ? g_contCtx : g_mainCtx;
    ImGuiContext* prev = ImGui::GetCurrentContext();
    if (ctx) ImGui::SetCurrentContext(ctx);
    bool handled = (ctx && ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam));
    LRESULT r = 0; bool ret = handled;
    if (!handled) {
        switch (msg) {
        case WM_SIZE:
            if (wParam != SIZE_MINIMIZED) {
                if (isCont) {
                    if (g_contSwap) { CleanupContRTV(); g_contSwap->ResizeBuffers(0,(UINT)LOWORD(lParam),(UINT)HIWORD(lParam),DXGI_FORMAT_UNKNOWN,0); CreateContRTV(); }
                } else if (g_pd3dDevice) {
                    CleanupMainRTV(); g_pSwapChain->ResizeBuffers(0,(UINT)LOWORD(lParam),(UINT)HIWORD(lParam),DXGI_FORMAT_UNKNOWN,0); CreateMainRTV();
                }
            }
            ret = true; break;
        case WM_CLOSE:
            if (isCont) { ShowWindow(g_contHwnd, SW_HIDE); if (g_app) g_app->setContainerOpen(false); ret = true; break; }
            r = DefWindowProcW(hWnd, msg, wParam, lParam); break;
        case WM_DESTROY:
            if (!isCont) { PostQuitMessage(0); ret = true; break; }
            r = DefWindowProcW(hWnd, msg, wParam, lParam); break;
        default:
            r = DefWindowProcW(hWnd, msg, wParam, lParam); break;
        }
    }
    if (prev) ImGui::SetCurrentContext(prev);
    return ret ? (handled ? true : r) : r;
}

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

    bool headless = std::wstring(GetCommandLineW()).find(L"--headless") != std::wstring::npos;
    ShowWindow(hwnd, headless ? SW_HIDE : SW_SHOWDEFAULT);
    UpdateWindow(hwnd);

    IMGUI_CHECKVERSION();
    // Contexto principal (docking, SIN viewports: la ventana Contenedor es nativa).
    g_mainCtx = ImGui::CreateContext();
    ImGui::SetCurrentContext(g_mainCtx);
    ImGuiIO& io = ImGui::GetIO();
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
    io.ConfigFlags |= ImGuiConfigFlags_DockingEnable;
    ImGui::StyleColorsDark();
    ImGui_ImplWin32_Init(hwnd);
    ImGui_ImplDX11_Init(g_pd3dDevice, g_pd3dDeviceContext);

    // Ventana Contenedor nativa (oculta hasta que el usuario la abra) + su contexto ImGui.
    g_contHwnd = CreateWindowW(wc.lpszClassName, L"DebuggerJ++  -  Contenedor",
                               WS_OVERLAPPEDWINDOW, 120, 80, 900, 700,
                               nullptr, nullptr, wc.hInstance, nullptr);
    if (g_contHwnd && CreateContSwapchain(g_contHwnd)) {
        g_contCtx = ImGui::CreateContext();
        ImGui::SetCurrentContext(g_contCtx);
        ImGuiIO& io2 = ImGui::GetIO();
        io2.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
        io2.ConfigFlags |= ImGuiConfigFlags_DockingEnable;
        io2.IniFilename = "imgui_container.ini";
        ImGui::StyleColorsDark();
        ImGui_ImplWin32_Init(g_contHwnd);
        ImGui_ImplDX11_Init(g_pd3dDevice, g_pd3dDeviceContext);
    }
    ImGui::SetCurrentContext(g_mainCtx);

    std::unique_ptr<dbg::App> appPtr;
    for (int attempt = 0; attempt < 3 && !appPtr; ++attempt) {
        try { appPtr = std::make_unique<dbg::App>(); }
        catch (...) { appPtr.reset(); }
    }
    if (!appPtr) { CleanupDeviceD3D(); UnregisterClassW(wc.lpszClassName, wc.hInstance); return 1; }
    dbg::App& app = *appPtr; g_app = &app;
    app.setContainerHandles(g_contCtx, g_contHwnd);   // para guardar/cargar layouts del Contenedor

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

        // Rects de ambas ventanas (coords de pantalla) para el drag & drop entre ellas.
        { RECT rc; if (GetWindowRect(hwnd, &rc)) app.setMainScreenRect(rc.left, rc.top, rc.right-rc.left, rc.bottom-rc.top); }
        { RECT rc; bool ok = g_contHwnd && app.containerOpen() && IsWindowVisible(g_contHwnd) && GetWindowRect(g_contHwnd, &rc);
          app.setContainerScreenRect(ok?rc.left:0, ok?rc.top:0, ok?(rc.right-rc.left):0, ok?(rc.bottom-rc.top):0, ok); }

        // --- Ventana principal ---
        ImGui::SetCurrentContext(g_mainCtx);
        ImGui_ImplDX11_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();
        try {
            app.render();
            if (wantMcp && ++frameCount == 2) { app.cliStartMcp(mcpPort, mcpBindAll); wantMcp = false; }
        } catch (...) {}
        ImGui::Render();
        const float clear[4] = { 0.09f, 0.09f, 0.11f, 1.0f };
        g_pd3dDeviceContext->OMSetRenderTargets(1, &g_mainRTV, nullptr);
        g_pd3dDeviceContext->ClearRenderTargetView(g_mainRTV, clear);
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
        g_pSwapChain->Present(app.vsyncInterval(), 0);

        // Reposicionar la ventana del Contenedor si un layout aplicado lo pidio.
        { int rx,ry,rw,rh; if (g_contHwnd && app.consumeContWinMove(rx,ry,rw,rh))
            SetWindowPos(g_contHwnd, nullptr, rx, ry, rw, rh, SWP_NOZORDER | SWP_NOACTIVATE); }

        // --- Ventana Contenedor (segundo contexto) ---
        if (g_contCtx) {
            bool wantOpen = app.containerOpen();
            if (wantOpen && !IsWindowVisible(g_contHwnd)) { ShowWindow(g_contHwnd, SW_SHOW); UpdateWindow(g_contHwnd); }
            if (!wantOpen && IsWindowVisible(g_contHwnd)) ShowWindow(g_contHwnd, SW_HIDE);
            if (wantOpen && g_contRTV) {
                ImGui::SetCurrentContext(g_contCtx);
                ImGui_ImplDX11_NewFrame();
                ImGui_ImplWin32_NewFrame();
                ImGui::NewFrame();
                try { app.renderContainer(); } catch (...) {}
                ImGui::Render();
                g_pd3dDeviceContext->OMSetRenderTargets(1, &g_contRTV, nullptr);
                g_pd3dDeviceContext->ClearRenderTargetView(g_contRTV, clear);
                ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
                g_contSwap->Present(app.vsyncInterval(), 0);
            }
        }
    }

    if (g_contCtx) {
        ImGui::SetCurrentContext(g_contCtx);
        ImGui_ImplDX11_Shutdown();
        ImGui_ImplWin32_Shutdown();
        ImGui::DestroyContext(g_contCtx);
    }
    ImGui::SetCurrentContext(g_mainCtx);
    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext(g_mainCtx);
    CleanupDeviceD3D();
    if (g_contHwnd) DestroyWindow(g_contHwnd);
    DestroyWindow(hwnd);
    UnregisterClassW(wc.lpszClassName, wc.hInstance);
    return 0;
}

#pragma once
#include <deque>
#include <future>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "core/PeFile.h"
#include "core/Disassembler.h"
#include "core/Debugger.h"
#include "core/PackerDetect.h"
#include "core/StringScan.h"
#include "core/Unpack.h"
#include "net/ControlServer.h"
#include "ai/AiClient.h"
#include "ai/AiConfig.h"

// Orquestador de la interfaz. Mantiene el estado y dibuja todos los paneles ImGui.

namespace dbg {

struct WinGeom { std::string name; float x=0, y=0, w=0, h=0; };
struct WinLayout { std::string name; std::vector<WinGeom> wins; };

class App {
public:
    App();
    ~App();

    void render();   // se llama cada frame
    void cliStartMcp(int port, bool bindAll); // arranca el MCP desde linea de comandos

private:
    // --- Acciones ---
    void openFile(const std::wstring& path);
    void refreshDisassembly();      // desde el archivo estatico
    void refreshLiveDisassembly(uint64_t around); // desde memoria del proceso
    void refreshStaticStrings();
    void runPackerScan();
    void startDebugSession();
    void sendAiMessage();
    void pushLog(const std::string& s);

    // --- Paneles ---
    void drawMenuBar();
    void drawToolbar();
    void drawCpuPanel();          // ventana CPU compuesta estilo Olly
    void drawCpuContent();        // solo el desensamblado
    void drawRegistersContent();
    void drawBreakpointsPanel();
    void drawMemoryPanel();
    void drawHexDumpContent();
    void drawStackContent();
    void drawStringsPanel();
    void drawReferencesPanel();
    void drawTracePanel();
    void findReferences(uint64_t addr);
    void loadAnnotations();
    void saveAnnotations();
    void drawModulesPanel();
    void drawPackerPanel();
    void drawExceptionsPanel();
    void drawExecModulesPanel();   // "Executable modules" estilo Olly
    void drawCallStackPanel();     // Call stack (cadena de frames)
    void drawPluginsPanel();
    void drawLogPanel();
    void drawAiPanel();
    void drawCodePanel();
    void drawOptionsWindow();      // Tools -> Options (configuracion de agentes de IA)
    void drawStatusBar();          // barra de estado inferior (Running/Paused)

    // --- MCP / control remoto ---
    std::string handleMcpCommand(const std::string& line); // corre en hilo UI
    std::string execDbgCommand(const std::string& line);   // encola y espera (hilo trabajador)
    std::vector<ToolDef> aiToolDefs();                      // catalogo de tools dbg_* para la IA
    void        drainMcpQueue();
    void        startMcp();
    void        stopMcp();
    void        drawMcpLogPanel();

    void gotoAddress(uint64_t va);   // navega el CPU a una VA
    std::string moduleNameAt(uint64_t va);  // modulo que contiene una VA

    // --- Gestion de ventanas ---
    void drawWindowMenu();           // menu "Window"
    void drawAddCustomPopup();       // modal para nombrar un layout
    void arrangeWindows();           // mosaico sin solapamiento
    void captureLayout(const std::string& name);
    void applyLayout(const WinLayout& L);
    void loadLayouts();
    void saveLayouts();
    static std::vector<const char*> managedWindows();

    // Visibilidad de ventanas (submenu Show, persistente)
    bool visible(const char* name);
    void ensureVisibilityKeys();
    void loadVisibility();
    void saveVisibility();

    std::string aiContextSnapshot(); // arma el contexto (regs + desensamblado) para la IA
    void sendCodeRequest();

    // --- Estado del binario / desensamblado ---
    PeFile        pe_;
    Disassembler  dis_{true};
    std::vector<Instruction> insns_;
    std::wstring  loadedPath_;
    std::string   openError_;
    bool          fileLoaded_ = false;
    int           selectedInsn_ = -1;
    int           pendingScroll_ = -1; // indice de instruccion al que hay que desplazar
    uint64_t      disBase_ = 0;      // VA base del listado actual
    bool          liveView_ = false; // true = desensamblando memoria viva

    // --- Excepciones (add manual) ---
    char          excCodeBuf_[24] = "C0000005";
    char          excAddrBuf_[24] = {0};
    char          excLabelBuf_[64] = {0};

    // --- Debugger ---
    Debugger      debugger_;
    DbgState      dbgState_ = DbgState::Idle;
    uint64_t      currentIp_ = 0;
    std::string   curModule_;   // modulo del RIP actual (para el titulo del CPU)
    Registers     regs_;
    char          regEditName_[8] = {0};   // registro en edicion (minusculas)
    char          regEditBuf_[24] = {0};
    bool          openRegEdit_ = false;
    void          applyRegEdit(const char* name, uint64_t value);

    // --- Packers ---
    PackerDetect  packer_;
    std::vector<PackerMatch> packerMatches_;
    bool          packerLoaded_ = false;

    // --- Strings / hex ---
    std::vector<FoundString> strings_;
    char          strFilter_[128] = {0};
    char          hexPattern_[128] = {0};
    char          textNeedle_[128] = {0};
    bool          searchUtf16_ = true;
    std::vector<uint64_t> searchHits_;
    std::string   searchStatus_;
    size_t        minStrLen_ = 4;

    // --- Memoria (hex dump) ---
    char          memGotoBuf_[32] = {0};
    uint64_t      memBase_ = 0;
    std::vector<uint8_t> memBuf_;
    std::vector<MemRegion> memMap_;

    // --- Volcado Hex dedicado ---
    char          dumpGotoBuf_[32] = {0};
    uint64_t      dumpBase_ = 0;
    std::vector<uint8_t> dumpBuf_;

    // --- Anotaciones (comentarios/etiquetas) ---
    std::map<uint64_t, std::string> comments_;
    std::map<uint64_t, std::string> labels_;
    char          annotBuf_[256] = {0};
    uint64_t      annotAddr_ = 0;
    bool          annotIsLabel_ = false;
    bool          openAnnot_ = false;

    // --- Referencias ---
    std::vector<uint64_t> refs_;
    uint64_t      refTarget_ = 0;

    // --- Ensamblador / patch ---
    char          asmBuf_[128] = {0};
    uint64_t      asmAddr_ = 0;
    bool          openAsm_ = false;      // patch por bytes
    bool          openAsmText_ = false;  // ensamblar texto (Keystone)
    std::string   asmError_;

    // --- IA ---
    AiClient      ai_;
    AiConfigStore aiConfig_;
    std::vector<ChatMessage> chat_;
    char          aiInput_[4096] = {0};
    bool          aiBusy_ = false;
    std::string   aiError_;
    std::mutex    aiMutex_;
    std::thread   aiThread_;
    bool          aiIncludeContext_ = true;
    bool          aiAgentMode_ = false;    // dejar que la IA controle el debugger (tools)

    // --- Code: pseudocodigo C++ generado por el agente para una rutina ---
    char          codeAddr_[32] = {0};
    char          codeInput_[2048] = "Interpreta el procedimiento como pseudocodigo C++ claro, con comentarios sobre llamadas API y efectos laterales.";
    std::string   codeOutput_;

    // --- Options (Tools -> Options) ---
    bool          showOptions_ = false;
    int           optEditIdx_ = -1;        // agente en edicion (-1 = ninguno)
    int           optPresetIdx_ = -1;      // preset elegido en el formulario
    AiAgent       optDraft_;               // copia de trabajo del formulario
    char          optName_[64]   = {0};
    char          optHost_[128]  = {0};
    char          optPath_[128]  = {0};
    char          optKey_[256]   = {0};
    char          optModel_[128] = {0};
    int           optPort_ = 443;
    std::string   optStatus_;              // mensaje de guardado/validacion
    void          optLoadDraft(int idx);   // llena el formulario desde agents()[idx]
    void          optApplyPreset(int presetIdx);

    // --- Log ---
    std::mutex    logMutex_;
    std::deque<std::string> log_;

    // --- args de lanzamiento ---
    char          launchArgs_[512] = {0};

    // --- plugins (unpacking) ---
    AntiDbgOptions antiOpt_;
    bool           antiReapply_ = false;   // re-aplicar en cada pausa
    bool           antiActive_ = false;
    uint64_t       pluginOEP_ = 0;
    std::wstring   lastDumpPath_;
    std::string    pluginStatus_;

    // --- MCP ---
    ControlServer mcp_;
    int           mcpPort_ = 8377;
    bool          mcpBindAll_ = false;
    std::string   mcpStatus_;
    struct McpReq { std::string req; std::promise<std::string> resp; };
    std::mutex    mcpMutex_;
    std::deque<McpReq*> mcpQueue_;
    std::mutex    mcpLogMutex_;
    std::deque<std::string> mcpLog_;

    // --- layouts de ventanas ---
    std::vector<WinLayout> customLayouts_;
    std::map<std::string, bool> winVisible_;   // nombre -> visible
    bool          openAddCustom_ = false;
    char          newLayoutName_[64] = {0};
    float         toolbarHeight_ = 44.0f;
};

} // namespace dbg

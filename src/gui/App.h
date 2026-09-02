#pragma once
#include <deque>
#include <future>
#include <map>
#include <set>
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
#include "core/ExprEval.h"
#include "net/ControlServer.h"
#include "plugins/PluginManager.h"
#include "ai/AiClient.h"
#include "ai/AiConfig.h"

// Orquestador de la interfaz. Mantiene el estado y dibuja todos los paneles ImGui.

namespace dbg {

struct WinGeom { std::string name; float x=0, y=0, w=0, h=0; };
struct WinLayout { std::string name; std::vector<WinGeom> wins; };
struct AnalyzedFunction { uint64_t start=0, end=0; uint32_t instructions=0, calls=0, branches=0; std::string name; };
struct AnalysisXref { uint64_t from=0, to=0; std::string type; };
struct AnalysisLoop { uint64_t start=0, end=0, function=0; };

class App {
public:
    App();
    ~App();

    void render();          // dibuja la ventana principal (contexto main)
    void renderContainer(); // dibuja la ventana Contenedor nativa (segundo contexto/monitor)
    bool containerOpen() const { return containerOpen_; }
    void setContainerOpen(bool v) { containerOpen_ = v; saveContainerState(); }
    void setContainerScreenRect(int x, int y, int w, int h, bool valid);  // desde main.cpp
    void setMainScreenRect(int x, int y, int w, int h);                    // desde main.cpp
    int  vsyncInterval() const { return vsyncOn_ ? 1 : 0; }  // sync interval para Present
    void cliStartMcp(int port, bool bindAll); // arranca el MCP desde linea de comandos
    void cliSetNoAuth(bool on);               // --noauth: bypass del token (antes de cliStartMcp)
    void cliSetAccess(int level);             // --access=N: nivel MCP (0/1/2) antes de cliStartMcp

private:
    // --- Acciones ---
    void openFile(const std::wstring& path);
    void addRecent(const std::wstring& path);  // registra un archivo en la lista de recientes
    void loadRecent();
    void saveRecent();
    void refreshDisassembly();      // desde el archivo estatico
    void refreshLiveDisassembly(uint64_t around); // desde memoria del proceso
    void refreshStaticStrings();
    void runPackerScan();
    void startDebugSession();
    void attachToProcess(uint32_t pid);
    void switchToChild(uint32_t pid);        // conmuta el target: detach del actual -> attach al hijo
    uint32_t pendingSwitchPid_ = 0;          // attach pendiente tras el detach (conmutacion)
    void runToAddress(uint64_t va);          // ejecuta hasta una direccion (BP temporal + go)
    std::set<uint64_t> runToTemp_;           // BPs temporales de run-to que se quitan al golpear
    // Run until expression / trace condicional (paridad x64dbg): single-step evaluando
    // una expresion en cada paso; para cuando la expresion es != 0 o se alcanza el tope.
    bool          runUntilActive_ = false;
    std::string   runUntilExpr_;
    int           runUntilMode_ = 0;         // 0 = step into, 1 = step over
    int           runUntilCount_ = 0;
    int           runUntilMax_ = 100000;
    void          startRunUntil(const std::string& expr, int mode, int maxSteps);
    void          tickRunUntil();            // llamado al pausar; hace el siguiente paso o para
    // Animate (step animado), skip y undo (paridad x64dbg)
    bool          animateActive_ = false;
    int           animateMode_ = 0;          // 0 = into, 1 = over
    int           animateFrame_ = 0;
    void          skipInstruction();         // avanza RIP/EIP sin ejecutar la instruccion
    void          undoInstruction();         // restaura los registros previos al ultimo paso
    Registers     regsBeforeStep_;
    bool          haveRegsBefore_ = false;
    bool saveSession(const std::wstring& path, std::string& error);
    bool loadSession(const std::wstring& path, std::string& error);
    std::string buildAnalysisReport();
    std::string buildAnalysisReportJson();          // informe estructurado (JSON/SARIF-friendly)
    std::string buildSarifReport();                 // SARIF 2.1.0 (hallazgos como results)
    bool saveSarifReport(const std::wstring& path, std::string& error);
    std::string runScript(const std::string& src, std::string& err);  // mini-lenguaje de scripts
    bool validateDump(const std::wstring& path, std::string& report); // validación PE del dump (unpacking)
    bool saveAnalysisReport(const std::wstring& path, std::string& error);
    bool saveAnalysisReportJson(const std::wstring& path, std::string& error);
    std::string peContentHash();                     // hash del contenido del PE (M6: DB por hash)

    // --- Bus de eventos / streaming (Fase 3) ---
    struct EventRec { uint64_t seq = 0; std::string type; uint64_t arg = 0; };
    void pushEvent(const std::string& type, uint64_t arg);

    // --- CFG interactivo (bloques básicos) ---
    void drawCfgPanel();
    struct BasicBlock { uint64_t start=0, end=0; std::vector<int> insnIdx; std::vector<uint64_t> succ; };
    std::vector<BasicBlock> computeBasicBlocks(uint64_t funcStart, uint64_t funcEnd);
    uint64_t cfgFunc_ = 0;                 // función cuyo CFG se muestra
    float    cfgZoom_ = 1.0f;
    float    cfgPanX_ = 0, cfgPanY_ = 0;
    // --- Comparación de dumps ---
    void drawComparePanel();
    // --- Struct inferido por IA (M8+) ---
    void inferStructWithAi();
    // --- Scripting ---
    void drawScriptPanel();
    char scriptBuf_[8192] = {0};
    std::string scriptOutput_;
    void saveSessionDialog();
    void loadSessionDialog();
    void exportReportDialog();
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
    void drawAnalysisPanel();
    void drawSearchResultsPanel();          // resultados de "Search for" (estilo Olly)
    void searchAllCommands(const std::string& needle);
    void searchIntermodularCalls();
    void searchBinaryString(const std::string& pattern, bool isHex, bool utf16);

    // --- Motor de expresiones (Fase 2) ---
    bool evalExpr(const std::string& expr, uint64_t& out, std::string& err);
    EvalContext makeEvalContext();          // arma los callbacks contra el estado actual

    // --- Command bar hibrida (M1) ---
    void drawCommandBar();
    void execCommandBar();

    // --- Watch (M2) ---
    void drawWatchPanel();
    void refreshWatches();                  // reevalua las expresiones (en cada pausa)

    // --- Trace + IA (M4) ---
    void summarizeTraceWithAi();

    // --- Struct viewer (M8) ---
    void drawStructPanel();

    // --- Breakpoints inteligentes (M3): accion al golpear ---
    void runBreakpointAction(uint64_t addr);   // ejecuta la accion asociada a una VA
    void drawTracePanel();
    void findReferences(uint64_t addr);
    void loadAnnotations();
    void saveAnnotations();
    bool loadAnalysisCache();
    void saveAnalysisCache();
    void drawModulesPanel();
    void drawPackerPanel();
    void drawExceptionsPanel();
    void drawExecModulesPanel();   // "Executable modules" estilo Olly
    void drawCallStackPanel();     // Call stack (cadena de frames)
    void drawThreadsPanel();       // hilos del proceso depurado
    void drawNotesPanel();         // notas globales + por-binario (paridad x64dbg)
    void drawSystemPanel();        // privilegios, conexiones TCP y handles del proceso
    void drawEntropyPanel();       // entropía por sección con barras (diálogo de entropía)
    void  buildDefaultDock(unsigned int dockspaceId);   // layout de docking inicial ordenado
    bool  dockNeedsInit_ = false;  // construir el layout por defecto una vez
    // Ventana Contenedor nativa (segunda ventana OS, sin multi-viewport de ImGui):
    bool  containerOpen_ = false;                       // ventana Contenedor visible
    std::map<std::string, bool> winContainer_;          // panel -> se dibuja en el Contenedor
    bool  containerDockInit_ = false;
    bool  showInMain(const char* name);                 // visible y NO asignado al Contenedor
    bool  showInContainer(const char* name);            // visible y asignado al Contenedor
    void  drawManagedPanel(const char* name);           // despacha a drawXPanel por nombre
    void  loadContainerState();
    void  saveContainerState();
    // Arrastrar una ventana del main y soltarla sobre la ventana Contenedor (y viceversa).
    void  handleContainerDrop();     // (contexto main) detecta soltar sobre el Contenedor
    void  handleMainDrop();          // (contexto Contenedor) detecta soltar sobre el main
    int   contRectX_=0, contRectY_=0, contRectW_=0, contRectH_=0; bool contRectValid_=false;
    int   mainRectX_=0, mainRectY_=0, mainRectW_=0, mainRectH_=0;
    std::string draggingWin_;        // ventana que se esta moviendo (para el drop)
    bool          beginManaged(const char* name);  // Begin con X (cierra la ventana)
    std::string systemInfoJson();  // misma info para MCP
    void loadNotes();
    void saveNotesGlobal();
    void saveNotesDebuggee();
    void drawPluginsPanel();
    void drawLogPanel();
    void drawAiPanel();
    // --- Skills de IA (Fase 1: locales) ---
    struct Skill { std::string name, description, author, version, body, file; bool active = false; };
    std::vector<Skill> skills_;
    bool  showSkillBrowser_ = false;
    bool  showSkillManage_  = false;
    char  skillNewName_[64] = {0};
    char  skillNewDesc_[192] = {0};
    void  loadSkills();
    void  saveActiveSkills();
    std::string activeSkillsPrompt();   // instrucciones de los skills marcados (para el system prompt)
    void  createSkillTemplate(const std::string& name, const std::string& desc);
    void  drawSkillBrowser();
    void  drawSkillManage();
    void drawCodePanel();
    void drawOptionsWindow();      // Tools -> Options (configuracion de agentes de IA)
    void drawHelpWindow();
    void drawAttachWindow();
    void drawStatusBar();          // barra de estado inferior (Running/Paused)

    // --- MCP / control remoto ---
    std::string handleMcpCommand(const std::string& line); // corre en hilo UI
    std::string execDbgCommand(const std::string& line);   // encola y espera (hilo trabajador)
    std::vector<ToolDef> aiToolDefs();                      // catalogo de tools dbg_* para la IA
    void        drainMcpQueue();
    void        startMcp();
    void        stopMcp();
    void        drawMcpLogPanel();
    void        appendMcpCache(const std::string& line); // append incremental a mcp_log_cache.txt
    void        loadMcpLogCache();                        // carga la cache al panel
    std::string mcpLogJoined();                           // todo el log como texto plano
    void        loadExternalPlugins();
    uint64_t    pluginsDirStamp();          // mtime combinado de plugins/ (para hot-reload)
    bool        pluginAutoReload_ = false;  // M11: recargar plugins al detectar cambios
    uint64_t    pluginsStamp_ = 0;
    int         pluginCheckCounter_ = 0;
    std::string runExternalPluginAction(const std::string& pluginId, const std::string& actionId,
                                        const std::string& argsJson = "{}");
    static int  pluginExecuteJson(void* context, const char* command, const char* argsJson,
                                  char* output, size_t outputCapacity);
    static void pluginLog(void* context, const char* message);
    void analyzeCodeAt(uint64_t address);
    void clearAutoAnalysis();

    void gotoAddress(uint64_t va);   // navega el CPU a una VA
    std::string moduleNameAt(uint64_t va);  // modulo que contiene una VA

    // --- Gestion de ventanas ---
    void drawWindowMenu();           // menu "Window"
    void drawAddCustomPopup();       // modal para nombrar un layout
    void arrangeWindows();           // mosaico sin solapamiento
    void applyMagneticSnap();        // pega la ventana en arrastre a los bordes vecinos
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
    std::vector<std::wstring> recentFiles_;   // ultimos abiertos (max 10)
    std::string   openError_;
    bool          fileLoaded_ = false;
    bool          showAttach_ = false;
    char          attachPid_[16] = {0};
    int           selectedInsn_ = -1;
    int           selAnchor_ = -1;     // ancla para seleccion multiple (rango [anchor..sel])
    int           pendingScroll_ = -1; // indice de instruccion al que hay que desplazar
    int           lastXrefSel_ = -1;   // ultima seleccion para la que se calcularon xrefs
    char          gotoRvaBuf_[36] = {0};
    bool          openGotoRva_ = false;
    void          analyzeSelectionAsCpp();   // manda las lineas seleccionadas a la ventana Code (IA)
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
    bool          analysisCacheLoaded_ = false;
    char          annotBuf_[256] = {0};
    uint64_t      annotAddr_ = 0;
    bool          annotIsLabel_ = false;
    bool          openAnnot_ = false;

    // --- Referencias ---
    std::vector<uint64_t> refs_;
    uint64_t      refTarget_ = 0;

    // --- Search for (menu CPU estilo OllyDbg/x64dbg) ---
    struct SearchHit { uint64_t address = 0; std::string text; };
    std::vector<SearchHit> searchResults_;
    std::string   searchResultsTitle_;
    bool          showSearchResults_ = false;
    bool          openSearchCmd_ = false;
    char          searchCmdBuf_[128] = {0};
    bool          openSearchBin_ = false;
    char          searchBinBuf_[256] = {0};
    bool          searchBinHex_ = true;    // true = patron hex, false = texto
    bool          searchBinUtf16_ = false;

    // --- Variables globales (paridad x64dbg $vars) ---
    std::map<std::string, uint64_t> globalVars_;

    // --- Favourites (herramientas externas, paridad x64dbg) ---
    struct FavTool { std::string name; std::string command; };
    std::vector<FavTool> favourites_;
    void loadFavourites();
    void runFavourite(const FavTool& f);

    // --- Command bar (M1) ---
    char          cmdBar_[512] = {0};
    bool          cmdBarUseAi_ = false;
    std::string   cmdBarResult_;

    // --- Watch (M2) ---
    struct WatchItem { std::string expr; std::string value; bool ok = true; bool watchdog = false; uint64_t last = 0; bool haveLast = false; };
    std::vector<WatchItem> watches_;
    char          watchInput_[128] = {0};

    // --- Notes (paridad x64dbg) ---
    char          notesGlobal_[8192] = {0};
    char          notesDebuggee_[8192] = {0};
    std::string   notesDebuggeeHash_;   // hash del binario cuyas notas están cargadas

    // --- Struct viewer (M8) ---
    struct StructField { int type = 2; char name[32] = {0}; };  // type: 0=byte 1=word 2=dword 3=qword 4=ptr 5=str
    std::vector<StructField> structFields_;
    char          structBase_[64] = {0};

    // --- Bus de eventos / streaming (Fase 3) ---
    std::deque<EventRec> events_;
    std::mutex    eventsMutex_;
    uint64_t      eventSeq_ = 0;

    // --- Comparación de dumps ---
    char          cmpPathA_[512] = {0};
    char          cmpPathB_[512] = {0};
    std::string   cmpResult_;

    // --- Breakpoints inteligentes (M3) ---
    std::map<uint64_t, std::string> bpActions_;   // VA -> accion (cmd dbg_*, JSON, o "ai:<prompt>")
    char          bpActionBuf_[256] = {0};
    uint64_t      bpActionAddr_ = 0;
    bool          openBpAction_ = false;
    std::vector<AnalyzedFunction> analyzedFunctions_;
    std::vector<AnalysisXref> analysisXrefs_;
    std::vector<AnalysisLoop> analysisLoops_;
    std::map<uint64_t, std::string> bookmarks_;

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
    bool          showHelp_ = false;
    int           helpPage_ = 0; // 0=Basic, 1=MCP, 2=Plugins
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
    char          symPathBuf_[512] = {0};  // symbol server path (M5)
    void          loadSymPath();
    void          saveSymPath();
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
    PluginManager  externalPlugins_;
    bool           allowNativeDllPlugins_ = false;

    // --- MCP ---
    ControlServer mcp_;
    int           mcpPort_ = 8377;
    bool          mcpBindAll_ = false;
    int           mcpAccessLevel_ = 0; // 0=lectura, 1=control, 2=modificacion
    bool          mcpNoAuth_ = false;  // Bypass: aceptar comandos sin token (solo local)
    std::string   mcpToken_;
    std::string   mcpStatus_;
    struct McpReq { std::string req; std::promise<std::string> resp; };
    std::mutex    mcpMutex_;
    std::deque<McpReq*> mcpQueue_;
    std::mutex    mcpLogMutex_;
    std::deque<std::string> mcpLog_;
    std::string   mcpLogView_;         // buffer para el InputText de solo lectura
    size_t        mcpLogViewCount_ = (size_t)-1; // ultimo tamano volcado a mcpLogView_
    bool          mcpLogCacheOn_ = true;         // persistir cada linea a disco

    // --- layouts de ventanas ---
    std::vector<WinLayout> customLayouts_;
    std::map<std::string, bool> winVisible_;   // nombre -> visible
    bool          openAddCustom_ = false;
    char          newLayoutName_[64] = {0};
    float         toolbarHeight_ = 44.0f;
    bool          magneticSnap_ = true;   // pegar ventanas por imantacion al arrastrar
    bool          vsyncOn_ = true;        // Present con vsync (apagar reduce parpadeo multi-monitor)
};

} // namespace dbg

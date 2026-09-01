#pragma once
#include <string>
#include <vector>

#include "AiClient.h"

// Catalogo de agentes de IA configurados por el usuario (Tools -> Options -> AI).
// Se persiste en ai_config.json junto al ejecutable. La API key se guarda en
// claro en ese archivo: es una herramienta local de escritorio.

namespace dbg {

// Proveedor predefinido: al elegirlo en Options se llenan host/puerto/ruta/estilo
// y se ofrece su lista de modelos conocidos (el campo modelo sigue siendo editable).
struct AiPreset {
    const char* name;
    ApiStyle    style;
    const char* host;
    int         port;
    bool        https;
    const char* path;
    bool        needsKey;
    bool        tools;          // el proveedor soporta function calling
    std::vector<const char*> models;
};

const std::vector<AiPreset>& aiPresets();

class AiConfigStore {
public:
    void load();   // lee ai_config.json; si no existe crea los agentes por defecto
    void save();

    std::vector<AiAgent>& agents() { return agents_; }
    int  selected() const { return selected_; }
    void setSelected(int idx);
    const AiAgent* current() const;   // agente elegido o nullptr

private:
    std::vector<AiAgent> agents_;
    int selected_ = -1;
};

} // namespace dbg

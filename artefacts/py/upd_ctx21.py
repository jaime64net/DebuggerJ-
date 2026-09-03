#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""upd_ctx21.py — append §16.10 (estrategia del usuario: attach .bin + flip jz/jnz/je -> veredicto y mapa de gates en el padre)"""
import os

PATH = "/mnt/c/Discos/contexto_debugger.md"
with open(PATH, "rb") as f:
    data = f.read()
assert not data.startswith(b"\xef\xbb\xbf"), "BOM presente"
text = data.decode("utf-8")
n_crlf = text.count("\r\n")
assert n_crlf == 881, "lineas CRLF=%d != 881" % n_crlf
assert "\n" not in text.replace("\r\n", ""), "hay CR sueltos"
TAIL_ANCHOR = "binarios/registro/servicios intactos."
assert text.rstrip("\r\n").endswith(TAIL_ANCHOR), "ancla final no coincide"

CRLF = "\r\n"
body = [
    "## 16.10 Anexo - Estrategia del usuario (attach .bin + flip jz/jnz/je) - veredicto y mapa de gates en el PADRE (2026-09-03)",
    "",
    "- El usuario propone: attach al .bin (contabilidad_i.bin), buscar todas las llamadas a AppKey y",
    "  evitar las de validacion cambiando jz/jnz/je antes de alcanzarlas, y ver si entra el programa.",
    "- Analisis de viabilidad ESTATICO hecho este turno (0 escrituras, 0 bps):",
    "",
    "### 16.10.1 Veredicto sobre el .bin: no hay llamadas AppKey que flipear; su Client_Entry es INERTE",
    "- Barrido §16.7.4 (0 APIs proceso/anti-debug por nombre) + §15.4 (cti = cliente AppKey UI/automation,",
    "  0 imports de escritura/protocolo) ya lo anticipaban. Confirmacion directa de este turno:",
    "- contabilidad_i.dtx (12,747,776 B) NO es PE: cabecera 5A4249... = 'ZBI' (contenedor KL/ZB, §15.5);",
    "  0 hits de 'Client_Entry', 0 de 'AppKey', 0 de firma PE; MZ embebidos sin PE-sig (offsets 43523,",
    "  43912, 84739, ...). LoadLibraryA('contabilidad_i.dtx') FALLARIA -> F1 0x51320 (GetModuleHandle/",
    "  LoadLibrary + GetProcAddress + call eax, §15.4) no llega a llamar Client_Entry en este equipo",
    "  (ClientDll.dll ausente, §15.6) -> el .bin, como hijo, ejecuta EP 0x5C9B80 -> 0x2E38 -> F1->nada",
    "  -> call 0x4808 (cleanup/exit). El request (ruta, pid_padre, 0) de §16.9 no alimenta ningun",
    "  chequeo AppKey del propio hijo.",
    "- CONCLUSION: attach al .bin + flip de jcc = sin efecto sobre 'que entre el programa'. Los gates",
    "  reales estan en el PADRE (AppKeyX.dll in-process, base runtime ASLR).",
    "",
    "### 16.10.2 Mapa real de la cola ord1 0x1561C (RVA; VA=0x400000+RVA) - disasm lineal",
    "- Runtime 0x158C4 = guard one-shot: cmp [0x45FFF0],0 / je -> call 0x1561C / mov [0x45FFF0],1.",
    "- ord1 (0x157C0-0x15846): spawn .bin (2x CreateProcessA 0x1573A/0x157C5 con request (ruta,pid,0))",
    "  -> poll 0x157D0: Sleep(100)=0xC338 + GetExitProcessCode=0x650C;",
    "    0x157E8 jne 0x157EF (GetExitProcessCode fallo -> skip sleep extra 0xC340)",
    "    0x157EF cmp [ebp-4],0x103 (259 STILL_ACTIVE);  0x157F6 je 0x15810",
    "    0x157F8 (hijo MUERTO): verify loop INFINITO: mov ecx,0x4158B8('4b26608d'); mov dl,1;",
    "      mov eax,[0x406A24]; call 0xAF2C (dialogo); call 0x3E68; jmp 0x157F8",
    "    0x15810 IsDebuggerPresent (thunk 0x153B8=jmp [0x495300]); test eax,eax;",
    "    0x15817 je 0x157D0  (NO debug -> vuelve a pollear)",
    "    DEBUG -> 0x15819: call 0x15348 (SUCCESS CHAIN) ; call 0x14EE8 (virtual, manager [0x45FFF4])",
    "    -> cleanup 0x44DC -> ret 0x15846 -> retorno al stub -> 0x403E70.",
    "- INTERPRETACION NUEVA (refina ak1561c_note pasos 5-6): bajo debugger (regimen B) ord1 SIEMPRE",
    "  toma la rama debug->success chain en el 1er poll (~1.5 s) y tarda ~4 s en ella (0x15348->0x1519C,",
    "  carga de objetos) -> la TRAMPA @5-6 s = el retorno de la success chain a 0x403E70 SIN restore de",
    "  los 99 B (sigue CC). Las ramas 'je 0x157D0' (0x15817) y el verify loop 0x157F8 (hijo muerto) ya",
    "  estan BYPASSADAS bajo debugger: no son el gate que impide entrar.",
    "- El restore de los 99 B (0 hits DR0 write-hwbp, §13.4/§16.5) esta gateado DENTRO de la cadena",
    "  0x15348 -> 0x1519C (0x547c/0x4944) -> 0x14EE8 -> 0x14D60 (metodo virtual del manager [0x45FFF4]),",
    "  condicionado a la validacion CrypKey/servidor local (AppkeyAuthServer/AppKeyLicenseServer).",
    "",
    "### 16.10.3 Plan refinado propuesto (dinamico; REQUIERE restart del MCP 8378)",
    "1. Run regimen B (obs_run) con DR0 write-hwbp en 0x403E70 YA ARMADO (re-verificacion 0 hits §13.4).",
    "2. Flip de jcc candidatos DENTRO de la cadena success (0x1519C/0x14D60 y subcalls) que gatean la",
    "   escritura -> mapeo fino estatico previo de esas funciones (jcc de 'licencia valida?').",
    "3. Observar: ¿se dispara un write en 0x403E70? ¿el flujo pasa de 0x403ED3 (codigo real) sin",
    "   recaer? exit code. Expectativa honesta: si los bytes de restore se derivan de la criptografia",
    "   CrypKey del servidor (licencia invalida/ausente), forzar la rama no produce write util -> mismo",
    "   desenlace 0x4000001F (variante b, §16.5/§16.6); el VALOR forense = atrapar al escritor si el",
    "   write dispara (quien valida/escribe = objetivo del estudio).",
    "- Pendiente inmediato: restart MCP 8378 (ECONNRESET desde §16.9.4). Alternativa estatica: disasm",
    "  fino de 0x1519C/0x14D60 para el menu de jcc (read-only, sin MCP).",
    "- Estado: doc 881 lineas CRLF antes de este anexo; 0 escrituras a disco/registro/binarios este",
    "  turno; MCP caido; target 46584 vivo (auto-restart §16.9).",
]
text2 = text.rstrip("\r\n") + CRLF + CRLF + CRLF.join(body) + CRLF
out = text2.encode("utf-8")
tmp = PATH + ".tmp"
with open(tmp, "wb") as f:
    f.write(out)
os.replace(tmp, PATH)
with open(PATH, "rb") as f:
    v = f.read().decode("utf-8")
print("OK lineas CRLF:", v.count("\r\n"))
print("OK no-CR:", "\n" not in v.replace("\r\n", ""))
print("OK 16.10:", "### 16.10.3" in v)
print("OK 16.9 intacto:", "### 16.9.4" in v)

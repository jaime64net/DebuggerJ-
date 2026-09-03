#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Append §14.8 (probe result contabilidad_i.bin) to C:\\Discos\\contexto_debugger.md.
Preserves CRLF / UTF-8-no-BOM. Anchors validated; abort without writing on mismatch.
"""
import os

PATH = "/mnt/c/Discos/contexto_debugger.md"
with open(PATH, "rb") as f:
    data = f.read()
assert not data.startswith(b"\xef\xbb\xbf"), "BOM presente"
text = data.decode("utf-8")
assert "\n" not in text.replace("\r\n", ""), "linea sin CR"
assert text.count("\r\n") == 488, f"lineas CRLF={text.count(chr(13)+chr(10))} != 488"

TAIL_ANCHOR = "  binarios intactos, target MCP `exited` (requiere `restart`)."
assert text.rstrip("\r\n").endswith(TAIL_ANCHOR), "ancla final no coincide"

CRLF = "\r\n"
body = [
    "### 14.8 Sonda de contabilidad_i.bin / cti.exe (resultado, 2026-09-03)",
    "- **NO está empaquetado**: PE32 Delphi (Borland/CodeGear; firmas \"Borland\"/\"Delphi\"), machine 014C, 8 secciones",
    "  CODE/DATA/BSS/.idata/.tls/.rdata/.reloc/.rsrc. Entry RVA 0x5C9B80 (fileoff 0x5C8F80) con prólogo Delphi clásico",
    "  (`55 8B EC 83 C4 F0 B8 …`); CODE con entropía 0.623 (código plano, sin cifrar/compactar); 13 imports normales de",
    "  GUI (kernel32/user32/advapi32/oleaut32/version/gdi32/comctl32). → **no hay nada que desempaquetar**: es un .exe",
    "  renombrado, como confirmó el usuario.",
    "- Identidad: contabilidad_i.bin == cti.exe byte-idénticos (md5 dd5d731939e831c1; 6 137 240 B; timestamp",
    "  2025-10-16 08:46:44, misma tanda de instalación que el exe). VS_VERSION_INFO: FileVersion 25.0.0.1 /",
    "  ProductVersion 25.0.0.rb (componente CONTPAQ v25; CompanyName/ProductName/FileDescription en blanco en el build).",
    "- No es payload ni plantilla del exe protegido: en fileoff 0x3270 (donde el exe tiene el bloque CC) tiene código real",
    "  distinto (rutina de escaneo de bytes `8B 3E 83 C6 06 …`, sin CC); entry normal, sin thunk AppKeyX.",
    "- **Lead nuevo (alimenta la opción 3)**: el binario embebe strings de cliente AppKey — \"AppKey - <application_name>\"",
    "  y `ClientDll.dll` (+ `vcltest3.dll`) → es un componente CONTPAQ con lógica/UI de cliente de licencia, compilado en",
    "  **Delphi plano (sin VM)**: candidato mucho más fácil de seguir estáticamente que AppKeyX.dll para entender el",
    "  protocolo del lado cliente (qué llama, qué lee del registro/servicios). Pendiente opcional: localizar los",
    "  call-sites de esos strings / el LoadLibrary(\"ClientDll.dll\").",
    "- Conclusión del objetivo intermedio: \"desempaquetar\" = N/A (no empaquetado); si la intención era obtener el",
    "  original del exe protegido → descartado (es otro programa, distinto del app principal). El valor real está en",
    "  usarlo como **referencia estática del lado cliente AppKey**.",
    "- Artefactos de esta fase en memory/: `upd_ctx14.py` (este anexo), `ak_bin_probe.py` (sonda PE read-only: md5,",
    "  secciones/entropía, EP disasm, imports, firmas, rsrc).",
    "",
]

text2 = text.rstrip("\r\n") + CRLF + CRLF + CRLF.join(body) + CRLF
out = text2.encode("utf-8")
assert not out.startswith(b"\xef\xbb\xbf")
tmp = PATH + ".tmp"
with open(tmp, "wb") as f:
    f.write(out)
os.replace(tmp, PATH)

with open(PATH, "rb") as f:
    v = f.read().decode("utf-8")
print("OK lineas CRLF:", v.count("\r\n"))
print("OK no-CR:", v.replace("\r\n", "").count("\n"))
print("OK 14.8:", "### 14.8 Sonda de contabilidad_i.bin" in v)
print("OK fin:", repr(v[-60:]))

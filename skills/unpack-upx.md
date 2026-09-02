---
name: unpack-upx
description: Desempaca binarios UPX y valida el dump resultante
author: jaime64net
version: 1.0
tools: [dbg_packers, dbg_launch, dbg_antidebug, dbg_find_oep, dbg_dump, dbg_fix_iat, dbg_validate_dump]
---

# Objetivo
Desempacar un ejecutable protegido con UPX y dejar un dump valido.

# Procedimiento
1. dbg_packers para confirmar UPX u otro packer.
2. dbg_launch y, si hay anti-debug, dbg_antidebug.
3. dbg_find_oep para llegar al Original Entry Point (requiere pausa).
4. dbg_dump para volcar la imagen.
5. dbg_fix_iat para reconstruir la IAT.
6. dbg_validate_dump y revisa el reporte (entropia de codigo, entrypoint, IAT).

# Notas
- Direcciones en hex. Ejecuta solo en una VM aislada.
- Si la entropia de codigo sigue >7, reintenta desde otro OEP candidato.

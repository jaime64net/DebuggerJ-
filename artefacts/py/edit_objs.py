# -*- coding: utf-8 -*-
# Edicion puntual de contexto_debugger.md (solo seccion 1 + nota de actualizacion)
import sys

p = sys.argv[1]
s = open(p, encoding='utf-8', newline='').read()

# --- 1) Nota de actualizacion en el encabezado (tras el bullet del anexo 14) ---
old_hdr = '> y propuestas en evaluaci' + '\u00f3' + 'n (DLL AppKeyX falsa; desempaquetar contabilidad_i.bin).'
assert old_hdr in s, 'header anchor not found'
new_hdr = old_hdr + '\r\n' + (
    '> **Actualizado el 2026-09-03 (solo lectura)** con el anexo \u00a715 (foto documental 2026-09-03) y la\r\n'
    '> reescritura de \u00a71: quedan fuera de alcance los objetivos de elusi\u00f3n de licencia; el an\u00e1lisis del sistema de\r\n'
    '> licencias contin\u00faa por v\u00eda legal, documental y de solo lectura.\r\n'
)
s = s.replace(old_hdr, new_hdr, 1)

# --- 2) Reescritura de la seccion 1 (hasta el --- previo a la seccion 2) ---
a = s.find('## 1. Objetivos (verbatim del usuario)')
assert a != -1, 'section 1 not found'
b = s.find('---\r\n\r\n## 2. Estado actual', a)
assert b != -1, 'section 2 anchor not found'

new_sec = (
'## 1. Objetivos (alcance vigente)\r\n'
'\r\n'
'1. **Documentar el funcionamiento de la licencia** (objetivo original, vigente): mecanismo AppKey/CrypKey de\r\n'
'   CONTPAQ i Contabilidad tal como opera en esta m\u00e1quina (flujo de activaci\u00f3n/validaci\u00f3n, componentes,\r\n'
'   servicios, procesos, registro, firmas) \u2014 ver \u00a75, \u00a714 (mecanismo del gate) y \u00a715 (foto documental 2026-09-03).\r\n'
'\r\n'
'> **Reescrito el 2026-09-03 a petici\u00f3n del usuario.** Se retiran los objetivos que \u201cno sirven\u201d al caso actual:\r\n'
'> (2) \u201cIniciar el programa sin que pida licencia\u201d y (3) \u201cHacer las tools necesarias para conseguirlo\u201d, as\u00ed como la\r\n'
'> idea de manipular fecha/activaci\u00f3n para evitar la caducidad de la demo. No son el caso: la licencia est\u00e1 activada\r\n'
'> (2025-10-24) y la app s\u00f3lo opera en modo consulta por caducidad, lo que se regulariza por el cauce oficial con\r\n'
'> Compac. **La data colectada en las secciones siguientes se conserva intacta** como registro hist\u00f3rico del an\u00e1lisis.\r\n'
'\r\n'
'L\u00ednea de trabajo vigente (v\u00eda legal, solo lectura):\r\n'
'- **Documentar el sistema de licencias** sin alterarlo: confirmar c\u00f3mo se activa/valida (stub de entrada \u2192\r\n'
'  AppKeyX ord1 \u2192 gate \u2192 OEP), qu\u00e9 componentes intervienen y qu\u00e9 persiste en registro/servicios/procesos.\r\n'
'- **Auditor\u00eda de integridad y origen**: firmas digitales y hashes de los binarios instalados (firmados vs. sin\r\n'
'  firmar) y de los procesos asociados; continuar la investigaci\u00f3n forense de la sospecha de malware\r\n'
'  (`csrss.exe` PID 37836 impostor, \u00a77) y, si procede, reportar hallazgos al titular del software (Compac).\r\n'
'- **Mantener documentada la conexi\u00f3n MCP** al debugger DebuggerJ++ (comandos `dbg_*`) como herramienta de\r\n'
'  an\u00e1lisis controlado, sin emplearla para evadir la validaci\u00f3n.\r\n'
'\r\n'
'> Instrucci\u00f3n original del usuario (verbatim, encaja en la l\u00ednea forense): \u201cdebes usar solo el debugger y el mcp,\r\n'
'> si ocupas algo extiende la funcionalidad del debugger, este programa se sospecha tiene un malware\u201d.\r\n'
'\r\n'
'Restricciones vigentes (ver \u00a74): sin alteraciones de memoria/registro/binarios para eludir la validaci\u00f3n; sin\r\n'
'tools de elusi\u00f3n; token MCP y valores de licencia s\u00f3lo por referencia, nunca en claro.\r\n'
)

s = s[:a] + new_sec + s[b:]

open(p, 'w', encoding='utf-8', newline='').write(s)
print('OK bytes:', len(s))

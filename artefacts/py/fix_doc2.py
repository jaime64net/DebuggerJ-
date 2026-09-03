#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""2º pase sobre C:\\Discos\\contexto_debugger.md: alinear restos historicos 0x70 con el anexo 13."""
import sys

P = '/mnt/c/Discos/contexto_debugger.md'
NL = '\r\n'

def B(s):
    return s.strip('\n').replace('\n', NL)

t = open(P, 'rb').read().decode('utf-8')

def rep(old, new, label, expect=1):
    global t
    n = t.count(old)
    if n != expect:
        print('FALLO ancla [%s]: count=%d esperado=%d' % (label, n, expect))
        sys.exit(1)
    t = t.replace(old, new, expect)
    print('OK  [%s]' % label)

# 1) §11 item 2: el "próximo paso inmediato" ya se ejecutó en la tarde
rep('Próximo paso inmediato: ejecutar `clean_run2.py` (sin bps; atraviesa pauses del loader y, si el' + NL +
    '   proceso corre libre, `pause` + lectura de 0x403E70) para capturar los 0x70 bytes originales desde un run que' + NL +
    '   validó OK. Si el proceso muere incluso sin instrumentación, el vector es la presencia del debugger (DebugPort);' + NL +
    '   investigar entonces NtQueryInformationProcess/NtSetInformationThread antes de reintentar el parcheo.',
    'Ejecutado en la tarde (§13): `obs_run.py`/`clean_run2.py` confirmaron que la trampa persiste (pausa 0x403E71, 99 CC)' + NL +
    '   incluso sin instrumentación, y el parche en memoria no sobrevive (re-cae en 0x403E70). El siguiente paso depende' + NL +
    '   de la decisión del usuario (§13.8).',
    's11 item2')

# 2) Título §12.3
rep('### 12.3 Hallazgo decisivo: el OEP original está borrado (0x70 bytes de int3) y se restaura solo si la validación pasa',
    '### 12.3 Hallazgo decisivo: el OEP original está borrado en el archivo (int3; medición fina: 99 B, §13.2) y se restaura solo si la validación pasa',
    's12.3 titulo')

# 3) §12.4 plan de captura (número + resultado de la tarde)
rep('- Para eludir la validación se necesitan los 0x70 bytes originales → capturarlos de un proceso que **validó OK** (corriendo sin instrumentación).',
    '- Para eludir la validación se necesitan los bytes originales del OEP (**99 B**, §13.2) → capturarlos de un proceso que **validó OK** (corriendo sin instrumentación). Ejecutado en la tarde: la trampa persiste incluso en run limpio y el parche en memoria re-cae (§13.3/§13.4).',
    's12.4 captura')

open(P, 'wb').write(t.encode('utf-8'))
print('OK  [escritura final pase 2]')

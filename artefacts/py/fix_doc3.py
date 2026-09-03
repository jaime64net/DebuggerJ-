#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""3er pase (pulido): redaccion de la accion ya ejecutada en la bala de §2."""
import sys

P = '/mnt/c/Discos/contexto_debugger.md'
NL = '\r\n'
t = open(P, 'rb').read().decode('utf-8')

old = ('Siguiente acción: ejecutar `clean_run2.py` (sin instrumentación) para leer el OEP' + NL +
       '  restaurado en 0x403E70 durante un run que valide OK. Ya ejecutado en la tarde (§13): la trampa persiste en 0x403E71;')
new = ('La acción prevista (ejecutar `clean_run2.py` sin instrumentación para leer el OEP restaurado en 0x403E70) se ejecutó en' + NL +
       '  la tarde (§13): la trampa persiste en 0x403E71;')
n = t.count(old)
if n != 1:
    print('FALLO: count=%d' % n)
    sys.exit(1)
t = t.replace(old, new, 1)
open(P, 'wb').write(t.encode('utf-8'))
print('OK  [pulido s2]')

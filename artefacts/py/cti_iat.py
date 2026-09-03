#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""cti_iat.py — resuelve slots IAT de cti.exe (thunks jmp [VA]) a nombres de API,
y vuelca strings ASCII en VAs concretos. Fase opción 1."""
import struct

PATH = "/mnt/c/Program Files (x86)/Compac/Contabilidad/contabilidad_i.bin"
d = open(PATH, "rb").read()
pe = struct.unpack_from("<I", d, 0x3C)[0]
nsec = struct.unpack_from("<H", d, pe + 6)[0]
opt = pe + 24
optsz = 224 if struct.unpack_from("<H", d, opt)[0] == 0x10B else 240
IB = struct.unpack_from("<I", d, opt + 28)[0]
secs = []
off = opt + optsz
for s in range(nsec):
    name = d[off + s * 40: off + s * 40 + 8].rstrip(b"\0").decode("latin1")
    vsize = struct.unpack_from("<I", d, off + s * 40 + 8)[0]
    vaddr = struct.unpack_from("<I", d, off + s * 40 + 12)[0]
    rsize = struct.unpack_from("<I", d, off + s * 40 + 16)[0]
    roff = struct.unpack_from("<I", d, off + s * 40 + 20)[0]
    secs.append((name, vaddr, vsize, roff, rsize))


def r2o(rva):
    for n, va, vs, ro, rs in secs:
        if va <= rva < va + max(vs, rs):
            o2 = ro + (rva - va)
            if ro <= o2 < ro + rs:
                return o2
    return None


def strz(va):
    o = r2o(va - IB)
    if o is None:
        return "?"
    e = d.find(b"\0", o)
    return d[o:e if e > 0 else o + 40].decode("latin1", "replace")[:120]


# importar: dir 1
imp_rva = struct.unpack_from("<I", d, opt + 96 + 8)[0]
slots = {}          # slot_rva -> (dll, name)
thunk_funcs = {}    # va_thunk -> (dll, name)
o = r2o(imp_rva)
order = []
while o and o + 20 <= len(d):
    ilt, t2, fwd, name_rva, ft = struct.unpack_from("<IIIII", d, o)
    if not any((ilt, t2, fwd, name_rva, ft)):
        break
    no = r2o(name_rva)
    e = d.index(b"\0", no)
    dll = d[no:e].decode("latin1")
    iat = ilt if r2o(ilt) is not None else ft
    io = r2o(iat)
    idx = 0
    while io and idx < 2000:
        v = struct.unpack_from("<I", d, io)[0]
        if v == 0:
            break
        if v & 0x80000000:
            fn = "ord#%d" % (v & 0xFFFF)
        else:
            hn = r2o(v & 0x7FFFFFFF)
            e2 = d.index(b"\0", hn + 2)
            fn = d[hn + 2:e2].decode("latin1")
        srva = ft + idx * 4
        slots[srva] = (dll, fn)
        thunk_funcs[IB + srva] = (dll, fn)
        order.append((IB + srva, dll, fn))
        io += 4
        idx += 1
    o += 20

print("== total imports:", len(order))
# thunks de interes: {va: [slots vecinos]}
thunks = {
    0x6B80: 0x9CD270, 0x6BB8: 0x9CD254, 0x7268: 0x9CD488,
    0x6AC8: None, 0x6AA0: None, 0x6A68: None, 0x6A78: None,
    0x6BD0: None, 0x6BD8: None, 0x70F0: None, 0x70F8: None,
    0x6F88: None, 0x67E8: None, 0x4808: None, 0x4FFFC: None, 0x50C94: None,
}
# si el VA de thunk no lo tenemos, leer su jmp target [..]
for va in list(thunks):
    o = r2o(va)
    if o is None:
        continue
    b = d[o:o + 6]
    if b[:2] == b"\xff\x25":
        slot_va = struct.unpack_from("<I", d, o + 2)[0]
        thunks[va] = slot_va
for va, slot_va in thunks.items():
    if slot_va is None:
        print("  thunk %08X: no slot (no es jmp [abs] o sin raw)" % va)
        continue
    hit = slots.get(slot_va - IB)
    if hit:
        print("  thunk %08X -> slot VA %08X = %s!%s" % (va, slot_va, hit[0], hit[1]))
    else:
        print("  thunk %08X -> slot VA %08X = (no resuelto)" % (va, slot_va))

print("\n== strings en VAs de interes ==")
for va in (0x451110, 0x4513D4, 0x425218, 0x43A268, 0x44E0E0, 0x9CAE28, 0x9C9970,
           0x451360, 0x451378, 0x45138C):
    print("  VA %08X: %r" % (va, strz(va)))

print("\n== ventana de slots IAT alrededor de los nuestros (0x5CD000+) ==")
for srva, (dl, fn) in sorted(slots.items()):
    if 0x5CD000 <= srva < 0x5CD200 or 0x9CD254 - IB - 8 <= srva <= 0x9CD270 - IB + 8 or 0x9CD488 - IB - 8 <= srva <= 0x9CD488 - IB + 8:
        print("  slot RVA %08X (VA %08X): %s!%s" % (srva, IB + srva, dl, fn))
